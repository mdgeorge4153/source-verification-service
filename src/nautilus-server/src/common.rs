// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, Json};
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::traits::{KeyPair as FcKeyPair, Signer, ToFromBytes};
use nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
use nsm_api::driver;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tracing::info;

use crate::{AppState, EnclaveError};

/// Timeout for each connectivity probe in [`health_check`].
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Intent message wrapper struct containing the intent scope and timestamp.
/// This standardizes the serialized payload for signing. Generic over the data
/// type T. Intent scope is stored as u8.
#[derive(Serialize, Deserialize)]
pub struct IntentMessage<T: Serialize> {
    pub intent: u8,
    pub timestamp_ms: u64,
    pub data: T,
}

/// Wrapper struct containing the response (the intent message) and signature.
#[derive(Serialize, Deserialize)]
pub struct ProcessedDataResponse<T> {
    pub response: T,
    pub signature: String,
}

/// Wrapper struct containing the request payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessDataRequest<T> {
    pub payload: T,
}

/// Response for get attestation.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// Attestation document serialized in Hex.
    pub attestation: String,
}

/// Health check response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Hex encoded public key booted on enclave.
    pub pk: String,
    /// Status of endpoint connectivity checks
    pub endpoints_status: HashMap<String, bool>,
    /// Why no checks ran, when `endpoints_status` is empty for a reason other
    /// than having no endpoints configured. Absent when the checks did run, so a
    /// healthy response is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints_error: Option<String>,
}

impl<T: Serialize> IntentMessage<T> {
    pub fn new(data: T, timestamp_ms: u64, intent: u8) -> Self {
        Self {
            data,
            timestamp_ms,
            intent,
        }
    }
}

/// Sign the bcs bytes of the payload with keypair.
pub fn to_signed_response<T: Serialize>(
    kp: &Ed25519KeyPair,
    payload: T,
    timestamp_ms: u64,
    intent: u8,
) -> ProcessedDataResponse<IntentMessage<T>> {
    let intent_msg = IntentMessage::new(payload, timestamp_ms, intent);

    let signing_payload = bcs::to_bytes(&intent_msg).expect("should not fail");
    let sig = kp.sign(&signing_payload);
    ProcessedDataResponse {
        response: intent_msg,
        signature: Hex::encode(sig),
    }
}

/// Endpoint that returns an attestation committed to the enclave's public key.
pub async fn get_attestation(
    State(state): State<Arc<AppState>>,
) -> Result<Json<AttestationResponse>, EnclaveError> {
    info!("get attestation called");

    let pk = state.eph_kp.public();
    let fd = driver::nsm_init();

    // Send attestation request to NSM driver with public key set.
    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: None,
        public_key: Some(ByteBuf::from(pk.as_bytes().to_vec())),
    };

    let response = driver::nsm_process_request(fd, request);
    driver::nsm_exit(fd);

    match response {
        NsmResponse::Attestation { document } => Ok(Json(AttestationResponse {
            attestation: Hex::encode(document),
        })),
        other => Err(EnclaveError::GenericError(format!(
            "NSM returned {other:?} for the attestation request, expected an Attestation document"
        ))),
    }
}

/// Endpoint that health checks the enclave connectivity to all domains and
/// returns the enclave's public key.
pub async fn health_check(
    State(state): State<Arc<AppState>>,
) -> Result<Json<HealthCheckResponse>, EnclaveError> {
    let pk = state.eph_kp.public();

    let client = Client::builder()
        .timeout(HEALTH_CHECK_TIMEOUT)
        .build()
        .map_err(|e| EnclaveError::GenericError(format!("Failed to create HTTP client: {e}")))?;

    // An empty endpoints_status is otherwise indistinguishable from a healthy
    // enclave with nothing to check, so a failure to read the endpoints is
    // reported in endpoints_error rather than swallowed.
    let (endpoints_status, endpoints_error) = match allowed_endpoints() {
        Ok(hosts) => {
            let mut status = HashMap::new();
            for host in hosts {
                let reachable = check_endpoint(&client, &host).await;
                info!("Checked endpoint {host}: reachable = {reachable}");
                status.insert(host, reachable);
            }
            (status, None)
        }
        Err(e) => {
            info!("{e}");
            (HashMap::new(), Some(e))
        }
    };

    Ok(Json(HealthCheckResponse {
        pk: Hex::encode(pk.as_bytes()),
        endpoints_status,
        endpoints_error,
    }))
}

/// The hosts listed under `endpoints:` in `allowed_endpoints.yaml`. Returns an
/// error message, for the health response, if the file cannot be read or parsed
/// or has no `endpoints` sequence.
fn allowed_endpoints() -> Result<Vec<String>, String> {
    let yaml = std::fs::read_to_string("allowed_endpoints.yaml")
        .map_err(|e| format!("could not read allowed_endpoints.yaml: {e}"))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&yaml)
        .map_err(|e| format!("could not parse allowed_endpoints.yaml: {e}"))?;
    let Some(hosts) = value.get("endpoints").and_then(|e| e.as_sequence()) else {
        return Err("allowed_endpoints.yaml has no 'endpoints' sequence".to_string());
    };
    Ok(hosts
        .iter()
        .filter_map(|h| h.as_str().map(str::to_string))
        .collect())
}

/// Whether `host` answers a health probe. AWS endpoints must return a body
/// containing "healthy"; other hosts must return a success status.
async fn check_endpoint(client: &Client, host: &str) -> bool {
    let is_aws = host.contains(".amazonaws.com");
    let url = if is_aws {
        format!("https://{host}/ping")
    } else {
        format!("https://{host}")
    };

    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(e) => {
            info!("Failed to connect to {host}: {e}");
            return false;
        }
    };

    if !is_aws {
        return response.status().is_success();
    }
    match response.text().await {
        Ok(body) => body.to_lowercase().contains("healthy"),
        Err(e) => {
            info!("Failed to read response body from {host}: {e}");
            false
        }
    }
}
