// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Source-verification enclave app. Given git coordinates for a Move package and
//! the on-chain package it claims to be, the enclave fetches the source, hashes
//! it, and runs `sui client verify-source` to check the source compiles to the
//! on-chain bytecode + linkage. On a match it signs a `SourceVerification`
//! attestation; on a mismatch (non-zero exit) it refuses to sign.

use crate::common::{to_signed_response, IntentMessage, ProcessDataRequest, ProcessedDataResponse};
use crate::AppState;
use crate::EnclaveError;
use axum::extract::State;
use axum::Json;
use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

/// Intent scope for the source-verification signature. Must match the on-chain
/// verifier's scope.
#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
pub enum IntentScope {
    SourceVerification = 0,
}

/// Where to find the source and what to compare it against.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Git repository URL to clone.
    pub git_url: String,
    /// Git revision (branch, tag, or commit) to check out.
    pub git_rev: String,
    /// Path to the Move package within the repo.
    pub subdir: String,
    /// Build environment whose `Published.toml` published-at the source is
    /// verified against (e.g. "mainnet").
    pub build_env: String,
}

/// The signed attestation content: package `pkg_id` was built from the source at
/// `git_url`/`subdir` (resolved commit `git_sha`), whose contents hash to
/// `source_hash`. `source_hash` (blake2b256) is the authoritative identifier;
/// the git fields are informational provenance only — git's SHA-1 is not
/// collision-resistant and must not be relied on for integrity.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceVerification {
    pub pkg_id: [u8; 32],
    pub source_hash: Vec<u8>,
    pub git_url: String,
    pub subdir: String,
    pub git_sha: String,
}

/// Clone the source, hash it, verify it against the on-chain package, and — on a
/// match — return a signed `SourceVerification`.
pub async fn process_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessDataRequest<VerifyRequest>>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<SourceVerification>>>, EnclaveError> {
    let req = request.payload;

    let workdir = std::env::temp_dir().join(format!("srcverif-{}", uuid::Uuid::new_v4()));
    let clone = workdir.join("repo");
    git_clone_checkout(&req.git_url, &req.git_rev, &clone)?;
    let git_sha = git_rev_parse(&clone)?;
    let package_dir = clone.join(&req.subdir);

    // Hash the pristine source, then verify it against the on-chain bytecode
    // recorded in the source's Published.toml for this env.
    let source_hash = hash_dir(&package_dir)?;
    run_verify_source(&package_dir, &req.build_env)?;
    let pkg_id = published_at(&package_dir, &req.build_env)?;

    let payload = SourceVerification {
        pkg_id,
        source_hash,
        git_url: req.git_url,
        subdir: req.subdir,
        git_sha,
    };
    let _ = std::fs::remove_dir_all(&workdir);
    Ok(Json(to_signed_response(
        &state.eph_kp,
        payload,
        now_ms()?,
        IntentScope::SourceVerification as u8,
    )))
}

/// Parse a (optionally `0x`-prefixed) 32-byte hex package id.
fn parse_pkg_id(s: &str) -> Result<[u8; 32], EnclaveError> {
    let bytes = Hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| err(format!("bad on_chain_id: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| err("on_chain_id must be 32 bytes"))
}

/// Clone `url` into `dest` and check out `rev`.
fn git_clone_checkout(url: &str, rev: &str, dest: &Path) -> Result<(), EnclaveError> {
    let dest = path_str(dest)?;
    run("git", &["clone", "--quiet", url, dest])?;
    run("git", &["-C", dest, "checkout", "--quiet", rev])
}

/// Resolve the checked-out commit to its full SHA.
fn git_rev_parse(dir: &Path) -> Result<String, EnclaveError> {
    Ok(output("git", &["-C", path_str(dir)?, "rev-parse", "HEAD"])?
        .trim()
        .to_string())
}

/// Run `sui client verify-source --build-env <env> <dir>`; a zero exit means the
/// source compiles to the on-chain bytecode + linkage recorded in the package's
/// `Published.toml` for `<env>`. `SUI_BIN` overrides the binary (defaults to
/// `sui` on PATH).
fn run_verify_source(package_dir: &Path, build_env: &str) -> Result<(), EnclaveError> {
    let sui = std::env::var("SUI_BIN").unwrap_or_else(|_| "sui".to_string());
    run(
        &sui,
        &[
            "client",
            "verify-source",
            "--build-env",
            build_env,
            path_str(package_dir)?,
        ],
    )
}

/// The verified on-chain package id: the `published-at` under `[published.<env>]`
/// in the package's committed `Published.toml`.
fn published_at(package_dir: &Path, env: &str) -> Result<[u8; 32], EnclaveError> {
    let toml = std::fs::read_to_string(package_dir.join("Published.toml"))
        .map_err(|e| err(format!("read Published.toml: {e}")))?;
    let header = format!("[published.{env}]");
    let mut in_section = false;
    for line in toml.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == header;
        } else if in_section {
            if let Some(rest) = line.strip_prefix("published-at") {
                let val = rest.trim_start_matches([' ', '=']).trim().trim_matches('"');
                return parse_pkg_id(val);
            }
        }
    }
    Err(err(format!("no published-at for env '{env}' in Published.toml")))
}

/// blake2b256 over a lexicographically-sorted manifest of the package directory:
/// for each file, `<relative path>` + NUL + `blake2b256(contents)`. Reproducible
/// from the same source tree; filenames and file boundaries are part of the hash
/// so content cannot be shuffled between files undetected.
fn hash_dir(dir: &Path) -> Result<Vec<u8>, EnclaveError> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    files.sort();
    let mut manifest = Blake2b256::new();
    for rel in files {
        let content =
            std::fs::read(dir.join(&rel)).map_err(|e| err(format!("read {rel}: {e}")))?;
        manifest.update(rel.as_bytes());
        manifest.update([0u8]);
        manifest.update(Blake2b256::digest(content).digest);
    }
    Ok(manifest.finalize().digest.to_vec())
}

/// Collect files under `dir` as paths relative to `root`.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), EnclaveError> {
    for entry in std::fs::read_dir(dir).map_err(|e| err(format!("readdir {dir:?}: {e}")))? {
        let path = entry.map_err(|e| err(format!("direntry: {e}")))?.path();
        if path.is_dir() {
            collect_files(root, &path, out)?;
        } else {
            out.push(path.strip_prefix(root).unwrap().to_string_lossy().into_owned());
        }
    }
    Ok(())
}

/// Run a command, returning an error (with stderr) on non-zero exit.
fn run(bin: &str, args: &[&str]) -> Result<(), EnclaveError> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| err(format!("failed to spawn {bin}: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(err(format!(
            "{bin} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        )))
    }
}

/// Run a command and capture stdout, erroring (with stderr) on non-zero exit.
fn output(bin: &str, args: &[&str]) -> Result<String, EnclaveError> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| err(format!("failed to spawn {bin}: {e}")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(err(format!(
            "{bin} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )))
    }
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> Result<u64, EnclaveError> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| err(format!("clock: {e}")))?
        .as_millis() as u64)
}

/// A path as `&str`, erroring on non-UTF-8.
fn path_str(p: &Path) -> Result<&str, EnclaveError> {
    p.to_str().ok_or_else(|| err("non-UTF-8 path"))
}

fn err(msg: impl Into<String>) -> EnclaveError {
    EnclaveError::GenericError(msg.into())
}
