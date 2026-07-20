/// Source-verification skill — standalone Nautilus + attestations.
///
/// A Nitro enclave running the verify-source workload signs a
/// `SourceVerification` over a Move package it checked against its on-chain
/// bytecode. This module verifies that signature against a registered
/// `Enclave<SourceVerifier>` and records the result as an
/// `Attestation<SourceVerification>` about the on-chain package. Registration is
/// permissionless (`enclave::register_enclave`), so anyone running the attested
/// PCRs can provide the service; `attest_source` accepts any such enclave.
module source_verification::source_verification;

use std::internal;
use std::string::String;
use sui::display_registry::DisplayRegistry;
use enclave::enclave::{Self, Enclave};
use attestations::attestations::{Registry, attest};

#[error(code = 0)]
const EBadSignature: vector<u8> =
    b"enclave signature does not verify against the registered enclave";

/// Intent scope the enclave stamps when signing a `SourceVerification`. Must
/// match `IntentScope::SourceVerification` in the enclave server.
const VERIFY_SCOPE: u8 = 0;

// Expected enclave PCRs, set at publish and updatable by the `Cap` holder via
// `enclave::update_pcrs`. Provisional — these are the stage-1 build (no
// verify-source binary bundled yet); the real values change once the EIF is
// final. A deployer can also `update_pcrs` to all-zeros for debug-mode testing.
const PCR0: vector<u8> =
    x"2636e44c0588f296412e5474368ab06811f1dc55b7bbf33060eb9324e36714803b03c4576102d62358c2b3b736dfa0c1";
const PCR1: vector<u8> =
    x"2636e44c0588f296412e5474368ab06811f1dc55b7bbf33060eb9324e36714803b03c4576102d62358c2b3b736dfa0c1";
const PCR2: vector<u8> =
    x"21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a";

/// Marker `T` for this skill's `EnclaveConfig<T>` / `Enclave<T>`. A plain `drop`
/// witness (not a one-time witness): only this module can name it, so only this
/// module can create the enclave config/cap and verify signatures under it.
public struct SourceVerifier has drop {}

/// The attestation payload: package `pkg_id` was built from the source at
/// `git_url`/`subdir` (resolved commit `git_sha`), whose contents hash to
/// `source_hash`. `source_hash` (blake2b256 of the package dir) is the
/// authoritative identifier; the git fields are informational provenance only —
/// git's SHA-1 is not collision-resistant. Field order + types are pinned to the
/// enclave server's Rust `SourceVerification` by a cross-language BCS byte-test.
#[allow(unused_field)]
public struct SourceVerification has copy, store, drop {
    pkg_id: ID,
    source_hash: vector<u8>,
    git_url: String,
    subdir: String,
    git_sha: String,
}

/// Publish-time: mint the enclave `Cap<SourceVerifier>`, create the shared
/// `EnclaveConfig<SourceVerifier>` holding the expected PCRs, and hand the cap to
/// the publisher. Providers permissionlessly `register_enclave` their own
/// `Enclave<SourceVerifier>` against this config.
fun init(ctx: &mut TxContext) {
    let cap = enclave::new_cap(SourceVerifier {}, ctx);
    enclave::create_enclave_config(
        &cap,
        b"source-verification".to_string(),
        PCR0,
        PCR1,
        PCR2,
        ctx,
    );
    transfer::public_transfer(cap, ctx.sender());
}

/// Verify an enclave-signed `SourceVerification` and record it as an
/// `Attestation<SourceVerification>` about `payload.pkg_id`. Accepts any
/// `Enclave<SourceVerifier>` registered against the config (permissionless
/// multi-provider). `registry` is the attestations `Registry` id. Returns the
/// new attestation's ID.
public fun attest_source(
    registry: ID,
    enclave: &Enclave<SourceVerifier>,
    payload: SourceVerification,
    timestamp_ms: u64,
    signature: vector<u8>,
    ctx: &mut TxContext,
): ID {
    let subject = payload.pkg_id;
    assert!(
        enclave.verify_signature(VERIFY_SCOPE, timestamp_ms, payload, &signature),
        EBadSignature,
    );
    attest(registry, internal::permit<SourceVerification>(), subject, payload, ctx)
}

/// One-shot setup of the append-only `Display<Attestation<SourceVerification>>`.
/// Call once shortly after publish; aborts on a second call.
entry fun register_source_display(
    registry: &Registry,
    display_registry: &mut DisplayRegistry,
    ctx: &mut TxContext,
) {
    registry.register_display(
        display_registry,
        internal::permit<SourceVerification>(),
        vector[b"name".to_string(), b"description".to_string()],
        vector[
            b"Source verification".to_string(),
            b"Package {data.pkg_id} was built from the source hashing to {data.source_hash}".to_string(),
        ],
        ctx,
    );
}

#[test]
/// Pins the `SourceVerification` signing-byte layout against the enclave
/// server's Rust `signing_bytes` test — the enclave↔chain contract.
fun signing_bytes_match_rust() {
    let payload = SourceVerification {
        pkg_id: object::id_from_address(@0x2a),
        source_hash: b"abc",
        git_url: b"https://example.com/repo.git".to_string(),
        subdir: b"pkg".to_string(),
        git_sha: b"deadbeef".to_string(),
    };
    let msg = enclave::create_intent_message(VERIFY_SCOPE, 1_700_000_000_000, payload);
    let expected =
        x"000068e5cf8b010000000000000000000000000000000000000000000000000000000000000000002a036162631c68747470733a2f2f6578616d706c652e636f6d2f7265706f2e67697403706b67086465616462656566";
    assert!(sui::bcs::to_bytes(&msg) == expected);
}
