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

#[test_only]
use sui::test_scenario;

#[error(code = 0)]
const EBadSignature: vector<u8> =
    b"enclave signature does not verify against the registered enclave";

/// Intent scope the enclave stamps when signing a `SourceVerification`. Must
/// match `IntentScope::SourceVerification` in the enclave server.
const VERIFY_SCOPE: u8 = 0;

// Expected enclave PCRs, set at publish and updatable by the `Cap` holder via
// `enclave::update_pcrs`. From the EIF that carries the verifier (215 MB,
// commit cbf3d34): `make ENCLAVE_APP=source-verification` then out/nitro.pcrs.
// A deployer can `update_pcrs` to all-zeros for debug-mode testing.
//
// PCR2 has been identical across every build regardless of contents, so it is
// PCR0/PCR1 that actually bind the image; pinning PCR2 costs nothing but proves
// nothing either.
const PCR0: vector<u8> =
    x"8b4074fbb4ed0ed70db680838c3885e40ac2d47996b0e6a6e69359bb00602c472db0d8a099df29941cbf36dd5bf27f4a";
const PCR1: vector<u8> =
    x"8b4074fbb4ed0ed70db680838c3885e40ac2d47996b0e6a6e69359bb00602c472db0d8a099df29941cbf36dd5bf27f4a";
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
///
/// `toolchain_version` and `toolchain_digest` name the compiler that performed
/// the rebuild. The enclave downloads that compiler at run time, so it is not
/// covered by the PCRs in `EnclaveConfig`: the PCRs attest to the image, and
/// these two fields attest to what the image then fetched and ran.
/// `toolchain_digest` is sha256 of that binary, so a consumer can check it
/// against the official release for `toolchain_version` and decide whether to
/// believe the rebuild.
#[allow(unused_field)]
public struct SourceVerification has copy, store, drop {
    pkg_id: ID,
    source_hash: vector<u8>,
    git_url: String,
    subdir: String,
    git_sha: String,
    toolchain_version: String,
    toolchain_digest: vector<u8>,
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
/// `Attestation<SourceVerification>` about `pkg_id`. Accepts any
/// `Enclave<SourceVerifier>` registered against the config (permissionless
/// multi-provider). `registry` is the attestations `Registry` id. Returns the
/// new attestation's ID.
///
/// The payload arrives as fields rather than as a `SourceVerification` because a
/// programmable transaction can supply only primitives, vectors and a handful of
/// special types as pure arguments; an arbitrary Move struct is not among them,
/// so taking the struct by value would make this uncallable. Rebuilding it here
/// is also what gives the signature check its meaning — the signature is checked
/// against the fields the caller actually supplied.
public fun attest_source(
    registry: ID,
    enclave: &Enclave<SourceVerifier>,
    pkg_id: ID,
    source_hash: vector<u8>,
    git_url: String,
    subdir: String,
    git_sha: String,
    toolchain_version: String,
    toolchain_digest: vector<u8>,
    timestamp_ms: u64,
    signature: vector<u8>,
    ctx: &mut TxContext,
): ID {
    let payload = SourceVerification {
        pkg_id,
        source_hash,
        git_url,
        subdir,
        git_sha,
        toolchain_version,
        toolchain_digest,
    };
    assert!(
        enclave.verify_signature(VERIFY_SCOPE, timestamp_ms, payload, &signature),
        EBadSignature,
    );
    attest(registry, internal::permit<SourceVerification>(), pkg_id, payload, ctx)
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
        toolchain_version: b"1.71.1".to_string(),
        toolchain_digest: b"xyz",
    };
    let msg = enclave::create_intent_message(VERIFY_SCOPE, 1_700_000_000_000, payload);
    let expected =
        x"000068e5cf8b010000000000000000000000000000000000000000000000000000000000000000002a036162631c68747470733a2f2f6578616d706c652e636f6d2f7265706f2e67697403706b6708646561646265656606312e37312e310378797a";
    assert!(sui::bcs::to_bytes(&msg) == expected);
}

#[test]
/// `attest_source` accepts a payload correctly signed by a registered enclave
/// and mints the attestation. The `Enclave<SourceVerifier>` is fabricated with
/// the fixed test pubkey, and the signature is the matching one emitted by the
/// enclave app's `signing_bytes` test over the same payload.
fun attest_source_accepts_valid_signature() {
    let alice = @0xA11CE;
    let mut scenario = test_scenario::begin(alice);
    attestations::attestations::init_for_testing(scenario.ctx());
    let enclave = enclave::new_enclave_for_testing<SourceVerifier>(
        x"d04a166e8dcd71127be0012f3e882c9b8c355af7d43dd98f8200b69eb17e312f",
        scenario.ctx(),
    );

    scenario.next_tx(alice);
    let registry: Registry = scenario.take_shared();
    let _ = attest_source(
        object::id(&registry),
        &enclave,
        object::id_from_address(@0x2a),
        b"abc",
        b"https://example.com/repo.git".to_string(),
        b"pkg".to_string(),
        b"deadbeef".to_string(),
        b"1.71.1".to_string(),
        b"xyz",
        1_700_000_000_000,
        x"d13ea677c4a3e33c9ec5010f0724e55fc19edb8518818653ed88b8b85bf62645d5f2b34d3ff972ae10fb65df2413e9aa39c66e45df6c815b9a43e90716c32a0b",
        scenario.ctx(),
    );

    test_scenario::return_shared(registry);
    enclave::destroy(enclave);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = EBadSignature)]
/// A signature that doesn't verify against the enclave's key is rejected.
fun attest_source_rejects_bad_signature() {
    let alice = @0xA11CE;
    let mut scenario = test_scenario::begin(alice);
    attestations::attestations::init_for_testing(scenario.ctx());
    let enclave = enclave::new_enclave_for_testing<SourceVerifier>(
        x"d04a166e8dcd71127be0012f3e882c9b8c355af7d43dd98f8200b69eb17e312f",
        scenario.ctx(),
    );

    scenario.next_tx(alice);
    let registry: Registry = scenario.take_shared();
    let _ = attest_source(
        object::id(&registry),
        &enclave,
        object::id_from_address(@0x2a),
        b"abc",
        b"https://example.com/repo.git".to_string(),
        b"pkg".to_string(),
        b"deadbeef".to_string(),
        b"1.71.1".to_string(),
        b"xyz",
        1_700_000_000_000,
        x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        scenario.ctx(),
    );

    test_scenario::return_shared(registry);
    enclave::destroy(enclave);
    scenario.end();
}
