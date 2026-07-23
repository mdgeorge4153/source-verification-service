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
use fastcrypto::hash::{Blake2b256, HashFunction, Sha256};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;

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
///
/// `toolchain_version` and `toolchain_digest` name the compiler that produced the
/// comparison. They are load-bearing, not informational: the compiler is fetched
/// at run time and so is *not* covered by the enclave's PCRs, which measure only
/// the image. Without them the attestation would assert a rebuild without saying
/// what performed it, and a substituted release would be indistinguishable.
/// `toolchain_digest` is sha256 of the compiler binary as executed, so a consumer
/// can check it against the corresponding official release.
///
/// The two digests are lowercase hex strings rather than byte vectors. They exist
/// to be compared by whoever reads the attestation -- against a recomputed source
/// hash, or against `sha256sum` of an official release -- and a `vector<u8>`
/// renders in explorers as a list of decimal numbers, which nobody can compare
/// against anything.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceVerification {
    pub pkg_id: [u8; 32],
    pub source_hash: String,
    pub git_url: String,
    pub subdir: String,
    pub git_sha: String,
    pub toolchain_version: String,
    pub toolchain_digest: String,
}

/// Admits one verification at a time.
///
/// Two reasons, either sufficient. A verification holds a source checkout, a
/// build tree, and a ~200 MB compiler in a filesystem that is RAM, so running
/// them concurrently multiplies the scarcest resource the enclave has — and
/// exhausting it kills the enclave rather than the request, losing the ephemeral
/// key and forcing re-registration. Separately, the compiler cache evicts
/// least-recently-used entries on install, so a concurrent verification can
/// delete the binary this one is about to hash.
static VERIFY_LOCK: Mutex<()> = Mutex::const_new(());

/// Clone the source, hash it, verify it against the on-chain package, and — on a
/// match — return a signed `SourceVerification`. Verifications are serialized;
/// see `VERIFY_LOCK`.
pub async fn process_data(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ProcessDataRequest<VerifyRequest>>,
) -> Result<Json<ProcessedDataResponse<IntentMessage<SourceVerification>>>, EnclaveError> {
    let req = request.payload;
    let _guard = VERIFY_LOCK.lock().await;

    let workdir = Workdir {
        path: std::env::temp_dir().join(format!("srcverif-{}", uuid::Uuid::new_v4())),
    };
    check_request(&req)?;
    let clone = workdir.path.join("repo");
    git_clone_checkout(&req.git_url, &req.git_rev, &clone)?;
    let git_sha = git_rev_parse(&clone)?;
    let package_dir = clone.join(&req.subdir);

    // Hash the pristine source, then verify it against the on-chain bytecode
    // recorded in the source's Published.toml for this env. What it compared
    // against, and what compiled it, come back from verify-source itself.
    prune_to_build_inputs(&package_dir)?;
    let source_hash = hash_dir(&package_dir)?;
    let verified = run_verify_source(&package_dir, &req.build_env, &workdir.path.join("move"))?;
    let toolchain = std::fs::read(&verified.binary_path)
        .map_err(|e| err(format!("read toolchain {:?}: {e}", verified.binary_path)))?;

    let payload = SourceVerification {
        pkg_id: parse_pkg_id(&verified.published_at)?,
        source_hash,
        git_url: req.git_url,
        subdir: req.subdir,
        git_sha,
        toolchain_version: verified.toolchain_version,
        toolchain_digest: Hex::encode(Sha256::digest(toolchain).digest),
    };
    Ok(Json(to_signed_response(
        &state.eph_kp,
        payload,
        now_ms()?,
        IntentScope::SourceVerification as u8,
    )))
}

/// Reject request fields that git would read as options, or that would escape
/// the request's working directory.
///
/// These are attacker-controlled and reach `git` as positional arguments, where a
/// leading `-` is an option rather than an operand: a `git_url` of
/// `--upload-pack=<cmd>` runs `<cmd>`. The enclave holds the signing key, so code
/// execution here forges attestations rather than merely misbehaving. `subdir` is
/// joined onto the checkout, and `Path::join` with an absolute path discards the
/// base entirely, so an unchecked value selects any directory in the image.
fn check_request(req: &VerifyRequest) -> Result<(), EnclaveError> {
    if !req.git_url.starts_with("https://") {
        return Err(err("git_url must be an https:// URL"));
    }
    if req.git_rev.is_empty()
        || !req
            .git_rev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./_-".contains(&b))
        || req.git_rev.starts_with('-')
        || req.git_rev.contains("..")
    {
        return Err(err("git_rev must be a plain branch, tag or commit"));
    }
    let subdir = Path::new(&req.subdir);
    if subdir.is_absolute()
        || subdir
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(err("subdir must be a relative path inside the repository"));
    }
    Ok(())
}

/// A scratch directory removed when dropped.
///
/// On drop rather than at the end of a request because a verification can fail
/// at several points, and a leaked checkout and build tree stay in the enclave's
/// RAM-backed filesystem for the life of the enclave. Failures are the common
/// case for a service that verifies whatever it is asked to.
struct Workdir {
    path: PathBuf,
}

impl Drop for Workdir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Parse a (optionally `0x`-prefixed) 32-byte hex package id.
fn parse_pkg_id(s: &str) -> Result<[u8; 32], EnclaveError> {
    let bytes = Hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| err(format!("bad id {s}: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| err(format!("id {s} is not 32 bytes")))
}

/// Clone `url` into `dest` and check out `rev`.
fn git_clone_checkout(url: &str, rev: &str, dest: &Path) -> Result<(), EnclaveError> {
    let dest = path_str(dest)?;
    // `--` as well as the checks in `check_request`: either alone stops a
    // leading-dash operand being read as an option.
    run("git", &["clone", "--quiet", "--", url, dest])?;
    run("git", &["-C", dest, "checkout", "--quiet", rev, "--"])
}

/// Resolve the checked-out commit to its full SHA.
fn git_rev_parse(dir: &Path) -> Result<String, EnclaveError> {
    Ok(
        output("git", &["-C", path_str(dir)?, "rev-parse", "HEAD"], &[])?
            .trim()
            .to_string(),
    )
}

/// The fullnode a build environment is verified against.
///
/// Only the environments the enclave can actually reach: it has no DNS, just the
/// fixed `/etc/hosts` entries `run.sh` writes, so accepting others would turn a
/// configuration mistake into an opaque connection failure.
fn rpc_url(build_env: &str) -> Result<&'static str, EnclaveError> {
    match build_env {
        "mainnet" => Ok("https://fullnode.mainnet.sui.io:443"),
        "testnet" => Ok("https://fullnode.testnet.sui.io:443"),
        other => Err(err(format!(
            "unsupported build_env {other:?}: the enclave has egress for mainnet and testnet only"
        ))),
    }
}

/// Write a client config for `build_env` under `dir`, returning its path.
///
/// `--build-env` selects which publication to compare against, but the RPC comes
/// from the client's *active environment*. Without a config the CLI creates one
/// defaulting to testnet, and a mainnet package is then reported as not found.
/// No key is needed: verification only reads.
fn write_client_config(dir: &Path, build_env: &str) -> Result<PathBuf, EnclaveError> {
    let rpc = rpc_url(build_env)?;
    std::fs::create_dir_all(dir).map_err(|e| err(format!("create {dir:?}: {e}")))?;
    let keystore = dir.join("sui.keystore");
    std::fs::write(&keystore, "[]").map_err(|e| err(format!("write keystore: {e}")))?;
    let config = dir.join("client.yaml");
    // A raw literal, not an escaped one: the indentation here is significant, and
    // an escaped string with line continuations had its alignment whitespace
    // folded into the value by rustfmt, producing YAML that would not parse.
    let yaml = format!(
        r#"keystore:
  File: {keystore}
envs:
  - alias: {build_env}
    rpc: "{rpc}"
    ws: ~
    basic_auth: ~
active_env: {build_env}
active_address: ~
"#,
        keystore = path_str(&keystore)?,
    );
    std::fs::write(&config, yaml).map_err(|e| err(format!("write client config: {e}")))?;
    Ok(config)
}

/// What `verify-source` reports on success, from its `--json` output.
///
/// Deliberately not derived from the package's own `Published.toml`: the address
/// compared against and the compiler used are decisions `verify-source` makes,
/// including precedence rules this app would otherwise have to reproduce and keep
/// in step. It reports a superset of these fields; the rest are ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedMetadata {
    /// The on-chain address whose bytecode the rebuild was compared against.
    published_at: String,
    /// The release the source was rebuilt with.
    toolchain_version: String,
    /// The `sui` binary that performed the rebuild.
    binary_path: PathBuf,
}

/// Run `sui client verify-source --build-env <env> --json <dir>`; a zero exit
/// means the source compiles to the on-chain bytecode + linkage recorded in the
/// package's `Published.toml` for `<env>`. Returns what it verified against and
/// with. `SUI_BIN` overrides the binary (defaults to `sui` on PATH).
///
/// `move_home` is this request's alone, so the compiler and the dependency
/// checkouts it downloads are removed with the workdir. That matters most for
/// packages published by older releases, whose package system clones whole
/// dependency repositories rather than sparse, shallow ones — into a filesystem
/// that is RAM. Per-request also means no cache is shared between requests, so
/// the eviction policy has nothing to race with here.
fn run_verify_source(
    package_dir: &Path,
    build_env: &str,
    move_home: &Path,
) -> Result<VerifiedMetadata, EnclaveError> {
    let sui = std::env::var("SUI_BIN").unwrap_or_else(|_| "sui".to_string());
    let config = write_client_config(move_home, build_env)?;
    let stdout = output(
        &sui,
        &[
            "client",
            "--client.config",
            path_str(&config)?,
            "verify-source",
            "--build-env",
            build_env,
            "--json",
            path_str(package_dir)?,
        ],
        &[("MOVE_HOME", path_str(move_home)?)],
    )?;
    serde_json::from_str(&stdout)
        .map_err(|e| err(format!("parse verify-source --json output: {e}: {stdout}")))
}

/// Delete everything in the package directory except the files that determine the
/// build, leaving `sources/`, `Move.toml`, `Move.lock`, and `Published.toml`.
///
/// Done before both hashing and building, so `source_hash` covers *exactly* the
/// files the rebuild reads: a file outside this set cannot influence the bytecode
/// and later be changed without changing the hash. It also drops `.git` for a
/// root-level package (`subdir` empty), which a whole-directory hash would fold
/// in. `git_sha` is already resolved by this point, so removing `.git` is safe.
///
// REVIEW: this is the definition of "the package's source" that source_hash
// commits to. `move build` compiles `sources/` and resolves dependencies from the
// manifests; nothing else in the directory affects the bytecode. Confirm this set
// is complete for the package layouts we care about before relying on it.
fn prune_to_build_inputs(dir: &Path) -> Result<(), EnclaveError> {
    const KEEP: &[&str] = &["sources", "Move.toml", "Move.lock", "Published.toml"];
    for entry in std::fs::read_dir(dir).map_err(|e| err(format!("readdir {dir:?}: {e}")))? {
        let path = entry.map_err(|e| err(format!("direntry: {e}")))?.path();
        let keep = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| KEEP.contains(&n));
        if keep {
            continue;
        }
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.map_err(|e| err(format!("prune {path:?}: {e}")))?;
    }
    Ok(())
}

/// Lowercase hex of a blake2b256 over a lexicographically-sorted manifest of the
/// package directory:
/// for each file, `<relative path>` + NUL + `blake2b256(contents)`. Reproducible
/// from the same source tree; filenames and file boundaries are part of the hash
/// so content cannot be shuffled between files undetected. Runs after
/// `prune_to_build_inputs`, so "the package directory" is exactly the build inputs.
fn hash_dir(dir: &Path) -> Result<String, EnclaveError> {
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files)?;
    files.sort();
    let mut manifest = Blake2b256::new();
    for rel in files {
        let content = std::fs::read(dir.join(&rel)).map_err(|e| err(format!("read {rel}: {e}")))?;
        manifest.update(rel.as_bytes());
        manifest.update([0u8]);
        manifest.update(Blake2b256::digest(content).digest);
    }
    Ok(Hex::encode(manifest.finalize().digest))
}

/// Collect files under `dir` as paths relative to `root`.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), EnclaveError> {
    for entry in std::fs::read_dir(dir).map_err(|e| err(format!("readdir {dir:?}: {e}")))? {
        let path = entry.map_err(|e| err(format!("direntry: {e}")))?.path();
        if path.is_dir() {
            collect_files(root, &path, out)?;
        } else {
            out.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    Ok(())
}

/// Run a command, returning an error carrying its output on non-zero exit.
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
            described(&out)
        )))
    }
}

/// Run a command with `envs` set, capturing stdout and erroring with its output
/// on non-zero exit.
fn output(bin: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<String, EnclaveError> {
    let out = Command::new(bin)
        .args(args)
        .envs(envs.iter().copied())
        .output()
        .map_err(|e| err(format!("failed to spawn {bin}: {e}")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(err(format!("{bin} failed: {}", described(&out))))
    }
}

/// Both output streams of a failed command, labelled.
///
/// Both, because a failed verification is the case a requestor most needs to
/// read, and `verify-source` splits its reporting across the two: progress and
/// the `--json` result go to stdout, warnings and the rebuild's own diagnostics
/// to stderr. Which stream carries the detail of a given failure is not worth
/// depending on. This is debugging output only — it is returned unsigned, so it
/// carries no more authority than the server sending it.
fn described(out: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (true, true) => format!("no output ({})", out.status),
        (true, false) => format!("{}\n{stderr}", out.status),
        (false, true) => format!("{}\n{stdout}", out.status),
        (false, false) => format!("{}\nstdout:\n{stdout}\nstderr:\n{stderr}", out.status),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::IntentMessage;
    use fastcrypto::encoding::{Encoding, Hex};

    fn req(git_url: &str, git_rev: &str, subdir: &str) -> VerifyRequest {
        VerifyRequest {
            git_url: git_url.to_string(),
            git_rev: git_rev.to_string(),
            subdir: subdir.to_string(),
            build_env: "mainnet".to_string(),
        }
    }

    /// A well-formed request is accepted.
    #[test]
    fn check_request_accepts_ordinary_input() {
        assert!(check_request(&req(
            "https://github.com/MystenLabs/deepbookv3.git",
            "verify/v8",
            "packages/deepbook"
        ))
        .is_ok());
        assert!(check_request(&req("https://example.com/x.git", "e87243ed", "")).is_ok());
    }

    /// Fields git would read as options are rejected. `--upload-pack=<cmd>` as a
    /// URL is remote code execution in an enclave that holds a signing key.
    #[test]
    fn check_request_rejects_option_lookalikes() {
        assert!(check_request(&req("--upload-pack=touch /tmp/pwn", "main", "p")).is_err());
        assert!(check_request(&req("-q", "main", "p")).is_err());
        assert!(check_request(&req("git@github.com:a/b.git", "main", "p")).is_err());
        assert!(check_request(&req("https://e.com/x.git", "--upload-pack=x", "p")).is_err());
        assert!(check_request(&req("https://e.com/x.git", "-q", "p")).is_err());
    }

    /// Subdirs that leave the checkout are rejected. `Path::join` with an
    /// absolute path discards the base, selecting any directory in the image.
    #[test]
    fn check_request_rejects_escaping_subdir() {
        assert!(check_request(&req("https://e.com/x.git", "main", "/etc")).is_err());
        assert!(check_request(&req("https://e.com/x.git", "main", "../../etc")).is_err());
        assert!(check_request(&req("https://e.com/x.git", "main", "a/../../b")).is_err());
    }

    /// The generated client config is valid YAML with the indentation the sui
    /// CLI expects. Pinned because an earlier version built this with escaped
    /// line continuations, and rustfmt folded the alignment whitespace into the
    /// string, emitting a file the CLI refused to parse.
    #[test]
    fn client_config_yaml_is_well_formed() {
        let dir = std::env::temp_dir().join(format!("cfgtest-{}", std::process::id()));
        let config = write_client_config(&dir, "mainnet").expect("writes");
        let text = std::fs::read_to_string(&config).expect("reads");

        assert!(text.contains("\n  - alias: mainnet\n"));
        assert!(text.contains("\n    rpc: \"https://fullnode.mainnet.sui.io:443\"\n"));
        assert!(text.contains("\n    ws: ~\n"));
        assert!(text.contains("\n    basic_auth: ~\n"));
        assert!(text.contains("\nactive_env: mainnet\n"));
        // Every key under the env entry sits at exactly four spaces.
        for line in text
            .lines()
            .filter(|l| l.starts_with(' ') && l.contains(": "))
        {
            let indent = line.len() - line.trim_start().len();
            assert!(
                indent == 2 || indent == 4,
                "bad indent {indent} in {line:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Pins the `verify-source --json` contract this app parses. Fields it does
    /// not need (here `originalId`) must be tolerated, not rejected.
    #[test]
    fn parses_verify_source_json() {
        let json = r#"{
            "originalId": "0x0e735f8c93a95722efd73521aca7a7652c0bb71ed1daf41b26dfd7d1ff71f748",
            "publishedAt": "0x0e735f8c93a95722efd73521aca7a7652c0bb71ed1daf41b26dfd7d1ff71f748",
            "toolchainVersion": "1.71.1",
            "binaryPath": "/root/.move/binaries/1.71.1/target/release/sui"
        }"#;

        let m: VerifiedMetadata = serde_json::from_str(json).expect("parses");
        assert_eq!(m.toolchain_version, "1.71.1");
        assert_eq!(
            m.binary_path,
            PathBuf::from("/root/.move/binaries/1.71.1/target/release/sui")
        );
        assert_eq!(
            parse_pkg_id(&m.published_at).expect("id")[..4],
            [0x0e, 0x73, 0x5f, 0x8c]
        );
    }

    /// Prints the BCS signing bytes for a fixed `SourceVerification` vector, to
    /// pin against the Move `source_verification` package's byte-test.
    #[test]
    fn signing_bytes() {
        let mut pkg_id = [0u8; 32];
        pkg_id[31] = 0x2a;
        let payload = SourceVerification {
            pkg_id,
            source_hash: "abc".to_string(),
            git_url: "https://example.com/repo.git".to_string(),
            subdir: "pkg".to_string(),
            git_sha: "deadbeef".to_string(),
            toolchain_version: "1.71.1".to_string(),
            toolchain_digest: "xyz".to_string(),
        };
        let msg = IntentMessage::new(
            payload,
            1_700_000_000_000,
            IntentScope::SourceVerification as u8,
        );
        let bytes = bcs::to_bytes(&msg).expect("bcs");
        println!("SIGNING_BYTES_HEX={}", Hex::encode(&bytes));

        // Deterministic keypair + signature over those bytes, for the Move
        // package's `attest_source` unit test (fixed pk + sig it can hardcode).
        use fastcrypto::ed25519::Ed25519KeyPair;
        use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
        let kp = Ed25519KeyPair::generate(&mut rng);
        let sig = kp.sign(&bytes);
        println!("PK_HEX={}", Hex::encode(kp.public().as_bytes()));
        println!("SIG_HEX={}", Hex::encode(sig.as_ref()));
    }
}
