# source_verification

Verifiable **source ↔ on-chain-bytecode** attestations for Sui Move packages,
produced by a Nautilus (AWS Nitro) enclave and recorded through the
`attestations` framework.

## What it does

An enclave running `verify-source` checks that a Move package's committed source
compiles to the bytecode + linkage published on-chain, then signs a
`SourceVerification`. This package verifies that signature against a registered
`Enclave<SourceVerifier>` and mints an `Attestation<SourceVerification>` about the
on-chain package.

## Architecture

- **Enclave (signer)** — `src/nautilus-server/src/apps/source-verification` in this
  repo. Given `{git_url, git_rev, subdir, build_env}`, it clones the source,
  hashes it, runs `verify-source`, and — on a match — signs
  `SourceVerification{pkg_id, source_hash, git_url, subdir, git_sha}` (intent
  scope `0`).
- **On-chain (this package)** — `attest_source` verifies that signature and
  publishes the attestation.
- Built on **Nautilus** (`enclave`: `Enclave`/`EnclaveConfig`, permissionless
  `register_enclave`, `verify_signature`) and **attestations** (`Attestation<T>`,
  `attest`). No dependency on cormorant.

The payload layout is byte-locked to the enclave's Rust struct by a cross-language
BCS test (`signing_bytes_match_rust` here ↔ `signing_bytes` in the enclave app).

## Registration is permissionless

`enclave::register_enclave` takes no capability: anyone running an enclave whose
PCRs match `EnclaveConfig<SourceVerifier>` can register their own shared
`Enclave<SourceVerifier>` and provide the service, and `attest_source` accepts any
of them. Expect a handful of providers in practice; the point is that nobody can
gatekeep new ones or kill someone else's enclave.

## Trust model: an attestation is a reverifiable cache

The claim — "package `X` was built from source hashing to `H`" — is objective and
cheap for anyone to recompute (`verify-source` + `blake2b256` of the package dir).
So an attestation is a **cache of a publicly checkable fact, not an authority**:

- **Detectable** — a false attestation is caught by re-running `verify-source`.
- **Competable** — anyone can stand up a rival attestation stack.
- **Bypassable (off-chain)** — an off-chain consumer can just reverify itself.

The one place trust genuinely bites is **on-chain consumers** — another Move
contract that gates on a source-verification attestation can't run `verify-source`
at call time, so it must pick which stack(s) to trust in its code, and switching
means a contract upgrade.

## `source_hash` vs `git_sha`

`source_hash` (blake2b256 over the package directory) is the **authoritative**
identifier — reproducible by anyone from the same tree. The `git_url` / `subdir` /
`git_sha` fields are **informational provenance only**: git's SHA-1 is not
collision-resistant and must not be relied on for integrity.

## Governance

Three capabilities can each, in principle, forge a false attestation, so they are
**soundness roots** and must be governed jointly:

- the `source_verification` package **UpgradeCap** — could rewrite `attest_source`;
- our vendored `enclave` package **UpgradeCap** — could add a function minting a
  fake `Enclave<SourceVerifier>`;
- the `EnclaveConfig` **MaintainerCap** — `update_pcrs` could point the accepted
  PCRs at a malicious enclave.

Plus external roots we inherit but don't control: the `attestations` package
(Mysten), the framework's `nitro_attestation` native, and the AWS Nitro root.

**Decision: keep** the three caps (for upgradability — e.g. a future incompatible
Move-format change forcing a new enclave/contract) in a **multisig**, ideally with
a timelock on `update_pcrs` and upgrades. Do **not** freeze: freezing one root
while keeping another is theater, and freezing all of them trades away
upgradability for no real gain, since the trust here is already soft — competable,
reverifiable, and bypassable off-chain. A multisig is sufficient; no heavier
governance machinery is warranted.
