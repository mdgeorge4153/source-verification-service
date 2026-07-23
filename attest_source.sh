#!/bin/bash
# Request a source verification for the Move package in the current directory,
# and optionally record the result onchain.
#
# Run it from inside the package (the directory holding Move.toml). The git
# coordinates the enclave needs are exactly the ones under your feet, so they are
# read from the checkout rather than passed:
#
#   cd packages/deepbook && ../../attest_source.sh
#
# The enclave clones from the *remote*, so what it verifies is the pushed commit,
# not your working tree. The checks below exist to stop the two ways that
# silently diverges: uncommitted changes, and a commit you have not pushed.
#
# Configuration (environment):
#   ENCLAVE_URL              required, e.g. http://1.2.3.4:3000
#   BUILD_ENV                environment to verify against (default: mainnet)
#   APP_PACKAGE_ID           source_verification package, required to attest
#   ENCLAVE_OBJECT_ID        the registered Enclave<SourceVerifier> shared object
#   ENCLAVE_CONFIG_ID        the EnclaveConfig<SourceVerifier> shared object
#   ATTESTATION_REGISTRY_ID  the attestations Registry shared object
#   GAS_BUDGET               default 100000000 (0.1 SUI)
#
# With the last three unset it stops after printing the signed response, which is
# a complete result in itself: the signature is the product, recording it onchain
# is optional and anyone can do it later.

set -euo pipefail

BUILD_ENV="${BUILD_ENV:-mainnet}"
GAS_BUDGET="${GAS_BUDGET:-100000000}"
ATTEST=true
[ "${1:-}" = "--no-attest" ] && ATTEST=false

die() { echo "error: $*" >&2; exit 1; }

[ -n "${ENCLAVE_URL:-}" ] || die "set ENCLAVE_URL (e.g. http://1.2.3.4:3000)"
[ -f Move.toml ] || die "no Move.toml here; run this from inside the package"
git rev-parse --git-dir >/dev/null 2>&1 || die "not a git checkout"

# --- what the enclave will be asked to verify -------------------------------

GIT_REV=$(git rev-parse HEAD)
REPO_ROOT=$(git rev-parse --show-toplevel)
# Pure parameter expansion: realpath --relative-to is GNU-only and silently
# yields an empty subdir on macOS, which would verify the wrong directory.
SUBDIR="${PWD#"$REPO_ROOT"}"
SUBDIR="${SUBDIR#/}"

# The enclave has no ssh credentials, so an ssh remote has to be rewritten.
RAW_URL=$(git remote get-url origin 2>/dev/null) || die "no 'origin' remote"
GIT_URL=$(printf '%s' "$RAW_URL" \
    | sed -e 's|^git@\([^:]*\):|https://\1/|' -e 's|^ssh://git@|https://|')

# --- refuse to attest something that is not what is published ---------------

if ! git diff --quiet HEAD -- . 2>/dev/null; then
    die "uncommitted changes in this package; the enclave verifies the pushed commit, not your tree"
fi

git fetch --quiet origin 2>/dev/null || echo "warning: could not fetch origin; push check may be stale" >&2
if [ -z "$(git branch -r --contains "$GIT_REV" 2>/dev/null)" ]; then
    die "commit $GIT_REV is not on any remote branch; push it first, or the enclave will clone something else"
fi

echo "package:   $GIT_URL [$SUBDIR] @ $GIT_REV"
echo "verifying against: $BUILD_ENV"

# --- ask the enclave --------------------------------------------------------

REQUEST=$(jq -n --arg u "$GIT_URL" --arg r "$GIT_REV" --arg s "$SUBDIR" --arg e "$BUILD_ENV" \
    '{payload: {git_url: $u, git_rev: $r, subdir: $s, build_env: $e}}')

RESPONSE=$(curl -sS --fail-with-body -X POST "$ENCLAVE_URL/process_data" \
    -H 'Content-Type: application/json' -d "$REQUEST") \
    || die "enclave rejected the request:
$RESPONSE"

echo "$RESPONSE" | jq .

SIGNATURE=$(echo "$RESPONSE" | jq -r '.signature')
[ -n "$SIGNATURE" ] && [ "$SIGNATURE" != "null" ] || die "no signature in response"

if ! $ATTEST; then
    echo "--no-attest: stopping with the signed response"
    exit 0
fi
for v in APP_PACKAGE_ID ENCLAVE_OBJECT_ID ENCLAVE_CONFIG_ID ATTESTATION_REGISTRY_ID; do
    [ -n "${!v:-}" ] || { echo "$v unset; stopping with the signed response (nothing recorded onchain)"; exit 0; }
done

# --- record it onchain ------------------------------------------------------

# pkg_id is a 32-byte array in the response but an ID in Move, so it becomes an
# address literal. The digests are already hex strings and pass through as
# strings; only the signature is still a vector<u8>, which `sui client ptb`
# accepts only as a vector[..u8] literal.
#
# These values come from the enclave response, which this script does not
# re-derive and fetches over plain http. A hostile endpoint (the multi-provider
# model makes pointing at someone else's enclave normal) or a MITM can therefore
# put anything here. They are shell-quoted with shlex.quote before eval --
# repr() is NOT shell quoting: it can emit a double-quoted string, inside which
# `$(...)` still executes, so a value of `'$(cmd)` would run cmd on this machine.
eval "$(echo "$RESPONSE" | python3 -c '
import json, shlex, sys
r = json.load(sys.stdin)
d = r["response"]["data"]

def q(name, value):
    print(f"{name}={shlex.quote(value)}")

def vec(byts):
    return "vector[" + ", ".join(f"{b}u8" for b in byts) + "]"

def hexbytes(s):
    return [int(s[i:i+2], 16) for i in range(0, len(s), 2)]

q("PKG_ID", "0x" + "".join(f"{b:02x}" for b in d["pkg_id"]))
q("SOURCE_HASH", d["source_hash"])
q("TOOLCHAIN_DIGEST", d["toolchain_digest"])
q("SIG_VEC", vec(hexbytes(r["signature"])))
q("TIMESTAMP_MS", str(r["response"]["timestamp_ms"]))
q("TOOLCHAIN_VERSION", d["toolchain_version"])
q("RESP_GIT_URL", d["git_url"])
q("RESP_SUBDIR", d["subdir"])
q("RESP_GIT_SHA", d["git_sha"])
')"

echo "recording attestation for $PKG_ID"

sui client ptb \
    --assign signature "$SIG_VEC" \
    --move-call "${APP_PACKAGE_ID}::source_verification::attest_source" \
        @"${ATTESTATION_REGISTRY_ID}" \
        @"${ENCLAVE_OBJECT_ID}" \
        @"${ENCLAVE_CONFIG_ID}" \
        @"${PKG_ID}" \
        "'${SOURCE_HASH}'" \
        "'${RESP_GIT_URL}'" \
        "'${RESP_SUBDIR}'" \
        "'${RESP_GIT_SHA}'" \
        "'${TOOLCHAIN_VERSION}'" \
        "'${TOOLCHAIN_DIGEST}'" \
        "${TIMESTAMP_MS}" \
        signature \
    --gas-budget "$GAS_BUDGET"
