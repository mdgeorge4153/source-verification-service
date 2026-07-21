# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#!/bin/bash

# Gets the enclave id and CID
# expects there to be only one enclave running
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
ENCLAVE_CID=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveCID")

sleep 5
# Forward host port 3000 to the enclave. This only opens a local listener -- it
# connects to the enclave lazily, per incoming connection -- so it is started
# before the secrets exchange below rather than after it, and cannot be left
# unstarted if that exchange does not complete.
socat TCP4-LISTEN:3000,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:3000 &

# Secrets-block
# This section will be populated by configure_enclave.sh based on secret configuration

# Hand the enclave its secrets. -T bounds the exchange: without it this socat has
# been observed not to return, leaving the script hung.
cat secrets.json | socat -T 5 - VSOCK-CONNECT:$ENCLAVE_CID:7777

# Additional port configurations will be added here by configure_enclave.sh if needed
