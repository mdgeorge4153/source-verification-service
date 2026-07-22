REGISTRY := local

# Resources given to the enclave by `make run` / `make run-debug`. The default is
# the upstream one and is too small for this image: it carries a ~200 MB compiler,
# and run.sh mounts a 6G tmpfs for verification scratch that only bounds anything
# if the enclave has memory above it. Must fit within the allocator (see
# /etc/nitro_enclaves/allocator.yaml, which configure_enclave.sh sets to 3072 MiB).
CPU_COUNT := 2
MEMORY := 512M

# A sui checkout to build the measured verifier from; required by `make verifier`.
SUI_SRC ?=
VERIFIER := verifier/sui

.DEFAULT_GOAL :=
.PHONY: default
default: out/nitro.eif

out:
	mkdir -p out

# The verifier is part of the image, so the EIF depends on it: changing it changes
# the PCRs.
out/nitro.eif: $(shell git ls-files src) $(VERIFIER) | out
	docker build \
		--pull \
		--tag $(REGISTRY)/enclaveos \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=out\
		-f Containerfile \
		--build-arg ENCLAVE_APP=$(ENCLAVE_APP) \
		.

.PHONY: run
run: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count $(CPU_COUNT) \
		--memory $(MEMORY) \
		--eif-path out/nitro.eif

.PHONY: run-debug
run-debug: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count $(CPU_COUNT) \
		--memory $(MEMORY) \
		--eif-path out/nitro.eif \
		--debug-mode \
		--attach-console

.PHONY: update
update:
	./update.sh


# Build the Move compiler that gets baked into the enclave image.
#
# GIT_REVISION is passed because `bin_version::bin_version!()` runs `git rev-parse`
# at compile time, and git refuses the bind-mounted checkout as dubiously owned
# when cargo runs as root -- the build then fails with "unable to query git
# revision". safe.directory covers the same ground for any other git call.
.PHONY: verifier
verifier: $(VERIFIER)

$(VERIFIER):
	@test -n "$(SUI_SRC)" || { echo "set SUI_SRC=/path/to/a/sui/checkout"; exit 1; }
	mkdir -p $(dir $(VERIFIER))
	docker run --rm \
		-v "$(abspath $(SUI_SRC))":/src -w /src \
		-e GIT_REVISION="$(shell git -C $(SUI_SRC) rev-parse HEAD 2>/dev/null)" \
		rust:latest bash -c '\
			apt-get update -qq && \
			apt-get install -y -qq clang cmake libssl-dev pkg-config protobuf-compiler >/dev/null && \
			git config --global --add safe.directory /src && \
			cargo build --release --bin sui'
	cp "$(abspath $(SUI_SRC))/target/release/sui" $(VERIFIER)
