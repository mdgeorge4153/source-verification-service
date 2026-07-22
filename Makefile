REGISTRY := local

# Resources given to the enclave by `make run` / `make run-debug`. The default is
# the upstream one and is too small for this image: it carries a ~200 MB compiler,
# and run.sh mounts a 6G tmpfs for verification scratch that only bounds anything
# if the enclave has memory above it. Must fit within the allocator (see
# /etc/nitro_enclaves/allocator.yaml, which configure_enclave.sh sets to 3072 MiB).
CPU_COUNT := 2
MEMORY := 512M

# The measured verifier: the Move compiler baked into the enclave image.
#
# Pinned by revision AND by the digest of the resulting binary, because the PCRs
# are only meaningful if someone else can arrive at the same image. The revision
# alone is not enough: `cargo build --release` is not guaranteed byte
# reproducible, so a matching revision can still yield a different binary and
# therefore different PCRs. The digest is what actually pins the image; the
# revision records where it came from.
#
# A mismatch is reported rather than ignored. If you hit one, the honest reading
# is that your toolchain produced a different binary from the published one --
# not that the check is wrong. Use the published artifact to reproduce the PCRs
# exactly.
SUI_SRC ?=
VERIFIER := verifier/sui
VERIFIER_REV := e87243ed1d13e3e2f13362dc75fa3ee80f0ba154
VERIFIER_SHA256 := 6b314ba6d46707092b0c4e24a46d78a3bd9f08b60a26b0efe7ec74147b129351

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
	git -C "$(SUI_SRC)" cat-file -e $(VERIFIER_REV) 2>/dev/null || \
		{ echo "$(SUI_SRC) does not contain $(VERIFIER_REV); fetch it first"; exit 1; }
	git -C "$(SUI_SRC)" checkout -q $(VERIFIER_REV)
	mkdir -p $(dir $(VERIFIER))
	docker run --rm \
		-v "$(abspath $(SUI_SRC))":/src -w /src \
		-e GIT_REVISION="$(VERIFIER_REV)" \
		rust:latest bash -c '\
			apt-get update -qq && \
			apt-get install -y -qq clang cmake libssl-dev pkg-config protobuf-compiler >/dev/null && \
			git config --global --add safe.directory /src && \
			cargo build --release --bin sui'
	cp "$(abspath $(SUI_SRC))/target/release/sui" $(VERIFIER)
	@actual=$$(shasum -a 256 $(VERIFIER) | cut -d" " -f1); \
	if [ "$$actual" != "$(VERIFIER_SHA256)" ]; then \
		echo "verifier digest mismatch:"; \
		echo "  expected $(VERIFIER_SHA256)"; \
		echo "  actual   $$actual"; \
		echo "The PCRs this produces will not match the published ones."; \
		exit 1; \
	fi; \
	echo "verifier digest matches $(VERIFIER_SHA256)"
