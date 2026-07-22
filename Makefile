REGISTRY := local

# Resources given to the enclave by `make run` / `make run-debug`. An image that
# carries a large prebuilt binary needs more than the default: the enclave
# filesystem is RAM. Must stay within the allocator (see configure_enclave.sh).
CPU_COUNT := 2
MEMORY := 512M

.DEFAULT_GOAL :=
.PHONY: default
default: out/nitro.eif

out:
	mkdir -p out

out/nitro.eif: $(shell git ls-files src) | out
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

