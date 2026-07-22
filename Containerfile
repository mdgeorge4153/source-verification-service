# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# This containerfile uses StageX (https://stagex.tools) images, which provide a
# full source bootstrapped, deterministic, and hermetic build toolchain

FROM stagex/core-binutils@sha256:f2d3bf6104db0d5ac39ca155c0241bfea2516a6829e3b4fd657cf9ba5b625478 AS core-binutils
FROM stagex/core-ca-certificates@sha256:d135f1189e9b232eb7316626bf7858534c5540b2fc53dced80a4c9a95f26493e AS core-ca-certificates
FROM stagex/core-gcc@sha256:964ffd3793c5a38ca581e9faefd19918c259f1611c4cbf5dc8be612e3a8b72f5 AS core-gcc
FROM stagex/core-git@sha256:6b3e0055f6aeaa8465f207a871db2c63a939cd7406113e9d769ff3b37239f3d0 AS core-git
FROM stagex/core-zlib@sha256:06f5168e20d85d1eb1d19836cdf96addc069769b40f8f0f4a7a70b2f49fc18f8 AS core-zlib
FROM stagex/core-libffi@sha256:64d087343541401271cf9fec6b7bd788040c72a16918748ae36c171e53e94002 AS core-libffi
FROM stagex/core-llvm@sha256:583ecda677f51b69857f8027dfc58f4a931d1adc4d16214870a373505210d973 AS core-llvm
FROM stagex/core-openssl@sha256:d6487f0cb15f4ee02b420c717cb9abd85d73043c0bb3a2c6ce07688b23c1df07 AS core-openssl
FROM stagex/core-rust@sha256:2ea0be043b92321b5d1c2784911a770ccca28c09c3cf6a0f81fc0cd05a2abb08 AS core-rust
FROM stagex/core-musl@sha256:d9af23284cca2e1002cd53159ada469dfe6d6791814e72d6163c7de18d4ae701 AS core-musl
FROM stagex/core-libunwind@sha256:eb66122d8fc543f5e2f335bb1616f8c3a471604383e2c0a9df4a8e278505d3bc AS core-libunwind
FROM stagex/core-pkgconf@sha256:52624a89bb8cc684bc0391fcb7770ded2bbcb281e84bdb68a31fce127439fd7b AS core-pkgconf
FROM stagex/core-busybox@sha256:637b1e0d9866807fac94c22d6dc4b2e1f45c8a5ca1113c88172e0324a30c7283 AS core-busybox
FROM stagex/core-python@sha256:95504b36f4340782f5aa492d68f9a713406391898bf41cd62c9c9b54d6bee3f1 AS core-python
FROM stagex/core-libzstd@sha256:5382c221194b6d0690eb65ccca01c720a6bd39f92e610dbc0e99ba43f38f3094 AS core-libzstd
FROM stagex/core-curl@sha256:fa58ff1a1c32677ce3034e69a2ee40081c799d6df68a7b1d5d480501de779030 AS core-curl
FROM stagex/user-eif_build@sha256:935032172a23772ea1a35c6334aa98aa7b0c46f9e34a040347c7b2a73496ef8a AS user-eif_build
FROM stagex/user-gen_initramfs@sha256:a87e9a3fa8468d2e08b5abb0a6da4c7a11df22273e2c526cb22e6b131151def8 AS user-gen_initramfs
FROM stagex/user-linux-nitro@sha256:aa1006d91a7265b33b86160031daad2fdf54ec2663ed5ccbd312567cc9beff2c AS user-linux-nitro
FROM stagex/user-cpio@sha256:9c8bf39001eca8a71d5617b46f8c9b4f7426db41a052f198d73400de6f8a16df AS user-cpio
FROM stagex/user-socat@sha256:4d1b7a403eba65087a3f69200d2644d01b63f0ea81ef171cedc17de490c8c9a0 AS user-socat
FROM stagex/user-jq@sha256:0c75672e97f54b83661aaa498e053340305e79cdc2004a40d92b7bf5ce906e9c AS user-jq
FROM stagex/user-nit@sha256:60b6eef4534ea6ea78d9f29e4c7feb27407b615424f20ad8943d807191688be7 AS user-nit
# glibc runtime, so the enclave can exec prebuilt (ubuntu-built) binaries such as
# the `sui` toolchain the source verifier downloads. `nautilus-server` itself is
# musl-static and unaffected.
FROM stagex/user-glibc@sha256:56bae3d45f62f61c94c679a5ce0a11c8cc5735448916ed65232edffaba25cde2 AS user-glibc
FROM stagex/core-cross-x86_64-gnu-gcc@sha256:79f4b11f01371aeca88c36c39ff9a5fcdc2e6152dedd2513b2e9026c11fafdc0 AS gnu-gcc

FROM scratch AS base
COPY --from=core-busybox . /
COPY --from=core-musl . /
COPY --from=core-libunwind . /
COPY --from=core-openssl . /
COPY --from=core-zlib . /
COPY --from=core-ca-certificates . /
COPY --from=core-libzstd . /
COPY --from=core-binutils . /
COPY --from=core-pkgconf . /
COPY --from=core-git . /
COPY --from=core-rust . /
COPY --from=user-gen_initramfs . /
COPY --from=user-eif_build . /
COPY --from=core-llvm . /
COPY --from=core-libffi . /
COPY --from=core-gcc . /
COPY --from=user-cpio . /
COPY --from=user-linux-nitro /bzImage .
COPY --from=user-linux-nitro /linux.config .

FROM base AS build
COPY . .

WORKDIR /src/nautilus-server
ENV OPENSSL_STATIC=true
ENV TARGET=x86_64-unknown-linux-musl
ARG ENCLAVE_APP
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static -C target-cpu=x86-64"
RUN cargo build --locked --no-default-features --features $ENCLAVE_APP --release --target "$TARGET"

WORKDIR /build_cpio
ENV KBUILD_BUILD_TIMESTAMP=1
RUN mkdir initramfs/
# Built-in as of latest linux-nitro
# COPY --from=user-linux-nitro /nsm.ko initramfs/nsm.ko
COPY --from=core-busybox . initramfs
COPY --from=core-python . initramfs
COPY --from=core-musl . initramfs
COPY --from=core-ca-certificates /etc/ssl/certs initramfs
COPY --from=core-busybox /bin/sh initramfs/sh
COPY --from=user-jq /bin/jq initramfs
COPY --from=user-socat /bin/socat . initramfs
COPY --from=user-nit /bin/init initramfs
# --- glibc runtime for prebuilt binaries (see the FROM aliases above) ---
# Ubuntu-built binaries hardcode their ELF interpreter as
# /lib64/ld-linux-x86-64.so.2, and that already resolves here: core-busybox
# brings a merged-usr `lib64 -> usr/lib` symlink and user-glibc puts the real
# loader at /usr/lib/ld-linux-x86-64.so.2. Do NOT add a /lib64 symlink of your
# own -- it writes *through* lib64 -> usr/lib and replaces the loader with a
# self-reference ("too many levels of symbolic links").
# libstdc++/libgcc_s must be the GNU-targeted builds under lib64/; core-gcc's are
# musl-targeted and will not serve a glibc binary.
COPY --from=user-glibc . initramfs
COPY --from=gnu-gcc /opt/cross/x86_64-linux-gnu/lib64/libstdc++.so.6* initramfs/usr/lib/
COPY --from=gnu-gcc /opt/cross/x86_64-linux-gnu/lib64/libgcc_s.so.1 initramfs/usr/lib/
# --- what the verifier shells out to ---
# The base image above has none of these: the stock initramfs is busybox, python,
# jq, socat and init. `git` fetches the source under verification and, for older
# packages, its dependencies; it needs zlib, and git-remote-https needs curl,
# which needs openssl. zstd is needed to clone repositories that use it. The full
# ca-certificates package rather than just /etc/ssl/certs, so that curl and git
# find the bundle at its conventional path as well as the one SSL_CERT_FILE names.
COPY --from=core-zlib . initramfs
COPY --from=core-openssl . initramfs
COPY --from=core-libzstd . initramfs
COPY --from=core-curl . initramfs
# Only the pieces the verifier needs, NOT the whole package. git ships ~140
# commands in libexec/git-core as hardlinks to one binary; `COPY` does not
# preserve hardlinks, so copying the package materialises 141 identical 18.9 MB
# files -- 2.6 GB of duplicates in a filesystem that is RAM. Every command in
# that set is a builtin reachable as `git <cmd>`, so the dispatch copies are
# redundant. The remote helpers are separate binaries and are needed: cloning
# over HTTPS execs git-remote-https. /usr/share/git-core holds the templates
# `git clone` requires.
#
# Two earlier attempts deduplicated this after the fact, inside the build. Both
# silently did nothing and still reported success. Not copying the duplicates in
# the first place cannot fail quietly: a wrong path fails the build outright.
COPY --from=core-git /usr/bin/git initramfs/usr/bin/git
COPY --from=core-git /usr/libexec/git-core/git-remote-http initramfs/usr/libexec/git-core/git-remote-http
COPY --from=core-git /usr/libexec/git-core/git-remote-https initramfs/usr/libexec/git-core/git-remote-https
COPY --from=core-git /usr/share/git-core initramfs/usr/share/git-core
COPY --from=core-ca-certificates . initramfs
# The Move compiler the verifier runs. Baked in rather than downloaded so that it
# is covered by the PCRs: an enclave that fetched its own verifier at run time
# would attest to a rebuild performed by unmeasured code. Build it with
# `make verifier` (see the Makefile) before building the EIF.
COPY verifier/sui initramfs/sui
RUN cp /src/nautilus-server/target/${TARGET}/release/nautilus-server initramfs
RUN cp /src/nautilus-server/traffic_forwarder.py initramfs/
RUN cp /src/nautilus-server/run.sh initramfs/
# health_check reads this at runtime from the working directory, so without it
# the endpoint reports an empty endpoints_status -- looking healthy while having
# probed nothing, which is worse than no health check at all.
RUN cp /src/nautilus-server/src/apps/${ENCLAVE_APP}/allowed_endpoints.yaml initramfs/

COPY <<-EOF initramfs/etc/environment
SSL_CERT_FILE=/ca-certificates.crt
GIT_SSL_CAINFO=/ca-certificates.crt
CURL_CA_BUNDLE=/ca-certificates.crt
SUI_BIN=/sui
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/
EOF

# Shrink and pack in one step. These must not be separate layers: git's ~140
# commands in libexec/git-core are hardlinks to one binary, `COPY` does not
# preserve hardlinks, and replacing them in an earlier layer did not survive the
# `COPY` of the verifier that follows it -- the archive still came out with 141
# identical 18.9 MB files. Doing it here means the tree cannot change between
# being shrunk and being packed.
#
# The heredoc delimiter is quoted so Docker performs no substitution and the
# shell receives the script verbatim; with an unquoted delimiter the escaping
# needed to protect '$' from Docker left a literal '$' for the shell instead.
#
# Symlinks rather than hardlinks: they survive, and git dispatches on argv[0]
# either way. Static archives and headers go too -- build-time artifacts nothing
# at run time can load. /usr/share stays: git needs its templates to clone.
RUN <<-'EOF'
	set -eux
	cd /build_cpio/initramfs
	find . -name '*.a' -delete
	rm -rf usr/include
	echo "initramfs: $(du -sh . | cut -f1)"
	# The image must stay small: it is unpacked into the enclave's RAM, and the
	# 6G verification tmpfs only bounds anything if there is memory left above it.
	test "$(du -sm . | cut -f1)" -lt 900
	find . -exec touch -hcd "@0" "{}" + -print0 \
	| sort -z \
	| cpio \
	    --null \
	    --create \
	    --reproducible \
	    --format=newc \
	| gzip --best \
	> /build_cpio/rootfs.cpio
EOF

WORKDIR /build_eif
RUN eif_build \
	--kernel /bzImage \
	--kernel_config /linux.config \
	--ramdisk /build_cpio/rootfs.cpio \
	--pcrs_output /nitro.pcrs \
	--output /nitro.eif \
	--cmdline 'reboot=k initrd=0x2000000,3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd nit.target=/run.sh'

FROM base AS install
WORKDIR /rootfs
COPY --from=build /nitro.eif .
COPY --from=build /nitro.pcrs .
COPY --from=build /build_cpio/rootfs.cpio .

FROM scratch AS package
COPY --from=install /rootfs .
