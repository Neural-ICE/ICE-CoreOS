# ADR-0006 — Kernel page size: standard 4k flavor instead of kernel-64k

- **Status**: Accepted — amends the *page-size* choice of
  [[ADR-0002-secure-boot-zero-touch]] and [[ADR-0003-base-and-update-model]]
  (the base OS, the update model and the Secure Boot plan are **unchanged**).
- **Date**: 2026-07-01
- **Decider**: Business/Security Owner (human)
- **Guiding principle**: *the appliance must run the software stack it exists to run.*

## Context

The GB10 SoC (Grace-Blackwell) is **not** in the stock el10 kernel nor in
mainline (the Grace-Blackwell + ConnectX-7 enablement lives only in NVIDIA's
Ubuntu kernel fork and Red Hat's developer-preview `nvidia-gb10` tree). So a
**custom kernel is unavoidable** on GB10 today — there is no stock,
upstream-signed kernel that boots this hardware.

We initially shipped the **`kernel-64k`** flavor (Red Hat's recommended flavor
for ARM64, per the DGX-Spark custom-kernel article). In practice, 64 KiB pages
**break the container AI stack the appliance is built to host**:

- **Qdrant** aborts at startup — bundled jemalloc rejects the page size
  (`<jemalloc>: Unsupported system page size`). A recurring, cross-version issue
  on 64k ARM64.
- **vLLM** and many **prebuilt aarch64 wheels / binaries** assume 4 KiB pages
  (mmap/alignment, pinned CUDA memory, allocator page assumptions).
- NVIDIA staff report the same on the DGX Spark forum: *"most of the software
  stack was failing [on the 64k kernel]… I would recommend to fallback to the
  regular kernel."*

Key fact: **64k is a performance-oriented flavor, not a functional requirement.**
Red Hat documents that *"the 4k pages kernel and kernel-64k do not differ in the
user experience as the user space is the same"*; 64k mainly helps large-memory /
HPC / high-throughput-network workloads at the cost of memory overhead.

## Decision

Build and ship the **STANDARD 4 KiB-page `kernel` flavor** from the **same** Red
Hat `nvidia-gb10` tree (i.e. the `kernel*` RPMs, **not** `kernel-64k*`).

Everything else is unchanged:

- **Base** = CentOS Stream 10 bootc (ADR-0003), **OTA** = native `bootc upgrade`.
- **NVIDIA r595 open driver** recompiled against the 4k kernel (identical
  vermagic coupling), baked + signed as before.
- **Secure Boot** (ADR-0002): page size does **not** affect signing. The kernel
  is still self-compiled → still signed with the lab key (interim, MOK-enrolled)
  and the **Microsoft `shim-review` submission plan stays exactly as designed**
  — it now simply signs a 4k kernel instead of a 64k one.

## Rejected alternatives

- **Keep 64k, fix each app** (rebuild jemalloc with `--with-lg-page=16`, patch
  every workload): whack-a-mole across every container, contradicts NVIDIA's own
  guidance, and never converges. Rejected.
- **Revert to a stock, upstream-signed kernel**: *impossible* on GB10 — the SoC
  is not in stock/mainline; RHEL-on-DGX-Spark is an explicit **developer
  preview, not production**. Rejected (not available).
- **Pivot to NVIDIA's Ubuntu-signed 4k kernel** (`6.14.0-nvidia`, MS-signed,
  firmware-trusted): would fix signing *and* page size, but **breaks the
  bootc / rpm-ostree foundation** (ADR-0003) → full re-architecture. Out of
  scope; may be revisited separately.

## Consequences

- (+) Qdrant, vLLM and prebuilt aarch64 wheels run — the appliance's reason to
  exist works.
- (+) **Minimal change**: keeps bootc, OTA, the release channels and the whole
  artifact/build pipeline; only the kernel flavor selected changes.
- (+) The Secure Boot analysis and the Microsoft shim submission (ADR-0002) are
  **unchanged** — no rework of the signing roadmap.
- (−) We give up the 64k large-memory/HPC performance edge — **validate that
  your workloads perform acceptably on 4k** (they are memory-latency, not
  page-size, bound in our case).
- (−) The kernel remains **self-compiled and self-signed** (GB10 is not
  upstream), so the ADR-0002 Secure Boot work is still required. 4k does not
  remove it — it only removes the userspace breakage.

## Implementation (delta)

1. `build/build-kernel.sh` — the `nvidia-gb10` tree ships **"aarch64 64k only"**
   (`redhat/Makefile`: `BUILDOPTS += … -arm64_4k …`, and `-arm64_4k` forces
   `with_up=0` → no 4k `up` kernel; see `kernel.spec.template`). The script
   **flips that token to `-arm64_64k` at build time** (the tree is
   `git reset --hard` on every run, so this cannot live in a tree commit), so it
   builds the **4k `up` kernel** and drops 64k. A guard **fails the build** if no
   `kernel-core-*.rpm` (4k) is produced. The NVIDIA driver `kver` is derived from
   `kernel-core-*.rpm`.
2. `image/Containerfile.bootc` — install the `kernel-core / kernel-modules-core /
   kernel-modules / kernel` **4k** RPMs (globs anchored on `-6.12` so they never
   catch the 64k RPMs).
3. Regenerate + **re-sign** the 4k kernel + 4k-vermagic driver `.ko` on the build
   host (**.63**), re-stage into `ARTIFACTS_DIR`, then run `build-image` → GHCR.
4. Validate on **.63** (qdrant/vLLM boot + `nvidia-smi`), then promote the digest
   to **.72 (live)** via the normal channel promotion (ADR-0005).
5. Docs/labels updated (README, `nvidia.conf`, CI comments).

## References

- Red Hat — *Building a custom RHEL kernel for NVIDIA DGX Spark*:
  <https://developers.redhat.com/articles/2026/06/23/building-custom-red-hat-enterprise-linux-kernel-nvidia-dgx-spark>
- RHEL docs — *The 64k page size kernel* (4k vs 64k, "user space is the same"):
  <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/managing_monitoring_and_updating_the_kernel/what-is-kernel-64k>
- NVIDIA forum — *Switch from 64K back to 4K kernel (Qdrant compatibility)*:
  <https://forums.developer.nvidia.com/t/how-to-switch-from-64k-page-size-back-to-4k-kernel-qdrant-compatibility-issue/364258>
- NVIDIA forum — *DGX Spark 64k kernels* ("fallback to the regular kernel"):
  <https://forums.developer.nvidia.com/t/dgx-spark-64k-kernels/355883>
- Qdrant — *jemalloc: Unsupported system page size on ARM64*:
  <https://github.com/qdrant/qdrant/issues/2474>
- See also [[ADR-0002-secure-boot-zero-touch]] and [[ADR-0003-base-and-update-model]].
