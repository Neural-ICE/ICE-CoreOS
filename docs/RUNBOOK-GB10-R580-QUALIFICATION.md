# Runbook — GB10 R580.159.03 experimental qualification

This runbook produces and qualifies an experimental ICE-CoreOS driver
generation. It does not authorize stable promotion or any Secure Boot policy
change.

## 1. Prepare the official driver bundle on the Spark runner

Keep every historical bundle and generation for rollback. Download into a
versioned location and verify NVIDIA's adjacent checksum:

```sh
driver_version=580.159.03
download_dir="$HOME/nvidia-userspace-build/downloads"
runfile="NVIDIA-Linux-aarch64-${driver_version}.run"
install -d -m 0755 "$download_dir"
curl -fL "https://download.nvidia.com/XFree86/Linux-aarch64/${driver_version}/${runfile}" \
  -o "$download_dir/$runfile"
curl -fL "https://download.nvidia.com/XFree86/Linux-aarch64/${driver_version}/${runfile}.sha256sum" \
  -o "$download_dir/${runfile}.sha256sum"
(cd "$download_dir" && sha256sum -c "${runfile}.sha256sum")
chmod 0755 "$download_dir/$runfile"
(cd "$HOME/nvidia-userspace-build" && "$download_dir/$runfile" --extract-only)
test -d "$HOME/nvidia-userspace-build/NVIDIA-Linux-aarch64-${driver_version}/kernel-open"
```

Never replace `$HOME/neural-ice/image/nvidia-userspace`; it is a legacy mutable
path and is intentionally no longer consumed by the workflow.

## 2. Dispatch the immutable candidate build

The default branch workflow accepts exact immutable inputs:

```sh
gh api repos/Neural-ICE/ICE-CoreOS/dispatches \
  -f event_type=build-coreos-kernel \
  -F 'client_payload[kernel_ref]=fa4faa0227e00c2291e47b120e71c7aed0fe27b7' \
  -F 'client_payload[nvidia_driver_version]=580.159.03'
```

Record the workflow run ID, candidate generation ID, kernel revision, NVIDIA
version and manifest hash. The workflow must not move `current`.

## 3. Finalize through the existing Owner gate

Sign the candidate's exact vmlinuz and reuse the existing reviewed lab trust
policy. Do not modify keys, hashes or signer mapping:

```sh
ARTIFACTS_ROOT="$HOME/neural-ice/artifacts" \
SIGNEDBOOT_SRC=/path/to/signed-boot-for-this-candidate \
SIGNED_BOOT_TRUST_POLICY_BIN="$PWD/secureboot/trust-policies/neural-ice-secureboot-lab-v1" \
SIGNED_BOOT_TRUST_POLICY_ID=neural-ice-secureboot-lab-v1 \
  ./ci/artifact-generation.sh finalize <candidate-generation-id>
```

## 4. Build beta and verify on the appliance

After the normal signed Fabric train installs the retained beta deployment:

```sh
getconf PAGESIZE
uname -r
modinfo -F version nvidia
nvidia-smi
sudo nvidia-ctk cdi list
journalctl -b -k --no-pager | grep -E 'NVRM|GSP|nvidia'
```

Expected: 4096-byte pages, R580.159.03 everywhere, GSP initialized, no module
signature or version mismatch.

Exercise the real product path:

1. thin client upload;
2. `/v1/kb/documents`;
3. 10-page Paddle batch;
4. RAG embedding/indexing;
5. retrieval in chat;
6. a larger PDF split into 10-page batches;
7. Case Law search and detail tool;
8. repeated inference/free cycles while observing host memory.

Do not use `drop_caches` during the measurement. Record per-phase durations,
GPU utilization, memory before/after and service restarts.

## 5. Reboot and rollback proof

Reboot once, repeat GPU/CDI/health and one ingestion. Then prove the retained
rollback path without deleting either deployment:

```sh
sudo bootc status
sudo bootc rollback
sudo systemctl reboot
```

Re-run the same boot/GPU checks on R595 before declaring the rollback proven.

## Grounded incident lesson

`[origine: incident live .72 2026-07-29 / CaseLaw 08:51:34–08:53:50 / THP A/B]`
A global two-minute `drop_caches=3` mitigation can turn a healthy hot local
corpus into repeated 60-second tool timeouts; driver, userspace and GSP firmware
must be staged from one exact versioned bundle, and UMA release must be
qualified without destructive global cache eviction. `(vérifié-le 2026-07-29)`
