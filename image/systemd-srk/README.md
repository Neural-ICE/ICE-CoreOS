# TPM credentials after the owner ceremony

CentOS systemd 257 credentials recreate a primary key through the owner
hierarchy. Neural ICE deliberately destroys owner authorization at first boot,
so that path cannot seal or unseal application credentials afterward.

`0001-creds-pin-srk.patch` backports upstream systemd commit
`70cfb11d4bf6175a3548520025e6d6b25d55ff17` to CentOS Stream `257-33.el10`.
It keeps the distribution's explicit format predicates and TPM API signatures,
uses upstream's six format identifiers, retains legacy readers, and rejects an
empty pinned SRK field. The existing persistent SRK parents the sealed key;
its serialized identity also authenticates the TPM session when unsealing.
There is no ownerAuth recovery, new authorization key, or host-only fallback
in the application's explicit `--with-key=tpm2` path.

The source RPM is pinned by SHA-256 and rebuilt as `257-33.ice1.el10`.
The image installs writer, shared reader library, PID1 package, PAM and udev
from the same build. Never replace just the `systemd-creds` executable on a
running appliance. RPMs remain generated build artifacts, not repository files.

## Compatibility and deployment gate

New credentials have a new format that unpatched 257 readers refuse. Existing
credentials retain their old semantics; an old TPM credential does not become
usable after owner lock merely by updating its reader.

Before enabling new application sealing, deploy and qualify a compatibility
image containing this reader and the application readers for every newly
persisted format, including the PKI child-key format. Keep application writers
inactive while qualifying that image. Retain the booted compatibility deployment
as recovery before activating the application fixes. Both retained and candidate
deployments must read a new test credential and the PKI state after an ordinary
reboot. An old bootable image whose systemd or application reader rejects the
persisted state is not a recovery target.

Required qualification covers a fresh emulated TPM, both old and new format
roundtrips before owner lock, reproduction of the stock writer's failure after
owner lock, new sealing after lock, TPM restart, wrong name, altered/truncated
headers, different TPM, and `LoadCredentialEncrypted=` through PID1. Use only
synthetic test secrets and task-owned emulated TPM state. The RPM build runs
`test-creds`; it cannot prove the VM and physical lifecycle gates by itself.

## Reproducible SWTPM matrix

`test-credentials.py` exercises all six explicit pinned-SRK formats. The three
public-key modes use `--with-key=*-with-public-key`; merely passing
`--tpm2-public-key=` to a non-public-key mode does not select that format. The
test verifies each 128-bit format ID, locks only the first fresh emulator's
synthetic owner hierarchy, and covers wrong name, scoped UID, PCR-policy
signature, malformed public-key/SRK headers, authentication tag, stock reader,
and a second TPM. Its `resume` phase refuses a different machine-id, socket, or
binary digest.

Run this only in caller-owned scratch. Never point either TCTI at a device node
or an existing emulator state. The example assumes the host has `swtpm` and
`swtpm_ioctl`; the final RPM-build image keeps the candidate binaries under
`/build/rpmbuild`:

```bash
set -euo pipefail
scratch=/home/user/ni-build/p0-usb-20260903/systemd-srk-codex-20260905
for name in matrix-c matrix-d; do
  test ! -e "$scratch/$name" && test ! -L "$scratch/$name"
  install -d -m 0700 "$scratch/$name/state"
  swtpm socket --tpm2 --tpmstate "dir=$scratch/$name/state" \
    --ctrl "type=unixio,path=$scratch/$name/tpm.sock.ctrl" \
    --server "type=unixio,path=$scratch/$name/tpm.sock" \
    --flags not-need-init,startup-clear --pid "file=$scratch/$name/pid" --daemon
done
if test -e "$scratch/machine-id" || test -L "$scratch/machine-id"; then
  test -f "$scratch/machine-id" && test ! -L "$scratch/machine-id"
else
  systemd-id128 new >"$scratch/machine-id"
fi
chmod 0600 "$scratch/machine-id"

run_matrix() {
  phase="$1"
  sudo podman run --rm --network=none --security-opt label=disable \
    --mount "type=bind,src=$scratch,dst=/work" \
    --mount "type=bind,src=$scratch/machine-id,dst=/etc/machine-id,ro=true" \
    localhost/ni-systemd-srk-rpms:20260905 sh -eu -c '
      getent passwd 1000 >/dev/null || useradd --uid 1000 --no-create-home srk-test
      exec python3 /work/test-credentials.py "$@"
    ' sh "$phase" \
      --creds /build/rpmbuild/BUILD/systemd-257/redhat-linux-build/systemd-creds \
      --stock-creds /usr/bin/systemd-creds \
      --measure /build/rpmbuild/BUILD/systemd-257/redhat-linux-build/systemd-measure \
      --tcti swtpm:path=/work/matrix-c/tpm.sock \
      --other-tcti swtpm:path=/work/matrix-d/tpm.sock \
      --work /work/matrix-evidence-fresh
}

run_matrix create
for name in matrix-c matrix-d; do
  old_pid="$(cat "$scratch/$name/pid")"
  swtpm_ioctl --unix "$scratch/$name/tpm.sock.ctrl" -s
  for _ in $(seq 1 100); do
    kill -0 "$old_pid" 2>/dev/null || break
    sleep 0.1
  done
  ! kill -0 "$old_pid" 2>/dev/null
  swtpm socket --tpm2 --tpmstate "dir=$scratch/$name/state" \
    --ctrl "type=unixio,path=$scratch/$name/tpm.sock.ctrl" \
    --server "type=unixio,path=$scratch/$name/tpm.sock" \
    --flags not-need-init,startup-clear --pid "file=$scratch/$name/pid" --daemon
  test "$(cat "$scratch/$name/pid")" != "$old_pid"
done
run_matrix resume
for name in matrix-c matrix-d; do
  pid="$(cat "$scratch/$name/pid")"
  swtpm_ioctl --unix "$scratch/$name/tpm.sock.ctrl" -s
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  ! kill -0 "$pid" 2>/dev/null
done
```

Retain `created.json` and `resumed.json` with the command log. They identify the
machine-id, both SWTPM sockets, harness, candidate and stock binary SHA-256
values, all six format IDs, and the negative-case counts without recording
credential plaintext or owner authorization. `auto`, `auto-initrd`, PID1,
boot/reboot, and physical TPM checks remain separate release gates.
