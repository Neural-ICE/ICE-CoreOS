#!/usr/bin/env bash
# Run only in the isolated RPM builder stage, never on an appliance.
set -euo pipefail
umask 022

readonly source_url=https://kojihub.stream.centos.org/kojifiles/packages/systemd/257/33.el10/data/signed/8483c65d/src/systemd-257-33.el10.src.rpm
readonly source_sha=a0ae59104843ad6a960f76d11d7e63a58406eb07b0cfda482ef0e1c45ac0ab30
readonly top=/build/rpmbuild
readonly patch=/build/input/0001-creds-pin-srk.patch
jobs="${SYSTEMD_BUILD_JOBS:-6}"
[[ "$jobs" =~ ^[1-9][0-9]?$ && "$jobs" -le 16 ]]
[[ -f /run/.containerenv || -f /.dockerenv ]] || {
  echo 'REFUSED: systemd RPM rebuild requires an isolated container' >&2
  exit 1
}
[[ ! -e "$top" ]] || { echo 'REFUSED: build directory already exists' >&2; exit 1; }
install -d /build /out
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 600 --retry 2 \
  "$source_url" -o /build/systemd.src.rpm
printf '%s  %s\n' "$source_sha" /build/systemd.src.rpm | sha256sum -c -
rpm -ivh --define "_topdir $top" /build/systemd.src.rpm
install -m 0644 "$patch" "$top/SOURCES/10000-creds-pin-srk.patch"
python3 - "$top/SPECS/systemd.spec" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
assert s.count('Release:        33%{?dist}') == 1
assert 'Patch0001:' in s
s = s.replace('Release:        33%{?dist}', 'Release:        33.ice1%{?dist}')
s = s.replace('Patch0001:', 'Patch10000: 10000-creds-pin-srk.patch\n\nPatch0001:', 1)
p.write_text(s)
PY
printf '%%_topdir %s\n' "$top" > /root/.rpmmacros
dnf -y --enablerepo=crb builddep "$top/SPECS/systemd.spec"
# Distribution-wide tests include VM-only/destructive tests. Run the credential
# unit suite below; real TPM restart/PID1 qualification is a separate release gate.
rpmbuild -ba --nocheck --noclean --define "_smp_mflags -j$jobs" "$top/SPECS/systemd.spec"
meson test -C "$top/BUILD/systemd-257/redhat-linux-build" --print-errorlogs test-creds
arch="$(rpm --eval '%{_arch}')"
for package in systemd systemd-libs systemd-pam systemd-udev; do
  file="$top/RPMS/$arch/$package-257-33.ice1.el10.$arch.rpm"
  [[ -f "$file" ]]
  install -m 0644 "$file" /out/
done
printf 'source_url=%s\nsource_sha256=%s\n' "$source_url" "$source_sha" > /out/provenance.txt
sha256sum "$patch" >> /out/provenance.txt
(cd /out && sha256sum ./*.rpm > SHA256SUMS)
