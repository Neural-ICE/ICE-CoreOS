# Runbook — validate persistent GB10 tty1 geometry

This procedure validates an already-installed candidate on a DGX Spark. It
does not publish an image, move a channel, flash media or modify the appliance.
Because production SSH is sealed, the Owner captures the tty1 view and the
diagnostic export; use the debug variant only through the approved access path.

## 1. Deterministic repository checks

Run from the ICE-CoreOS checkout:

```sh
./ci/test-gb10-console-boot.sh
shellcheck ci/test-gb10-console-boot.sh
```

During the image build, `image/Containerfile.bootc` additionally fails unless
the generated initramfs lists:

- `gsp_ga10x.bin`;
- `90-neural-ice-nvidia-drm.conf`;
- `vconsole.conf`; and
- the resolved `default8x16` console font.

## 2. Cold-boot hardware evidence

Boot the candidate normally. Do not apply an `/etc` hotfix before collecting
evidence. On tty1, capture the complete dashboard and confirm that the terminal
reports 240 columns by 67 rows. From an approved debug shell, collect:

```sh
uname -r
cat /sys/module/nvidia_drm/parameters/modeset
cat /sys/module/nvidia_drm/parameters/fbdev
cat /etc/vconsole.conf
stty -F /dev/tty1 size
systemctl --failed
systemctl status systemd-vconsole-setup.service --no-pager
journalctl -b -u systemd-vconsole-setup.service --no-pager
journalctl -b -k --no-pager | grep -E 'nvidia_drm|fbcon|simpledrm|modprobe|vconsole'
```

Expected evidence:

- `modeset` is `Y`;
- `fbdev` is `Y`;
- vconsole contains `FONT=default8x16`;
- `stty` prints `67 240` (rows, then columns);
- no failed unit and no modprobe/vconsole error;
- the kernel log shows NVIDIA DRM/fbcon taking over the console rather than
  leaving tty1 on the 800x600 simpledrm geometry.

Reboot once more and repeat the parameter, geometry and failed-unit checks.
Both cold boots must produce the same result.

## 3. Installed initramfs proof

Using the running kernel release, verify that the deployment contains the same
artifacts asserted at image-build time:

```sh
kver="$(uname -r)"
sudo lsinitrd "/usr/lib/modules/${kver}/initramfs.img" \
  | grep -E 'gsp_ga10x.bin|90-neural-ice-nvidia-drm.conf|vconsole.conf|default8x16'
```

All four artifact classes must appear. This command is diagnostic only.

## 4. One-version rollback proof

Before rollback, record `bootc status` and confirm that the previous deployment
is retained. Use the established Owner-approved rollback procedure:

```sh
sudo bootc rollback
sudo systemctl reboot
```

After reboot, confirm `bootc status` identifies the previous deployment, then
repeat:

```sh
cat /sys/module/nvidia_drm/parameters/modeset
cat /sys/module/nvidia_drm/parameters/fbdev
stty -F /dev/tty1 size
systemctl --failed
nvidia-smi
```

The rollback gate is bootability, GPU health and absence of failed boot units.
The previous image may retain `default8x16` through `/etc` merge semantics; that
font is compatible with both retained driver generations. Do not delete either
deployment or artifact generation while qualification is open.
