# Firmware Emulation — Tool & Command Reference

## QEMU user-mode

| Command | Purpose |
|---------|---------|
| `qemu-mipsel-static /bin/busybox` | Run one little-endian MIPS binary on the host. |
| `cp $(which qemu-arm-static) $ROOT/usr/bin/ && chroot $ROOT /usr/bin/qemu-arm-static <bin>` | chroot into a foreign rootfs. |
| `qemu-<arch>-static -g 1234 ./bin` | Run with a gdb stub on port 1234 for debugging. |
| `update-binfmts --display` | Verify binfmt_misc handlers are registered. |

User binaries: `qemu-arm-static`, `qemu-armeb-static`, `qemu-mips-static`, `qemu-mipsel-static`, `qemu-aarch64-static`, `qemu-ppc-static`.

## QEMU full-system

| Flag | Purpose |
|------|---------|
| `-M <machine>` | Machine model (e.g. `malta` for MIPS, `virt` for ARM). |
| `-kernel <vmlinux>` | Kernel image to boot. |
| `-dtb <file.dtb>` | Device tree blob (ARM/embedded). |
| `-drive file=rootfs.ext2,format=raw` | Attach the root filesystem image. |
| `-append "root=/dev/sda1 console=ttyS0"` | Kernel command line. |
| `-netdev tap,id=n0,ifname=tap0,script=no,downscript=no` | TAP networking. |
| `-device pcnet,netdev=n0` / `-device virtio-net,netdev=n0` | Virtual NIC. |
| `-nographic` | Serial console only. |
| `-s -S` | gdb stub on :1234, halt at start. |

## FirmAE

| Command | Purpose |
|---------|---------|
| `./download.sh && ./install.sh` | One-time setup of FirmAE and its kernels/images. |
| `sudo ./run.sh -c <brand> <fw.bin>` | Check mode: does it emulate + get network? |
| `sudo ./run.sh -r <brand> <fw.bin>` | Run mode: boot to an interactive emulated device. |
| `sudo ./run.sh -a <brand> <fw.bin>` | Analyze mode: emulate then run built-in checks. |
| `sudo ./run.sh -d <brand> <fw.bin>` | Debug mode: bring up with gdb support. |

## Firmadyne (manual pipeline)

| Step | Command |
|------|---------|
| Extract | `./sources/extractor/extractor.py -b <brand> -sql 127.0.0.1 <fw.bin> images` |
| Identify arch | `./scripts/getArch.sh ./images/1.tar.gz` |
| Build image | `./scripts/makeImage.sh 1` |
| Infer network | `./scripts/inferNetwork.sh 1` |
| Run | `./scratch/1/run.sh` |

## Triage / fuzzing

| Tool | Command | Purpose |
|------|---------|---------|
| nmap | `nmap -sV -p- <ip>` | Enumerate emulated services. |
| ffuf | `ffuf -u http://<ip>/FUZZ -w common.txt` | Content/parameter fuzzing. |
| curl | `curl -s http://<ip>/ | head` | Manual request inspection. |
| gdb-multiarch | `gdb-multiarch -ex 'target remote :1234' ./bin` | Attach to QEMU gdb stub. |

## Companion script (`scripts/agent.py`)

```
python3 scripts/agent.py inspect  --rootfs ./_fw.extracted/squashfs-root
python3 scripts/agent.py services --rootfs ./_fw.extracted/squashfs-root
```

| Subcommand | Key args | Output |
|------------|----------|--------|
| `inspect` | `--rootfs` | Arch/endianness from busybox ELF + suggested qemu invocation. |
| `services` | `--rootfs` | Network-facing init/inetd services found in the rootfs. |

## External References

- QEMU documentation: https://www.qemu.org/docs/master/
- FirmAE wiki: https://github.com/pr0v3rbs/FirmAE/wiki
- ffuf wiki: https://github.com/ffuf/ffuf/wiki
