# IoT Firmware Filesystem Triage — Tool & Command Reference

## firmwalker

| Command | Purpose |
|---------|---------|
| `./firmwalker.sh <rootfs> <report.txt>` | Sweep a mounted rootfs for known indicators; write a report. |
| edit `data/*` lists | Customize which strings/files/binaries firmwalker hunts for. |

## Account / hash analysis

| Command | Purpose |
|---------|---------|
| `cat <rootfs>/etc/passwd` | Accounts, UIDs, login shells. |
| `cat <rootfs>/etc/shadow` | Password hashes (algorithm prefix matters). |
| `unshadow etc/passwd etc/shadow > combined.txt` | Merge passwd+shadow for john. |
| `john --wordlist=rockyou.txt combined.txt` | Crack with a wordlist. |
| `john --show combined.txt` | Show cracked results. |
| `hashcat -m 1800 hashes.txt rockyou.txt` | Crack `$6$` SHA-512 (mode 1800; `$1$`=500, `$5$`=7400, bcrypt=3200, yescrypt=29800). |

## Secret / key discovery

| Command | Purpose |
|---------|---------|
| `grep -rIl -- "-----BEGIN .*PRIVATE KEY-----" <rootfs>` | Find PEM private keys. |
| `find <rootfs> \( -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.crt' \)` | Find key/cert files. |
| `openssl x509 -in cert.crt -noout -text` | Inspect a certificate. |
| `openssl rsa -in key.pem -noout -check` | Validate an RSA private key. |
| `grep -rniE "password|api[_-]?key|secret|token" <rootfs>/etc <rootfs>/www` | Credential hunt in configs/web root. |

## Privilege / service surface

| Command | Purpose |
|---------|---------|
| `find <rootfs> -type f -perm -4000` | List setuid binaries. |
| `find <rootfs> -type f -perm -2000` | List setgid binaries. |
| `grep -RniE "telnetd|ftpd|dropbear|sshd" <rootfs>/etc` | Find exposed-service config. |
| `cat <rootfs>/etc/inetd.conf` | Inetd-launched services. |

## Ghidra (binary RE)

| Command | Purpose |
|---------|---------|
| `$GHIDRA_HOME/support/analyzeHeadless <proj_dir> <proj> -import <binary>` | Headless import + auto-analysis. |
| `... -postScript <Script.java>` | Run an analysis script after import. |
| GUI: Search > For Strings | Find `system`, `popen`, `/bin/sh`, default creds. |
| GUI: References > Show References To | Trace xrefs from a sink to user input. |

## Companion script (`scripts/agent.py`)

```
python3 scripts/agent.py scan --rootfs <rootfs>
python3 scripts/agent.py scan --rootfs <rootfs> --secrets --suid --services
```

| Flag | Effect |
|------|--------|
| (default) | Parse passwd/shadow; grade hashes; flag empty passwords/backdoor accounts. |
| `--secrets` | Walk the tree for private keys, certs, and hardcoded credentials. |
| `--suid` | Report setuid/setgid binaries (by stat mode bits). |
| `--services` | Report references to telnet/ftp/ssh daemons in config files. |

## External References

- crypt(3) hash formats: https://man7.org/linux/man-pages/man3/crypt.3.html
- hashcat modes: https://hashcat.net/wiki/doku.php?id=example_hashes
- Ghidra docs: https://ghidra-sre.org/CheatSheet.html
