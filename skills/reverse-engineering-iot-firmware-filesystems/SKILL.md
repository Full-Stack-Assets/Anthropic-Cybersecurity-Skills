---
name: reverse-engineering-iot-firmware-filesystems
description: Triages an extracted IoT firmware root filesystem for security weaknesses including hardcoded credentials, private keys and certificates, backdoor accounts, weak password hashes in /etc/passwd and /etc/shadow, setuid binaries, vulnerable service configurations, and exposed telnet/ftp daemons. Combines firmwalker-style content sweeps, hash-strength assessment, and binary reverse engineering with Ghidra to map the device attack surface from a mounted filesystem.
domain: cybersecurity
subdomain: firmware-analysis
tags:
- firmware
- iot-security
- filesystem-analysis
- hardcoded-credentials
- firmwalker
- reverse-engineering
- private-keys
- backdoor-accounts
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- PR.AA-01
- DE.CM-01
- ID.AM-08
mitre_attack:
- T1552
- T1078
- T1505
---
# Reverse Engineering IoT Firmware Filesystems

> **Authorized Use Only:** Only analyze firmware filesystems you own or are explicitly authorized in writing to test. Firmware contents are typically copyrighted; respect licensing and the DMCA. Treat any credentials, keys, or certificates you recover as sensitive material and handle them under your engagement's data-handling rules.

## Overview

After a firmware image is extracted and its root filesystem is mounted (via binwalk, `unsquashfs`, `jefferson`, etc.), the highest-value security work is **static triage of the filesystem** — the place where vendors most often leave the keys to the kingdom. Embedded Linux firmware routinely ships with hardcoded service passwords, baked-in SSH/TLS **private keys**, vendor "support" **backdoor accounts**, world-readable secrets in config files, and weak or absent password hashes in `/etc/passwd` and `/etc/shadow`. Recovering these is the embedded analogue of MITRE ATT&CK **T1552 — Unsecured Credentials** (credentials in files and config); the accounts and keys recovered enable **T1078 — Valid Accounts**, and web/CGI components found in the filesystem are the staging ground for **T1505 — Server Software Component** backdoors.

The triage proceeds from the most universal weaknesses outward. First the authentication store: `/etc/passwd` and `/etc/shadow` reveal accounts, login shells, and the **hash algorithm** of each password — DES (`$` absent, 13-char crypt), MD5 (`$1$`), and the still-common weak choices versus modern `$5$`/`$6$`/`$y$`. A `root` account with a populated, crackable hash (or, worse, an empty password field) is an immediate finding; cracking it with `john` or `hashcat` confirms exploitability. Next, secrets at rest: PEM/DER private keys (`-----BEGIN ... PRIVATE KEY-----`), `.key`/`.pem`/`.p12` files, and credentials embedded in config files, init scripts, and web roots. Then the binary attack surface: **setuid/setgid** binaries (privilege-escalation targets), and the network daemons enabled at boot (telnetd, ftpd, dropbear) whose presence and configuration define remote exposure.

Tooling combines breadth and depth. **firmwalker** is the de-facto first-pass scanner that greps a mounted filesystem for the well-known indicators (password files, key files, banners, `etc/ssl`, dropbear/openssl binaries, common backdoor strings). Manual `grep`/`find` sweeps confirm and extend it. For the binaries themselves — a vendor `httpd`, a CGI handler, a key-derivation routine — **Ghidra** decompiles the code to locate command-injection sinks, hardcoded keys, and authentication-bypass logic. The output is an attack-surface map: who can log in, with what secret, over which service, and which binaries elevate or accept untrusted input.

## When to Use

- You have a mounted/extracted firmware root filesystem and need a security triage of its contents.
- Searching for hardcoded credentials, private keys, certificates, or backdoor accounts.
- Assessing the strength of password hashes in `/etc/passwd` and `/etc/shadow`.
- Enumerating setuid binaries and remotely exposed services as escalation/entry points.
- Reverse engineering a specific vendor binary (httpd/CGI) for injection or auth-bypass flaws.
- Producing an attack-surface and findings report for an authorized IoT assessment.

## Prerequisites

- A mounted/extracted root filesystem (from `binwalk -Me`, `unsquashfs`, `jefferson`, etc.).
- Tooling:
  ```bash
  git clone https://github.com/craigz28/firmwalker
  sudo apt install john hashcat openssl
  # Ghidra for binary RE:
  # download from https://ghidra-sre.org/ and run ./ghidraRun
  ```
- `john`/`hashcat` with a wordlist (e.g. `rockyou.txt`) for hash cracking.
- Python 3.8+ (the companion scanner is pure stdlib).
- Written authorization to analyze the firmware and handle recovered secrets.

## Objectives

- Inventory accounts and assess password-hash strength in `/etc/passwd` and `/etc/shadow`.
- Locate hardcoded credentials in configs, init scripts, and web roots.
- Find private keys, certificates, and other secrets at rest.
- Enumerate setuid/setgid binaries and remotely exposed services (telnet/ftp/ssh).
- Identify and (where authorized) reverse engineer vulnerable vendor binaries.
- Produce a prioritized attack-surface map and remediation recommendations.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1552 | Unsecured Credentials | Credential Access | Hardcoded passwords, private keys, and secrets in firmware files/configs. |
| T1078 | Valid Accounts | Initial Access / Privilege Escalation | Reusing recovered/backdoor accounts and keys to authenticate. |
| T1505 | Server Software Component | Persistence | Backdoor or vulnerable web/CGI components in the firmware web stack. |

## Workflow

### 1. First-pass sweep with firmwalker

Run firmwalker over the extracted root to get a fast indicator list, then read its report.

```bash
./firmwalker.sh /path/to/extracted/squashfs-root firmwalker_report.txt
cat firmwalker_report.txt
# firmwalker reports: passwd/shadow, *.pem/*.key, etc/ssl, dropbear/openssl/ssh binaries,
# common backdoor strings, web roots, and version/banner files.
```

### 2. Inventory accounts and grade password hashes

Parse `/etc/passwd` and `/etc/shadow`; flag empty passwords, login shells on system accounts, and weak hash algorithms.

```bash
python3 scripts/agent.py scan --rootfs /path/to/extracted/squashfs-root
# Manual cross-check:
cat /path/to/extracted/squashfs-root/etc/passwd
cat /path/to/extracted/squashfs-root/etc/shadow
# Hash algorithm tells: no '$'=DES, $1$=MD5(crypt) [weak], $5$=SHA256, $6$=SHA512, $y$=yescrypt
```

### 3. Crack recovered hashes to prove exploitability

Combine passwd+shadow and run john/hashcat. A cracked root hash is a confirmed finding.

```bash
unshadow etc/passwd etc/shadow > combined.txt        # from the john suite
john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt
john --show combined.txt
# hashcat equivalent for $6$ (mode 1800) / $1$ (mode 500):
hashcat -m 1800 -a 0 shadow_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 4. Hunt secrets at rest: keys, certs, and credentials

Find private keys/certs and credentials in configs and scripts.

```bash
python3 scripts/agent.py scan --rootfs /path/to/extracted/squashfs-root --secrets
# Manual sweeps:
grep -rIl -- "-----BEGIN .*PRIVATE KEY-----" /path/to/extracted/squashfs-root
find /path/to/extracted/squashfs-root \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.crt" \)
grep -rniE "password|passwd|api[_-]?key|secret|token" \
  /path/to/extracted/squashfs-root/etc /path/to/extracted/squashfs-root/www
# Inspect a recovered cert/key:
openssl x509 -in server.crt -noout -text | head -20
openssl rsa  -in server.key -noout -check
```

### 5. Enumerate setuid binaries and exposed services

Map privilege-escalation and remote-entry surface.

```bash
python3 scripts/agent.py scan --rootfs /path/to/extracted/squashfs-root --suid --services
# Manual:
find /path/to/extracted/squashfs-root -type f -perm -4000 -exec ls -l {} \;   # setuid
grep -RniE "telnetd|ftpd|dropbear|sshd" /path/to/extracted/squashfs-root/etc
cat /path/to/extracted/squashfs-root/etc/inetd.conf 2>/dev/null
```

### 6. Reverse engineer suspect binaries in Ghidra

Decompile a vendor binary (e.g. httpd or a CGI handler) to find command-injection sinks, hardcoded keys, or auth bypasses.

```bash
# Headless Ghidra triage of a single binary:
$GHIDRA_HOME/support/analyzeHeadless /tmp/proj iotproj \
  -import /path/to/extracted/squashfs-root/usr/sbin/httpd \
  -postScript GhidraStringsScript.java
# In the Ghidra GUI, search Defined Strings for "system", "popen", "exec",
# default passwords, and "/bin/sh"; follow xrefs from those to user-controlled input.
```

## Tools and Resources

| Resource | Link |
|----------|------|
| firmwalker | https://github.com/craigz28/firmwalker |
| John the Ripper | https://www.openwall.com/john/ |
| hashcat | https://hashcat.net/hashcat/ |
| Ghidra | https://ghidra-sre.org/ |
| OpenSSL | https://www.openssl.org/ |
| OWASP Firmware Security Testing Methodology (FSTM) | https://github.com/scriptingxss/owasp-fstm |
| OWASP IoT Top 10 | https://owasp.org/www-project-internet-of-things/ |

## Password Hash Reference

| `/etc/shadow` prefix | Algorithm | Strength |
|----------------------|-----------|----------|
| (no `$`, 13 chars) | DES crypt | Very weak (trivially cracked). |
| `$1$` | MD5 crypt | Weak. |
| `$2a$`/`$2y$` | bcrypt | Strong. |
| `$5$` | SHA-256 crypt | Moderate. |
| `$6$` | SHA-512 crypt | Moderate–strong. |
| `$y$` | yescrypt | Strong (modern default). |
| empty field (`user::`) | no password | Critical — passwordless login. |

| Indicator file | Why it matters |
|----------------|----------------|
| `etc/passwd` / `etc/shadow` | Accounts, shells, hash strength, backdoor users. |
| `*.pem` / `*.key` / `*.p12` | Private keys / certs usable to impersonate or decrypt. |
| `etc/dropbear/` / `etc/ssh/` | Host keys; shared keys across a product line = mass risk. |
| `www/` / `cgi-bin/` | Web attack surface; injection and auth-bypass code. |
| `etc/inetd.conf` / `etc/init.d/` | Which services auto-start and listen. |

## Validation Criteria

- [ ] Accounts inventoried; password-hash algorithm graded for each user.
- [ ] Empty-password and backdoor accounts identified.
- [ ] Crackable hashes run through john/hashcat; results recorded.
- [ ] Private keys, certificates, and hardcoded credentials located.
- [ ] setuid/setgid binaries enumerated.
- [ ] Remotely exposed services (telnet/ftp/ssh) identified with their configs.
- [ ] At least one suspect binary triaged in Ghidra for injection/auth-bypass.
- [ ] Prioritized attack-surface map and remediation recommendations produced.
