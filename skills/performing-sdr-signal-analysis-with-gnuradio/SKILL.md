---
name: performing-sdr-signal-analysis-with-gnuradio
description: Perform software-defined-radio capture and signal analysis for authorized RF security assessments using RTL-SDR and HackRF, run spectrum surveys, demodulate and characterize sub-GHz device signals, and assess replay risk of fixed-code remotes while respecting spectrum and transmission law.
domain: cybersecurity
subdomain: wireless-security
tags:
- wireless-security
- sdr
- gnuradio
- rtl-sdr
- hackrf
- spectrum-analysis
- sub-ghz
- replay-attack
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1040
- T1200
- T1557
- T1059
---
# Performing SDR Signal Analysis with GNU Radio

> **Authorized Use Only:** Receiving across the radio spectrum and especially *transmitting* are tightly regulated. Capture only RF you are authorized to assess, analyze only devices you own or are explicitly permitted to test, and never transmit (including replaying a captured signal) on licensed or shared spectrum without authorization and the appropriate license. Intercepting third-party communications and unauthorized transmission are offences under telecommunications and wiretap law in virtually every jurisdiction.

## Overview

A **software-defined radio (SDR)** moves signal processing from fixed hardware into software, letting a single device tune across a wide frequency range and demodulate arbitrary protocols. For security assessments this means you can survey the spectrum your environment actually uses, capture and characterize the signals of sub-GHz devices (remote controls, garage/gate openers, wireless sensors, TPMS, some IoT links on 315/433/868/915 MHz), and evaluate their resistance to capture-and-replay. Passive capture of these signals is **Network Sniffing (T1040)** at the RF layer; an SDR or recorded signal used to drive a device is **Hardware Additions (T1200)**; relaying or replaying a captured transmission to impersonate a legitimate transmitter is **Adversary-in-the-Middle (T1557)**; and the GNU Radio Companion flowgraphs and helper scripts that orchestrate capture and demodulation are **Command and Scripting Interpreter (T1059)** automation.

The workflow follows the classic RF-analysis funnel. First a **spectrum survey** (e.g. `rtl_power` sweeping a band into a CSV waterfall) finds *where* energy is — which frequencies a target environment or device actually transmits on. Then a **narrowband capture** at the identified center frequency records IQ samples while the device operates. **Visual analysis** in `inspectrum` or **Universal Radio Hacker (URH)** reveals the modulation (OOK/ASK, FSK, etc.), symbol rate, and frame structure, after which the bits are demodulated and decoded. The crucial security question for many sub-GHz devices is whether the protocol uses a **fixed code** (the same bits every time — trivially replayable) or a **rolling code** (a changing counter/crypto, resistant to naive replay, though vulnerable to specialized attacks like RollJam). Identifying fixed-code or weak-rolling-code devices, and the replay risk they carry, is the core deliverable.

This skill builds that capability with GNU Radio and the RTL-SDR/HackRF ecosystem, then maps findings to a risk picture and remediation (move to authenticated/rolling-code or encrypted links). It emphasizes legal, receive-first methodology and aligns with NIST CSF ID.RA-01 (vulnerability identification) and DE.CM-01 (RF/environment monitoring). The companion script ranks active signal peaks from an `rtl_power` sweep so you can quickly prioritize bands of interest.

## When to Use

- When inventorying the RF emitters in a facility or around a device under test (spectrum survey).
- When assessing sub-GHz remotes, sensors, gate/garage openers, or IoT links for replay/capture risk.
- When determining whether a wireless device uses fixed vs. rolling codes before deeper analysis.
- When characterizing an unknown signal's frequency, modulation, and symbol rate during a hardware/IoT assessment.
- When validating that a remediated device moved to an authenticated/rolling-code or encrypted protocol.
- When building reproducible GNU Radio capture/demod flowgraphs for an engagement.

## Prerequisites

- An SDR: **RTL-SDR** (RTL2832U, ~24 MHz–1.7 GHz, receive-only) for survey/capture, and/or a **HackRF One** (1 MHz–6 GHz, half-duplex TX/RX) for wider coverage. ANT500/appropriate antennas.
- A Linux host with the SDR toolchain:
  ```bash
  sudo apt update
  sudo apt install -y gnuradio gqrx-sdr rtl-sdr hackrf inspectrum
  # Universal Radio Hacker (URH) for protocol reverse-engineering
  pip install urh
  # quick device check
  rtl_test -t          # confirm RTL-SDR is detected
  ```
- For analysis, Python with numpy is helpful for IQ math (the companion script is stdlib-only).
- Knowledge of your local spectrum allocations and a documented authorization for any capture/transmission.

## Objectives

- Run a spectrum survey across a target band and identify active frequencies/peaks.
- Capture narrowband IQ at an identified center frequency while a device operates.
- Visually characterize modulation, symbol rate, and frame structure in inspectrum/URH.
- Demodulate and decode the payload bits with a GNU Radio flowgraph.
- Classify fixed-code vs. rolling-code behavior and assess replay risk.
- Produce a ranked list of signals of interest and a remediation recommendation.

## MITRE ATT&CK Mapping

| ID | Name | Tactic | Where it shows up |
|----|------|--------|-------------------|
| T1040 | Network Sniffing | Discovery / Credential Access | Passive RF capture of device transmissions (spectrum survey, IQ recording) |
| T1200 | Hardware Additions | Initial Access | An SDR/recorded signal used as a transmitter against a target device |
| T1557 | Adversary-in-the-Middle | Credential Access / Collection | Replay/relay of a captured fixed-code transmission to impersonate a remote |
| T1059 | Command and Scripting Interpreter | Execution | GNU Radio flowgraphs / Python scripts orchestrating capture and demodulation |

## Workflow

### 1. Run a spectrum survey
Sweep the band(s) of interest to find where energy lives. `rtl_power` produces a CSV (frequency bins × time) you can render as a waterfall or feed to the companion script to rank peaks.

```bash
# Sweep 300-450 MHz in 5 kHz bins, 10s integration, for ~2 minutes -> CSV
rtl_power -f 300M:450M:5k -i 10 -e 120 -g 40 survey_300_450.csv
# Rank the active peaks/bands of interest from the sweep:
python3 scripts/agent.py peaks --csv survey_300_450.csv --top 15 --json peaks.json
```

### 2. Confirm visually in gqrx
Tune a real-time receiver to the candidate frequency and watch the waterfall while operating the target device, so you can see the burst and confirm the exact center frequency and bandwidth before recording.

```bash
gqrx          # set device to rtl=0 or hackrf, tune to e.g. 433.92 MHz, observe burst
# Note the precise center freq and occupied bandwidth from the live waterfall.
```

### 3. Capture narrowband IQ while the device transmits
Record raw IQ samples centered on the signal at a sample rate comfortably wider than the occupied bandwidth. Trigger the device (e.g. press the remote) during the capture window.

```bash
# RTL-SDR: 2.048 Msps centered at 433.92 MHz, ~10 seconds of IQ
rtl_sdr -f 433920000 -s 2048000 -g 40 -n 20480000 capture_43392.iq
# HackRF equivalent (wider tuning range):
hackrf_transfer -r capture_43392.iq -f 433920000 -s 8000000 -l 32 -g 40
```

### 4. Characterize modulation and symbol rate
Load the IQ into inspectrum or URH to read off the modulation (OOK/ASK vs FSK), the symbol/baud rate, and the frame structure (preamble, payload, repeats).

```bash
# Visual: open the IQ, measure symbol period and modulation
inspectrum -r 2048000 capture_43392.iq
# URH: auto-detect modulation, demodulate to bits, diff repeated presses
urh           # File > Open capture_43392.iq ; use the interpretation/analysis tabs
```

### 5. Demodulate and decode with GNU Radio
Build a flowgraph (File Source → resampler → quadrature/AM demod → binary slicer → file/print) to recover the bitstream programmatically and capture multiple presses for comparison.

```python
# Minimal GNU Radio OOK/AM demod sketch (run inside a gnuradio top_block)
from gnuradio import gr, blocks, analog, filter
# src = blocks.file_source(gr.sizeof_gr_complex, "capture_43392.iq", False)
# mag = blocks.complex_to_mag()           # AM/OOK envelope
# slc = digital.binary_slicer_fb()        # bits
# snk = blocks.file_sink(gr.sizeof_char, "bits.bin")
# ...connect and run(); then byte-align and inspect the frame.
# In practice, prototype this in GNU Radio Companion (gnuradio-companion).
```

### 6. Classify replay risk and recommend remediation
Compare the decoded payload across several transmissions. Identical payloads each press = **fixed code** (high replay risk). Changing counter/crypto each press = **rolling code** (replay-resistant, but note RollJam-class attacks). Record the verdict and remediation.

```bash
# Compare decoded frames from N presses (identical => fixed code => replayable)
python3 scripts/agent.py replay --frames frames.txt
#  -> reports fixed vs rolling and an estimated replay-risk rating
```

## Tools and Resources

| Resource | Link |
|----------|------|
| GNU Radio | https://www.gnuradio.org/ |
| RTL-SDR (rtl_power / rtl_sdr / rtl_test) | https://osmocom.org/projects/rtl-sdr/wiki |
| HackRF (Great Scott Gadgets) | https://greatscottgadgets.com/hackrf/ |
| gqrx receiver | https://gqrx.dk/ |
| inspectrum | https://github.com/miek/inspectrum |
| Universal Radio Hacker (URH) | https://github.com/jopohl/urh |
| rtl_433 (sub-GHz device decoder) | https://github.com/merbanan/rtl_433 |
| NTIA US frequency allocation chart | https://www.ntia.gov/page/2011/united-states-frequency-allocation-chart |

## Signal Analysis Cheat-Sheet

| Stage | Tool / command | Output |
|-------|----------------|--------|
| Spectrum survey | `rtl_power -f a:b:bin` | CSV waterfall → active frequencies |
| Live confirm | `gqrx` | Visual burst, exact center freq/BW |
| IQ capture | `rtl_sdr` / `hackrf_transfer -r` | Raw IQ file |
| Modulation/baud | `inspectrum`, `urh` | OOK/FSK, symbol rate, frame |
| Demodulation | GNU Radio flowgraph | Bitstream |
| Known devices | `rtl_433 -A` | Decoded device telemetry |
| Replay verdict | compare frames | Fixed vs rolling code |

## Replay-Risk Classification

| Behavior across presses | Code type | Replay risk | Recommendation |
|-------------------------|-----------|-------------|----------------|
| Identical payload each press | Fixed code | HIGH | Replace with rolling-code/authenticated link |
| Incrementing counter, no crypto | Weak rolling | MEDIUM | Add crypto/auth; watch for RollJam |
| Changing, cryptographically bound | Rolling/encrypted | LOW | OK; verify against RollJam/jamming |
| Challenge-response / encrypted | Authenticated | VERY LOW | Target state |

## Validation Criteria

- [ ] Spectrum survey run and active frequencies/peaks identified and ranked.
- [ ] Exact center frequency and bandwidth confirmed live (gqrx).
- [ ] Narrowband IQ captured while the device transmits.
- [ ] Modulation, symbol rate, and frame structure characterized (inspectrum/URH).
- [ ] Payload demodulated/decoded with a GNU Radio flowgraph.
- [ ] Multiple transmissions compared and fixed- vs rolling-code verdict recorded.
- [ ] Replay-risk rating and remediation documented.
- [ ] All capture/analysis performed within spectrum/transmission-law authorization (no unauthorized TX).
