# SDR Signal Analysis — Tool & Command Reference

## Core CLI Tools

| Tool | Key flags | Purpose |
|------|-----------|---------|
| `rtl_test` | `-t` | Confirm RTL-SDR detection, check sample-rate stability |
| `rtl_power` | `-f <a:b:bin>`, `-i <sec>`, `-e <sec>`, `-g <gain>` | Spectrum sweep → CSV waterfall |
| `rtl_sdr` | `-f <hz>`, `-s <sps>`, `-g <gain>`, `-n <samples>` | Record raw IQ to file |
| `hackrf_transfer` | `-r <file>` (RX), `-t <file>` (TX), `-f <hz>`, `-s <sps>`, `-g`, `-l` | HackRF IQ capture / (authorized) transmit |
| `gqrx` | GUI | Real-time waterfall / demod, confirm center freq |
| `inspectrum` | `-r <sps> <iqfile>` | Visual symbol/modulation analysis |
| `urh` | GUI | Modulation auto-detect, demod to bits, protocol diff |
| `rtl_433` | `-A`, `-f <hz>`, `-R <decoder>` | Decode known sub-GHz devices |
| `gnuradio-companion` | GUI | Build/run demodulation flowgraphs |

## rtl_power CSV Format

```
date, time, Hz_low, Hz_high, Hz_step, samples, dB, dB, dB, ...
```
Each row is one frequency segment for one time integration; the trailing dB values
are the power in each bin from `Hz_low` stepping by `Hz_step`.

## Common Sub-GHz Frequencies

| Frequency | Typical use |
|-----------|-------------|
| 315 MHz | North American remotes / TPMS |
| 433.92 MHz | ISM remotes, sensors, weather stations |
| 868 MHz | EU ISM (LoRa, sensors) |
| 915 MHz | NA ISM (LoRa, industrial) |

## GNU Radio Demod Building Blocks

| Block | Purpose |
|-------|---------|
| `blocks.file_source` (complex) | Read recorded IQ |
| `filter.rational_resampler` | Match symbol rate / decimate |
| `blocks.complex_to_mag` | AM/OOK envelope |
| `analog.quadrature_demod_cf` | FSK demod |
| `digital.binary_slicer_fb` | Bits from soft samples |
| `blocks.file_sink` / `blocks.message_debug` | Output bitstream |

## Companion Script (`scripts/agent.py`)

| Subcommand | Args | Purpose |
|------------|------|---------|
| `peaks` | `--csv <rtl_power.csv>`, `--top <n>`, `--threshold <dB>`, `--json <out>` | Rank active signal peaks/bands from a sweep |
| `replay` | `--frames <file>` | Compare decoded frames; classify fixed vs rolling code + replay risk |

## External References

- rtl_power guide: https://osmocom.org/projects/rtl-sdr/wiki/Rtl-sdr#rtl_power
- HackRF docs: https://hackrf.readthedocs.io/
- URH wiki: https://github.com/jopohl/urh/wiki
- rtl_433 decoders: https://github.com/merbanan/rtl_433/tree/master/src/devices
