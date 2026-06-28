# UART / JTAG Extraction — Tool & Command Reference

## Serial console tools

| Tool | Key invocation | Purpose |
|------|----------------|---------|
| `picocom` | `picocom -b 115200 -l /dev/ttyUSB0` | Lightweight serial terminal; `-l` adds a local echo, pipe to `tee` to log. |
| `screen` | `screen /dev/ttyUSB0 115200` | Ubiquitous terminal; `Ctrl-a k` to quit; `-L` logs to file. |
| `minicom` | `minicom -D /dev/ttyUSB0 -b 115200` | Menu-driven terminal; `-C log.txt` captures. |
| `pyserial` (`python -m serial.tools.miniterm`) | `miniterm /dev/ttyUSB0 115200` | Scriptable Python serial console. |

## Logic analysis (sigrok)

| Command | Purpose |
|---------|---------|
| `sigrok-cli --driver fx2lafw --channels D0 --config samplerate=2m --samples 2000000 -o boot.sr` | Capture boot chatter on D0. |
| `sigrok-cli -i boot.sr -P uart:rx=D0:baudrate=115200 -A uart` | Decode UART at a candidate baud. |
| `pulseview` | GUI capture/decoding; visually measure the narrowest pulse (= bit time). |

Common baud rates to sweep: 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600.

## JTAG/SWD discovery

| Tool | Mode | Purpose |
|------|------|---------|
| JTAGulator | `v` set voltage, `i` IDCODE scan, `b` BYPASS scan | Identify TDI/TDO/TMS/TCK (and IDCODE) on unknown pads. |
| JTAGenum | flashed to Arduino/Teensy/Pi | Software JTAG/SWD pin brute-forcer. |

## OpenOCD

| Command (config or telnet `:4444`) | Purpose |
|-------------------------------------|---------|
| `openocd -f interface/<adapter>.cfg -f target/<soc>.cfg` | Attach adapter + target. |
| `reset halt` | Reset and halt the core. |
| `flash banks` | Enumerate flash banks and sizes. |
| `dump_image <file> <addr> <len>` | Dump arbitrary memory (e.g. internal flash). |
| `flash read_bank <bank> <file> <offset> <len>` | Read a flash bank to a file. |
| `mdw <addr> <count>` / `mdb` / `mdh` | Memory display (word/byte/halfword). |
| `program <file> verify reset` | (Write-back, when authorized for re-flash testing.) |

Common adapter configs: `interface/stlink.cfg`, `interface/jlink.cfg`, `interface/ftdi/ft2232h-module-swd.cfg`, `interface/raspberrypi-native.cfg`.
Common target configs: `target/stm32f4x.cfg`, `target/nrf52.cfg`, `target/esp32.cfg`, `target/imx6.cfg`.

## U-Boot console commands

| Command | Purpose |
|---------|---------|
| `printenv` / `setenv` / `saveenv` | Read/modify/persist environment (bootargs, IP, mtdparts). |
| `sf probe 0` / `sf read <addr> <off> <len>` | Init and read SPI-NOR flash into RAM. |
| `nand read <addr> <off> <len>` | Read NAND flash into RAM. |
| `mmc read <addr> <blk> <cnt>` | Read eMMC/SD blocks. |
| `md.b <addr> <len>` | Memory display (screen-scrape if no network). |
| `tftpput <addr> <len> <file>` / `loady` | Exfiltrate RAM region to a host (TFTP / Y-modem). |

## Companion script (`scripts/agent.py`)

```
python3 scripts/agent.py baud    --pulse-us 8.68
python3 scripts/agent.py baud    --bit-time-s 0.00000868
python3 scripts/agent.py pinout  --pads "p1=0.0,p2=3.30,p3=3.28,p4=2.9" --voltage 3.3
python3 scripts/agent.py console --port /dev/ttyUSB0 --baud 115200 --log boot.log
```

| Subcommand | Key args | Output |
|------------|----------|--------|
| `baud` | `--pulse-us` or `--bit-time-s` | Nearest standard baud rate to a measured shortest pulse. |
| `pinout` | `--pads`, `--voltage` | Ranked guess of which pad is GND/VCC/TX/RX. |
| `console` | `--port`, `--baud`, `--log` | Minimal serial reader (needs pyserial); logs boot output. |

## External References

- OpenOCD User's Guide: https://openocd.org/doc/html/index.html
- U-Boot command reference: https://docs.u-boot.org/en/latest/usage/index.html
- sigrok UART decoder: https://sigrok.org/wiki/Protocol_decoder:Uart
