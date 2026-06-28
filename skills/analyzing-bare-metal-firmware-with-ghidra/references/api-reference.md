# Bare-Metal Firmware RE — Tool & Command Reference

## Ghidra headless (analyzeHeadless)

| Argument | Purpose |
|----------|---------|
| `<project_dir> <project_name>` | Project location and name (created if absent). |
| `-import <file>` | Import a binary. |
| `-processor "ARM:LE:32:Cortex"` | Force the language/processor spec. |
| `-loader BinaryLoader -loader-baseAddr 0x08000000` | Raw-binary load at a base address. |
| `-postScript <Script.java|py>` | Run a script after analysis (e.g. SVD-Loader). |
| `-scriptPath <dir>` | Add a directory of scripts. |
| `-analysisTimeoutPerFile 600` | Cap analysis time. |
| `-overwrite` | Re-import over an existing program. |

Common processor specs: `ARM:LE:32:Cortex`, `ARM:LE:32:v7`, `ARM:BE:32:v7`, `MIPS:BE:32:default`, `MIPS:LE:32:default`, `RISCV:LE:32:RV32G`.

## Ghidra GUI orientation

| Action | Where |
|--------|-------|
| Set base address | Import dialog > Options > Base Address. |
| Edit memory map | Window > Memory Map (add flash/SRAM/PERIPH/SYSTEM blocks). |
| Create function | Place cursor at reset address, press `F`. |
| Go to address | Press `G`. |
| Find strings | Search > For Strings. |
| Find constants | Search > Memory (hex bytes). |
| Show xrefs | Right-click > References > Show References To. |
| Recover Thumb code | Analysis > One Shot > ARM Aggressive Instruction Finder. |
| Run a script | Window > Script Manager. |

## SVD-Loader

| Step | Action |
|------|--------|
| Add script path | Script Manager > Manage Script Directories > add SVD-Loader dir. |
| Run | Run `SVD-Loader.py` and select the vendor `.svd` file. |
| Result | Peripheral memory blocks + register symbols (e.g. `RCC`, `GPIOA`, `USART1`). |

Get SVDs from https://github.com/cmsis-svd/cmsis-svd (organized by vendor).

## Capstone (out-of-Ghidra sanity check)

```python
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for i in md.disasm(open("firmware.bin","rb").read()[0x190:0x200], 0x08000190):
    print(f"0x{i.address:x}: {i.mnemonic} {i.op_str}")
```

## Companion script (`scripts/agent.py`)

```
python3 scripts/agent.py arch    --image firmware.bin
python3 scripts/agent.py strings --image firmware.bin --min 6 --crypto
python3 scripts/agent.py vectors --image firmware.bin --base 0x08000000
```

| Subcommand | Key args | Output |
|------------|----------|--------|
| `arch` | `--image` | Cortex-M vector-table heuristic; suggested base/load address. |
| `strings` | `--image`, `--min`, `--crypto` | Printable strings; flags known crypto constants. |
| `vectors` | `--image`, `--base` | Dump and validate the first N vector-table entries at a base. |

## Cortex-M vector table (first entries)

| Offset | Entry | Expected value |
|--------|-------|----------------|
| 0x00 | Initial SP | SRAM address (e.g. `0x2000xxxx`). |
| 0x04 | Reset | Thumb code pointer (odd) into flash. |
| 0x08 | NMI | Code pointer (odd). |
| 0x0C | HardFault | Code pointer (odd). |
| 0x10.. | Other faults / IRQs | Code pointers (odd). |

## External References

- Ghidra Cheat Sheet: https://ghidra-sre.org/CheatSheet.html
- ARMv7-M Architecture Reference Manual: https://developer.arm.com/documentation/ddi0403/latest/
- CMSIS-SVD format: https://www.keil.com/pack/doc/CMSIS/SVD/html/index.html
