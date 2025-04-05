# NullHunter

> A collection of null-byte free shellcodes for exploitation and binary pwning

NullHunter is a curated repository of ready-to-use null-byte free shellcodes written in assembly for various architectures. Designed for CTF players, security researchers, and penetration testers who need reliable shellcodes for binary exploitation challenges.

## Overview

This repository contains hand-crafted shellcodes that:
- Contain no null bytes (0x00) to bypass common string handling vulnerabilities
- Are optimized for size to fit in constrained buffer spaces
- Support multiple techniques including XOR encoding for AV evasion
- Are organized by architecture (32-bit, 64-bit) and functionality (bind shell, reverse shell, etc.)

## Structure

```
NullHunter/
├── Linux 32 bits/          # 32-bit Linux shellcodes
│   ├── exec_shell.asm      # Execute /bin/sh
│   ├── reverse_shell.asm   # Reverse shell
│   └── ...
├── Linux 64 bits/          # 64-bit Linux shellcodes
│   ├── Basic_sh.asm        # Basic execve /bin/sh
│   ├── Basic_Bash.asm      # Basic execve /bin/bash
│   ├── bash_with_string.asm # Execve with string obfuscation
│   └── ...
├── Windows/                # Windows shellcodes
│   ├── 32 bits/
│   └── 64 bits/
├── NullHunter.py         # Shellcode extraction utility
└── README.md
```

## Usage

### Compiling Shellcodes

```bash
# Step 1: Compile the shellcode
nasm -f elf64 Linux\ 64\ bits/Basic_sh.asm -o shellcode.o

# Step 2: Extract the shellcode bytes
for i in $(objdump -d shellcode.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
```

### Using with NullHunter.py

```bash
# Launch the GUI
python3 NullHunter.py

# CLI mode
python3 NullHunter.py Linux64bits/Basic_sh.asm -a elf64 -o shellcode.txt -c
```

## Contribution

Feel free to contribute your own null-byte free shellcodes:

1. Fork the repository
2. Add your shellcode in the appropriate directory
3. Add comments to explain your shellcode
4. Include a brief description in the commit message
5. Create a pull request

## Disclaimer

These shellcodes are provided for educational and legitimate security testing purposes only. Use them responsibly and only on systems you have permission to test.
