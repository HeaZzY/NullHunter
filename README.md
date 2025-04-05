# Step 1 Compile the shellcode

```bash
nasm -f <arch ex: elf64> shellcode.asm -o shellcode.o
```
# Step 2 extract the shellcode from the .o

```bash
for i in $(objdump -d shellcode.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo
```
