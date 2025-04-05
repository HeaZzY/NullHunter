bits 64

section .text
    global _start
_start:
    xor rax, rax
    push rax            ; NULL terminator envp

    mov rdx, rsp        ; rdx = envp

    push rax            ; NULL terminator argv
    mov rdi, 0x687361622F2F2F2F   ; "/bin/bash"
    push rdi
    mov rdi, 0x2F6E69622F2F2F2F
    push rdi
    mov rdi, rsp
    mov rdi, rsp        ; rdi = ptr vers "/bin//sh"

    push rax            ; NULL
    push rdi            ; ptr "/bin//sh"
    mov rsi, rsp        ; rsi = argv ["/bin//sh", NULL]

    mov al, 59          ; execve
    syscall
