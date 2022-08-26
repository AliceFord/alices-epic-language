; ----------------------------------------------------------------------------------------
; Writes "Hello, World" to the console using only system calls. Runs on 64-bit Linux only.
; To assemble and run:
;
;     nasm -felf64 hello.asm && ld hello.o && ./a.out
; ----------------------------------------------------------------------------------------

          global    _start

          section   .text
;func:
;    push 10
;    mov rax, 1
;    mov rdi, 1
;    mov rdx, 1
;    mov rsi,rsp
;    syscall
;    pop rax
;    ret
_start:   ;mov       rax, 1                  ; system call for write
          ;mov       rdi, 1                  ; file handle 1 is stdout
          ;mov       rsi, message            ; address of string to output
          ;mov       rdx, 13                 ; number of bytes
          ;syscall                           ; invoke operating system to do the write
          ;mov       rax, 60                 ; system call for exit
          ;xor       rdi, rdi                ; exit code 0
          ;syscall                           ; invoke operating system to exit

          ;call func
          push 97
          push 98
loop:
    mov rax, 1
    mov rdi, 1
    mov rdx, 1
    mov rsi,rsp
    add rsi, 8
    add word [rsi], 3
    syscall
    jmp loop
    pop rax
    pop rax
          
          mov rax, 60
          xor rdi,rdi
          syscall
;          section   .data
;message:  db        "Hello, World", 10      ; note the newline at the end
