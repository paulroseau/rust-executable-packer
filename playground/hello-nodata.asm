; ----------------------------------------------------------------------------------------
; Writes "Hello, World" to the console using only system calls. Runs on 64-bit Linux only.
; To assemble and run:
;
;     nasm -felf64 hello.asm && ld hello.o && ./a.out
; ----------------------------------------------------------------------------------------

          global    _start

          section   .text

_start:   sub       rsp, 10                 ; allocate 10 bytes on the stack
          mov byte  [rsp+0], 111
          mov byte  [rsp+1], 107
          mov byte  [rsp+2], 97
          mov byte  [rsp+3], 121
          mov byte  [rsp+4], 32
          mov byte  [rsp+5], 116
          mov byte  [rsp+6], 104
          mov byte  [rsp+7], 101
          mov byte  [rsp+8], 110
          mov byte  [rsp+9], 10
          mov       rsi, rsp                ; address of string to output
          mov       rdx, 10                 ; number of bytes (9 chars + new line)
          mov       rdi, 1                  ; file handle 1 is stdout
          mov       rax, 1                  ; system call for write
          syscall                           ; invoke operating system to do the write
          add       rsp, 10                 ; free memory

          xor       rdi, rdi                ; exit code 0
          mov       rax, 60                 ; system call for exit
          syscall                           ; invoke operating system to exit
