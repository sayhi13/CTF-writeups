global _start

section .text
_start:
	pop ebx
	add ebx, 1
	xor ecx, ecx
	mov al, 11
	xor edx, edx
	int 0x80
