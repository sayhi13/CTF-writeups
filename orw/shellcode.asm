global _start

section .text
_start:
	mov eax, 3
	xor ebx, ebx
	mov ecx, 0x08048100
	mov edx, 100
	int 0x80

	mov eax, 5
	mov ebx, 0x8048100
	xor ecx, ecx
	xor edx, edx
	int 0x80
	test eax, eax
	js ex

	mov eax, 3
	mov ebx, 3
	mov ecx, 0x8048200
	mov edx, 0x100
	int 0x80

	mov eax, 4
	mov ebx, 1
	mov ecx, 0x8048200
	mov edx, 0x100
	int 0x80

ex:
