import array

_target = [0x84, 0x02, 0xf0, 0xe5, 0x7a, 0x40, 0x4e, 0x41, 0x9c, 0x1f, 0xed, 0xbd, 0x9b, 0xec, 0xbf, 0xc0, 0x74, 0xf1, 0x9c, 0xd6, 0xcd, 0x05, 0x53, 0x41]
print(*array.array('d', bytearray(_target)))