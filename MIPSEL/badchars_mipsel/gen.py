badchars = b".agx"
flag_txt = b"flag.txt"
key = ""
for each in flag_txt:
    for i in range(0, 32):
        if each ^ i not in badchars:
            key += str(hex(i)) + " "
            print(hex(each), hex(i ^ each), chr(i ^ each))
            break
print("key:", key)