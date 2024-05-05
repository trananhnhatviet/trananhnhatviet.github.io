---
title: DAMCTF 2024 - Writeups
date: 2024-05-05 01-10-28
categories: [CTF]
tags: [cryptography,DamCTF]
image: /assets/image/dam1.png
math: true
---
## aedes

```python
#!/usr/local/bin/python3

from functools import reduce, partial
import operator
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xor(*bs):
    return bytes(reduce(operator.xor, bb) for bb in zip(*bs, strict=True))

# def expand_k(k):
#     sched = []
#     for i in range(7):
#         subkey = F(k, i.to_bytes(16))
#         sched[i:i] = [subkey, subkey]

#     sched.insert(7, F(k, (7).to_bytes(16)))
#     return sched

def expand_k(k):
    sched = []
    for i in range(7):
        subkey = F(k, i.to_bytes(16, byteorder='big'))  # Specify byteorder='big'
        sched[i:i] = [subkey, subkey]

    sched.insert(7, F(k, (7).to_bytes(16, byteorder='big')))  # Specify byteorder='big'
    return sched



def F(k, x):
    f = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return f.update(x) + f.finalize()


def enc(k, m):
    subkeys = expand_k(k)
    left, right = m[:16], m[16:]
    for i in range(15):
        old_right = right
        right = xor(left, F(subkeys[i], right))
        left = old_right
      
    return left + right


print("Introducing AEDES, the result of taking all of the best parts of AES and DES and shoving them together! It should be a secure block cipher but proofs are hard so I figured I'd enlist the help of random strangers on the internet! If you're able to prove me wrong you might get a little prize :)")

key = secrets.token_bytes(16)

with open("flag", "rb") as f:
    flag = f.read(32)

assert len(flag) == 32
flag_enc = enc(key, flag)

print("Since I'm so confident in the security of AEDES, here's the encrypted flag. Good luck decrypting it without the key :)")
print(flag_enc.hex())

for _ in range(5):
    pt_hex = input("Your encryption query (hex): ")
    try:
        pt = bytes.fromhex(pt_hex)
        assert len(pt) == 32
    except (ValueError, AssertionError):
        print("Make sure your queries are 32 bytes of valid hex please")
        continue

    ct = enc(key, pt)
    print("Result (hex):", ct.hex())

```

Bài này khá giống **Feistel Cipher** nhưng có điều đặc biệt là có 15 key và các key[i] = key[15-i].

![image](/assets/image/dam2.png)

Từ hình trên, ta sẽ đổi ngược lại thứ tự L và R, sau đó sẽ gửi lại cho server, vì key[i] = key[15-i] nên ta không phải florentino nha. Chỉ có điều là phải đổi lại thứ tự sau khi lấy lại vì số key là lẻ.

```python
from pwn import*

io = process(["python3","aedes.py"])

io.recvuntil(b'without the key :)\n')

enc_flag = io.recvuntil(b'\n',drop=True).decode()

print(enc_flag)

left = enc_flag[:32]
right = enc_flag[32:]

io.recvuntil(b'Your encryption query (hex): ')
io.sendline((right+left).encode())

io.recvuntil(b'Result (hex): ')
flag = io.recvuntil(b'\n',drop=True).decode()

left = flag[32:]
right = flag[:32]

print(bytes.fromhex(left+right))
```

**Flag: dam{k3Y_sch3dul35_4r3_H4rd_0k4y}**

## Fundamental

```python
#!/usr/local/bin/python3

from Crypto.Util.number import*
import secrets
import sys

p = 129887472129814551050345803501316649949


def poly_eval(coeffs, x):
    res = 0
    for c in coeffs:
        res = (c + x * res) % p
    return res


def pad(m):
    padlen = 16 - (len(m) % 16)
    padding = bytes([padlen] * padlen)
    return m + padding


def to_coeffs(m):
    coeffs = []
    for i in range(0, len(m), 16):
        chunk = m[i:i+16]
        coeffs.append(bytes_to_long(chunk))
    return coeffs


def auth(s, k, m):
    coeffs = to_coeffs(m)
    mac_int = (poly_eval(coeffs, k) + s) % p
    return mac_int.to_bytes(16, byteorder='big')


def ver(s, k, m, t):
    return secrets.compare_digest(t, auth(s, k, m))


def hexinput(msg):
    try:
        return bytes.fromhex(input(msg))
    except ValueError:
        print("please enter a valid hex string")
        return None


k = secrets.randbelow(p)
kp = secrets.randbelow(p)
s = secrets.randbelow(p)
target = b"pleasepleasepleasepleasepleasepl"

print("Poly1305 is hard to understand so I decided to try simplifying it myself! Its parameters and stuff were probably just fluff right?")
print("Anyways it should be secure but if you can prove me wrong I'll give you a little something special :)")

print()
print("First I'll let you sign an arbitrary message")

while (msg1 := hexinput("message to sign (hex): ")) is None:
    pass

if len(msg1) == 0:
    print("message must be nonempty")
    sys.exit(1)
elif msg1 == target:
    print("nice try :)")
    sys.exit(1)

if len(msg1) % 16 != 0:
    mac = auth(s, kp, pad(msg1))
else:
    mac = auth(s, k, msg1)

print("authentication tag:", mac.hex())

print()
print("Now I just *might* give you the flag if you convince me my authenticator is insecure. Give me a valid tag and I'll give you the flag.")

while (tag := hexinput("enter verification tag (hex): ")) is None:
    pass

if ver(s, k, target, tag):
    print("oh you did it...here's your flag I guess")
    with open("flag") as f:
        print(f.read())

else:
    print("invalid authentication tag")

```

Bài này sign dưới thuật toán như sau:

$$
b_0*k^3 + b_1*k^2 + b_3*k + b_4 +s\mod p
$$

Và sign target sẽ có dạng như sau:

$$
target_1 * k + target_2 + s \mod p
$$

Bài này có hai cách, cách thứ nhất là mình sẽ gửi 3 block, với block thứ nhất là "00"*16, khi đó sẽ thu được sign của target mà không làm ảnh hưởng tới sign. Cách hai, ta sẽ lấy block 1 của target + p, khi đó mod p sẽ trở thành target luôn.

```python
from Crypto.Util.number import*
from pwn import*

io = process(["python3","fundamental.py"])
target = b"pleasepleasepleasepleasepleasepl"

io.recvuntil(b'(hex): ')
io.sendline(b"00"*16 + target.hex().encode())

io.recvuntil(b'authentication tag: ')
tag = io.recvuntil(b'\n',drop=True)

io.recvuntil(b'(hex): ')
io.sendline(tag)

io.interactive()
```

```python
from Crypto.Util.number import*
from pwn import*

io = process(["python3","fundamental.py"])
target = b"pleasepleasepleasepleasepleasepl"
p = 129887472129814551050345803501316649949

b1 = target[:16]
b2 = target[16:]

b1 = long_to_bytes(bytes_to_long(b1) + p).hex().encode()

io.recvuntil(b'(hex): ')
io.sendline(b1 + b2.hex().encode())

io.recvuntil(b'authentication tag: ')
tag = io.recvuntil(b'\n',drop=True)

io.recvuntil(b'(hex): ')
io.sendline(tag)

io.interactive()
```

**Flag: dam{17'5_4lW4Y5_7h3_z3r0s_15n'7_17}**

## fundamental-revenge

```python
#!/usr/local/bin/python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import sys
from Crypto.Util.number import*

p = 168344944319507532329116333970287616503


def F(k, x):
    f = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return f.update(x) + f.finalize()


def poly_eval(coeffs, x):
    res = 0
    for c in coeffs:
        res = (c + x * res) % p
    return res


def to_coeffs(m):
    coeffs = [1]
    for i in range(0, len(m), 16):
        chunk = m[i : i + 16]
        coeffs.append(bytes_to_long(chunk))
    return coeffs


def auth(k, s, m):
    coeffs = to_coeffs(m)
    poly_k = bytes_to_long(k[16:])
    mac_int = (poly_eval(coeffs, poly_k) + s) % p
    return F(k[:16], mac_int.to_bytes(16, byteorder='big'))


def ver(k, s, m, t):
    return secrets.compare_digest(auth(k, s, m), t)


def hexinput(msg):
    try:
        b = bytes.fromhex(input(msg))
        assert len(b) % 16 == 0 and len(b) > 0
        return b
    except (ValueError, AssertionError):
        print("please enter a valid hex string")
        return None


k = secrets.token_bytes(32)
s = secrets.randbelow(p)

target = b"gonna ace my crypto final with all this studying"

print("Let's try this again, shall we?")
print()

while (msg1 := hexinput("first message to sign (hex): ")) is None:
    pass

if msg1 == target:
    print("nice try :)")
    sys.exit(1)

mac = auth(k, s, msg1)
print("authentication tag:", mac.hex())

print()
print("now sign this:", target.decode())

while (tag := hexinput("enter verification tag (hex): ")) is None:
    pass

if ver(k, s, target, tag):
    print("oh you did it again...I guess I'm just bad at cryptography :((")
    with open("flag") as f:
        print("here's your flag again..", f.read())

else:
    print("invalid authentication tag")

```

Bài này có khè mình hơi rén, nhưng mà dùng cách hai như bài trên thì ra, không phải flo.

```python
from Crypto.Util.number import*
from pwn import*

io = process(["python3","fundamental-revenge.py"])
target = b"gonna ace my crypto final with all this studying"
p = 168344944319507532329116333970287616503

b1 = target[:16]
b2 = target[16:]

b1 = long_to_bytes(bytes_to_long(b1) + p).hex().encode()

io.recvuntil(b'(hex): ')
io.sendline(b1 + b2.hex().encode())

io.recvuntil(b'authentication tag: ')
tag = io.recvuntil(b'\n',drop=True)

io.recvuntil(b'(hex): ')
io.sendline(tag)

io.interactive()
```

**Flag: dam{50m371m35_1_m155_g00d_0lD_0n3_71m3_P4d}**
