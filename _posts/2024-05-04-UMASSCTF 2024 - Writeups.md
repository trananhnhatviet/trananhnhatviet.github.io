---
title: UMASS CTF 2024 - Writeups
date: 2024-05-04 01-10-28
categories: [CTF]
tags: [cryptography,UMASS]
image: /assets/image/UMASS.png
math: true
---

# UMASS CTF 2024

## Third Times the Charm

```python
from Crypto.Util.number import getPrime

with open("flag.txt",'rb') as f:
    FLAG = f.read().decode()
    f.close()


def encrypt(plaintext, mod):
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    return pow(plaintext_int, 3, mod)


while True:
    p = [getPrime(128) for _ in range(6)]
    if len(p) == len(set(p)):
        break

N1, N2, N3 = p[0] * p[1], p[2] * p[3], p[4] * p[5]
m1, m2, m3 = encrypt(FLAG, N1), encrypt(FLAG, N2), encrypt(FLAG, N3)

pairs = [(m1, N1), (m2, N2), (m3, N3)]
for i, pair in enumerate(pairs):
    print(f'm{i+1}: {pair[0]}\nN{i+1}: {pair[1]}\n')
```

Bài này cỏ =)))

```python
from Crypto.Util.number import long_to_bytes
from functools import reduce
from gmpy2 import iroot

e123 = 3
n1 = 34111446391345849621871727156387574194214317478242923140112491089359936613901
c1 = 15795946122944796531378200902356231756918005682087641224569386254369941003192
n2 = 47050878296634747021797065773193318743609137247754556043968364582222396604243
c2 = 22209723256044913703426486965939958009628708900981796783501554932111947434993
n3 = 53213833752674189683397927696526274516644363736816749487202933673093670109189
c3 = 44702062984562900866753245270627888517596326773116156548331358730143900951776

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod

def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

m=chinese_remainder([n1,n2,n3],[c1,c2,c3])
flag = iroot(m,e123)[0]

print(long_to_bytes(flag))
```

**Flag: UMASS{sunz1_su@nj1ng}**

## Brutal Mogging

```python
import os
from hashlib import sha256

from flag import FLAG

def xor(data1, data2):
    return bytes([data1[i] ^ data2[i] for i in range(len(data1))])

def do_round(data, key):
    m = sha256()
    m.update(xor(data[2:4], key))
    return bytes(data[2:4]) + xor(m.digest()[0:2], data[0:2])

def do_round_inv(data, key):
    m = sha256()
    m.update(xor(data[0:2], key))
    return xor(m.digest()[0:2], data[2:4]) + bytes(data[0:2])

def pad(data):
    padding_length = 4 - (len(data) % 4)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# XOR every character with bytes generated from the PRNG
def encrypt_block(data, key):
    
    for i in range(10):
        data = do_round(data, key)
    return data

def decrypt_block(data, key):
    for i in range(10):
        data = do_round_inv(data, key)
    return data

def encrypt_data(data, key):
    cipher = b''
    while data:
        cipher += encrypt_block(data[:4], key)
        data = data[4:]
    return cipher

def decrypt_data(cipher, key):
    data = b''
    while cipher:
        data += decrypt_block(cipher[:4], key)
        cipher = cipher[4:]
    return data

def encrypt(data, key):
    data = pad(data)
    return encrypt_data(encrypt_data(data, key[0:2]), key[2:4])

def decrypt(data, key):
    plain = decrypt_data(decrypt_data(data, key[2:4]), key[0:2])
    return unpad(plain)

if __name__ == '__main__':
    key = os.urandom(4)
    cipher = encrypt(FLAG, key)

    print("Oh yeah, my cipher is so strong and my one way function is so well defined.")
    print("No betas can ever break it, so I'll just give you the flag right now.")

    print(f"The encrypted flag is: {cipher.hex()}")

    print("I need to get back to looksmaxxing so I'll give you three small pieces of advice.")
    print("What are your questions?")
    for i in range(3):
        plain = input(f"{i}: ")[0:8]
        cipher = encrypt(plain.encode(), key)
        print(f"{plain}: {cipher.hex()}")
```

Bài này sẽ có dạng như hình này

![image](/assets/image/UMASS1.png)

Nhưng mà không cần bận tâm tới sơ đồ này, nó chỉ giúp bạn hiểu code hơn thôi.

Bài này sẽ lấy ngẫu nhiên 1 giá trị key gồm 4 byte, sau đó sẽ chia key làm đôi, sau đó sẽ mã hóa hai lần theo như sơ đồ kia nhưng mà cùng một key.

```python
def encrypt(data, key):
    data = pad(data)
    return encrypt_data(encrypt_data(data, key[0:2]), key[2:4])
```

Bài này na ná meet in the middle vậy, sẽ có một trạng thái ở giữa như thế này

![image](/assets/image/UMASS2.png)

Giờ ta chỉ cần bruteforce 2 byte, sau đó sẽ encrypt form flag và lưu vào 1 dict, làm tương tự với 4 byte đầu của ciphertext, nếu hai giá trị giống nhau thì sẽ thu được 2 byte đầu và 2 byte cuối của key.

```python
from hashlib import*
from tqdm import*
from Crypto.Util.number import *

def xor(data1, data2):
    return bytes([data1[i] ^ data2[i] for i in range(len(data1))])

def do_round(data, key):
    m = sha256()
    m.update(xor(data[2:4], key))
    return bytes(data[2:4]) + xor(m.digest()[0:2], data[0:2])

def do_round_inv(data, key):
    m = sha256()
    m.update(xor(data[0:2], key))
    return xor(m.digest()[0:2], data[2:4]) + bytes(data[0:2])

def pad(data):
    padding_length = 4 - (len(data) % 4)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# XOR every character with bytes generated from the PRNG
def encrypt_block(data, key):
    
    for i in range(10):
        data = do_round(data, key)
    return data

def decrypt_block(data, key):
    for i in range(10):
        data = do_round_inv(data, key)
    return data

def encrypt_data(data, key):
    cipher = b''
    while data:
        cipher += encrypt_block(data[:4], key)
        data = data[4:]
    return cipher

def decrypt_data(cipher, key):
    data = b''
    while cipher:
        data += decrypt_block(cipher[:4], key)
        cipher = cipher[4:]
    return data

def encrypt(data, key):
    data = pad(data)
    return encrypt_data(encrypt_data(data, key[0:2]), key[2:4])

def decrypt(data, key):
    plain = decrypt_data(decrypt_data(data, key[2:4]), key[0:2])
    return unpad(plain)

encrypt_flag = "f7940e9cbbba1f613d65dd7410bf315d509f12df0e5f2e9f587427820454c1132a65d3d752ea4d27bd33c0aea2d1e472"
encrypt_flag = bytes.fromhex(encrypt_flag)

list_key = []

for i in range(256):
    for j in range(256):
        list_key.append(long_to_bytes(i) + long_to_bytes(j))

d1 = {}
for i in list_key:
    d1[i] = encrypt_data(b"UMAS",i)

print("DONE")
d2 = {}
fullkey = b""
for i in trange(len(list_key)):
    dec = decrypt_data(encrypt_flag[:4], list_key[i])
    for key, value in d1.items():
        if value == dec:
            print("Found key:", list_key[i]+key)
            fullkey = key + list_key[i]
            flag = decrypt(encrypt_flag,fullkey)
            print(flag)
            exit(-1)
print("hello")
```
**Flag: UMASS{1_h4ve_b33n_m3w1ng_f0r_my_l1f3_733061741}**


## Shuffling As A Service

```python
import random
import string

from Crypto.Random.random import shuffle
from secrets import randbelow


class BitOfShuffling:
    def __init__(self, key_length):
        self.perm = [x for x in range(key_length)]
        shuffle(self.perm)

    def shuffle_int(self, input_int: int):
        shuffled_int = 0
        for x in range(len(self.perm)):
            shuffled_int |= ((input_int >> x) & 1) << self.perm[x]
        return shuffled_int

    def shuffle_bytes(self, input_bytes):
        return self.shuffle_int(int.from_bytes(input_bytes, 'big'))


def rand_string(length):
    return ''.join(
        random.choices(string.digits + string.ascii_letters + r"""!"#$%&'()*+,-./:;<=>?@[\]^_`|~""", k=length))


def pad_flag(flag, length):
    pad_size = length - len(flag)
    if pad_size == 0:
        return flag
    left_size = randbelow(pad_size)
    right_size = pad_size - left_size
    return rand_string(left_size) + flag + rand_string(right_size)


KEY_LENGTH = 128
trials = 10 # (KEY_LENGTH * 8 - 1).bit_length()
if __name__ == "__main__":
    FLAG = "UMASS{6Huff3d_2_b1t5}"
    FLAG = pad_flag(FLAG, KEY_LENGTH)
    shuffler = BitOfShuffling(KEY_LENGTH * 8)
    output_int = shuffler.shuffle_bytes(FLAG.encode())
    print("Quite a bit of shuffling gave us this hex string: ")
    print(f'{output_int:0{KEY_LENGTH * 2}x}')
    print(f"You too can shuffle your hexed bits with our {trials} free trials!")
    for i in range(trials):
        trial = input(f"Input {i + 1}:")
        bits_from_hex = bytes.fromhex(trial)
        print(f'{shuffler.shuffle_bytes(bits_from_hex):0{KEY_LENGTH * 2}x}')
    print("See you next time!")
```

Bài này là bài đảo bit thôi, giờ mình cho bạn ví dụ này nhóeee. Cho 8 bit, và quy luật đảo sẽ như thế này.

```python
7653210 -> 643751024
```

Giờ làm sao biết được bit 0 nằm ở chỗ nào sau khi được đảo, vì chỉ có 0 và 1 thôi ???

Mình sẽ gửi như thế này

```python
76543210 -> 64375102
00001111 -> 00100111
00110011 -> 01001110
01010101 -> 11000011
____________________
            00000010
```

Mình chỉ cần gửi 3 lần vì $$2^3 = 8$$. Bạn thắc mắc nếu bit 1 thì tính làm sao đúng không, mình chỉ cần lấy nghịch đảo của lần gửi thứ 3, thì sẽ thu được.

```
00100111
01001110
00111100
________
00000100
```


Thế nhưng giờ 1024 bits thì sao đây hihuuuhu 😭. Giờ mình sẽ được gửi 10 lần, đúng lun với $$2^{10} = 1024$$. Mình sẽ gửi theo quy luật như trên, sau đó sẽ thu thập các vị trí 1 và 0 bằng set(), sau đó chỉ cần gọi nó ra và AND với nhau thôi.

```python
from pwn import*
from Crypto.Util.number import*

def shuffle_int(input_int, perm):
    shuffled_int = 0
    for x in range(len(perm)):
        shuffled_int |= ((input_int >> x) & 1) << perm[x]
    return shuffled_int

p0 = ("0" * 128 + "f" * 128) * 1
p1 = ("0" * 64 + "f" * 64) * 2
p2 = ("0" * 32 + "f" * 32) * 4
p3 = ("0" * 16 + "f" * 16) * 8
p4 = ("0" * 8 + "f" * 8) * 16
p5 = ("0" * 4 + "f" * 4) * 32
p6 = ("0" * 2 + "f" * 2) * 64
p7 = "0f" * 128
p8 = "3" * 256
p9 = "5" * 256
p = [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9]

io = process(["python3","chal.py"])
io.recvline()
enc_flag = io.recvuntil(b'\n',drop=True).decode()

answers = []
for i in p:
    io.recvuntil(b":")
    io.sendline(i.encode())
    answer = io.recvuntil(b'\n',drop=True).decode()
    answers.append(bin(int(answer, 16))[2:].zfill(1024))
    
    
ones, zeros = [], []
for answer in answers:
    one, zero = set(), set()
    for i in range(len(answer)):
        if answer[i] == "0":
            zero.add(len(answer) - i - 1)
        else:
            one.add(len(answer) - i - 1)
    ones.append(one)
    zeros.append(zero)


perm = []
for i in range(1024):
    num = bin(i)[2:].zfill(10)
    index = set(range(1024))
    for j in range(len(num)):
        if num[j] == "0":
            index &= zeros[j]
        else:
            index &= ones[j]
    perm.append(index.pop())
    
perm = perm[::-1]
revPerm = [perm.index(i) for i in range(1024)]

print(long_to_bytes(shuffle_int(int(enc_flag, 16), revPerm)))
```


**Flag: UMASS{6Huff3d_2_b1t5}**

