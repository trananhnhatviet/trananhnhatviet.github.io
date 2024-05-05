---
title: GreyCat2024 - Writeups
date: 2024-05-05 01-10-28
categories: [CTF]
tags: [cryptography,GreyCat]
image: /assets/image/gaycat1.png
math: true
---
## Filter Ciphertext ⛓️

```python
from Crypto.Cipher import AES
import os

with open("flag.txt", "r") as f:
    flag = f.read()

BLOCK_SIZE = 16
iv = os.urandom(BLOCK_SIZE)

xor = lambda x, y: bytes(a^b for a,b in zip(x,y))

key = os.urandom(16)

def encrypt(pt):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
    tmp = iv
    ret = b""
  
    for block in blocks:
        res = cipher.encrypt(xor(block, tmp))
        ret += res
        tmp = xor(block, res)
      
    return ret

  
def decrypt(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    for block in blocks:
        if block in secret_enc:
            blocks.remove(block)
  
    tmp = iv
    ret = b""
  
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        ret += res
        tmp = xor(block, res)
  
    return ret
  
secret = os.urandom(80)
secret_enc = encrypt(secret)

print(f"Encrypted secret: {secret_enc.hex()}")

print("Enter messages to decrypt (in hex): ")

while True:
    res = input("> ")

    try:
        enc = bytes.fromhex(res)

        if (enc == secret_enc):
            print("Nice try.")
            continue
      
        dec = decrypt(enc)
        if (dec == secret):
            print(f"Wow! Here's the flag: {flag}")
            break

        else:
            print(dec.hex())
      
    except Exception as e:
        print(e)
        continue
```

Bài này có cái bug to vl là cái remove block á.

![image](/assets/image/gaycat2.png)

**Flag: grey{00ps_n3v3r_m0d1fy_wh1l3_1t3r4t1ng}**

## Filter Plaintext ⛓️

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import md5
import os

with open("flag.txt", "r") as f:
    flag = f.read()

BLOCK_SIZE = 16
iv = os.urandom(BLOCK_SIZE)

xor = lambda x, y: bytes(a^b for a,b in zip(x,y))

key = os.urandom(16)

def encrypt(pt):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]
    tmp = iv
    ret = b""
  
    for block in blocks:
        res = cipher.encrypt(xor(block, tmp))
        ret += res
        tmp = xor(block, res)
      
    return ret

  
def decrypt(ct):
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

  
    tmp = iv
    ret = b""
  
    for block in blocks:
        res = xor(cipher.decrypt(block), tmp)
        if (res not in secret):
            ret += res
        tmp = xor(block, res)
      
    return ret
  
secret = os.urandom(80)
secret_enc = encrypt(secret)

print(f"Encrypted secret: {secret_enc.hex()}")

secret_key = md5(secret).digest()
secret_iv = os.urandom(BLOCK_SIZE)
cipher = AES.new(key = secret_key, iv = secret_iv, mode = AES.MODE_CBC)
flag_enc = cipher.encrypt(pad(flag.encode(), BLOCK_SIZE))

print(f"iv: {secret_iv.hex()}")

print(f"ct: {flag_enc.hex()}")

print("Enter messages to decrypt (in hex): ")

while True:
    res = input("> ")

    try:
        enc = bytes.fromhex(res)
        dec = decrypt(enc)
        print(dec.hex())
      
    except Exception as e:
        print(e)
        continue
```

Bài này cũng tương tự thế, nhưng phải chú ý hơn về sơ đồ bla bla...

```python
from hashlib import md5
from pwn import*
from Crypto.Cipher import AES

io = remote("challs.nusgreyhats.org", 32223)

# io = process(["python3","./filter_ciphertext.py"])

io.recvuntil(b'Encrypted secret: ')

enc_secret = io.recvuntil(b'\n',drop=True).decode()

io.recvuntil(b'iv: ')

iv_flag = bytes.fromhex(io.recvuntil(b'\n',drop=True).decode())

io.recvuntil(b'ct: ')

ct = bytes.fromhex(io.recvuntil(b'\n',drop=True).decode())


io.recvuntil(b'> ')
io.sendline(b'00000000000000000000000000000000'*2)
iv = io.recvuntil(b'\n',drop=True).decode()
iv = bytes.fromhex(iv)
iv = iv[16:]

enc_flag = bytes.fromhex(enc_secret)
b0 = enc_flag[:16]
b1 = enc_flag[16:32]
b2 = enc_flag[32:48]
b3 = enc_flag[48:64]
b4 = enc_flag[64:80]

res = b''

io.recvuntil(b'> ')
io.sendline(b1.hex().encode() + b0.hex().encode())
de_b0 = bytes.fromhex(io.recvuntil(b'\n',drop=True).decode())
dec_b0 = xor(xor(xor(de_b0[:16],de_b0[16:]),iv),b1)
print(dec_b0.hex())

io.recvuntil(b'> ')
io.sendline(b2.hex().encode() + b1.hex().encode())
de_b1 = bytes.fromhex(io.recvuntil(b'\n',drop=True).decode())
dec_b1 = xor(xor(xor(xor(de_b1[:16],de_b1[16:]),dec_b0),b2),b0)
print(dec_b1.hex())

io.recvuntil(b'> ')
io.sendline(b3.hex().encode() + b2.hex().encode())
de_b2 = bytes.fromhex(io.recvuntil(b'\n',drop=True).decode())
dec_b2 = xor(xor(xor(xor(de_b2[:16],de_b2[16:]),b3),b1),dec_b1)
print(dec_b2.hex(),"2")

io.recvuntil(b'> ')
io.sendline(b4.hex().encode() + b3.hex().encode())
de_b3 = bytes.fromhex(io.recvuntil(b'\n',drop=True).decode())
dec_b3 = xor(xor(xor(xor(de_b3[:16],de_b3[16:]),b4),b2),dec_b2)
print(dec_b3.hex(),"3")

b5 = b'a'*16

io.recvuntil(b'> ')
io.sendline(b5.hex().encode() + b4.hex().encode())
de_b4 = bytes.fromhex(io.recvuntil(b'\n',drop=True).decode())
dec_b4 = xor(xor(xor(xor(de_b4[:16],de_b4[16:]),b5),b3),dec_b3)
print(dec_b4.hex(),)

secret = dec_b0+dec_b1+dec_b2+dec_b3+dec_b4
print(secret.hex())
secret_key = md5(secret).digest()

cipher = AES.new(key = secret_key, iv = iv_flag, mode = AES.MODE_CBC)

print(cipher.decrypt(ct))
```

**Flag: grey{pcbc_d3crypt10n_0r4cl3_3p1c_f41l}**

## AES

**aes.py**

```python
# Adapted from https://github.com/boppreh/aes/blob/master/aes.py

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

def mix_single_column(a):
    a[0], a[1], a[2], a[3] = a[1], a[2], a[3], a[0]

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

class AES:
    def __init__(self, master_key) -> None:
        assert len(master_key) == 16
        self.n_rounds = 10
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4
        i = 1

        while len(key_columns) < (self.n_rounds + 1) * 4:
            word = list(key_columns[-1])
            if len(key_columns) % iteration_size == 0:
                word.append(word.pop(0))
                word = [s_box[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)
  
    def encrypt(self, plaintext):
        plaintext = pad(plaintext)
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            ciphertext += self.encrypt_block(plaintext[i : i + 16])
        return ciphertext



```

**server.py**

```python
from secrets import token_bytes
from aes import AES

FLAG = 'REDACTED'
password = token_bytes(16)
key = token_bytes(16)

AES = AES(key)
m = bytes.fromhex(input("m: "))
if (len(m) > 4096): exit(0)
print("c:", AES.encrypt(m).hex())

print("c_p:", AES.encrypt(password).hex())
check = input("password: ")
if check == password.hex():
    print('flag:', FLAG)
```

Link của bản chính thức của [**aes.py**](https://github.com/boppreh/aes/blob/master/aes.py).

Ta thấy rằng điểm khác biệt chính là phần **mix_columns()** này đây

```python
def mix_single_column(a):
    a[0], a[1], a[2], a[3] = a[1], a[2], a[3], a[0]

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])
```

thay vì so với bản gốc là

```python
# learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])
```

Ở bài này, thì mix columns bị custom, chỉ tịnh tiến các cột, thế nên chắc chắn sẽ có lỗ hỏng ở đây.

Sửa code **aes.py** def encrypt_block như sau để phân tích

```python
def encrypt_block(self, plaintext):
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])
            print(plain_state)
        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])
        print(plain_state)
        return matrix2bytes(plain_state)
```

Thường là AES, mình sẽ gửi các byte 00 vào để coi nó như thế nào. Và mình thu được các plain_state như sau

```python
[[6, 76, 51, 190], [156, 4, 89, 215], [100, 32, 37, 202], [17, 31, 6, 0]]
[[100, 230, 246, 53], [23, 55, 122, 197], [55, 120, 248, 125], [236, 245, 199, 241]]
[[186, 245, 187, 191], [60, 42, 88, 23], [145, 21, 158, 67], [60, 179, 116, 100]]
[[52, 130, 245, 63], [8, 247, 112, 199], [75, 216, 176, 116], [114, 49, 209, 180]]
[[144, 113, 244, 241], [200, 205, 116, 245], [72, 39, 135, 131], [8, 203, 24, 47]]
[[221, 255, 196, 38], [5, 182, 113, 107], [89, 101, 119, 225], [254, 210, 247, 236]]
[[103, 178, 153, 203], [173, 52, 112, 226], [19, 154, 105, 241], [237, 101, 245, 93]]
[[5, 105, 149, 128], [69, 42, 65, 25], [22, 164, 208, 203], [151, 221, 228, 5]]
[[135, 142, 225, 142], [214, 91, 25, 7], [5, 82, 72, 152], [157, 119, 198, 7]]
[[252, 242, 171, 99], [130, 249, 153, 214], [219, 116, 73, 213], [138, 108, 188, 217]]
```

Giờ mình thay đổi byte đầu tiên là ``ff`` ở đầu, còn lại vẫn là các byte rỗng, thì mình thu được các plain_text như sau

```python
[[6, 76, 51, 242], [156, 4, 89, 215], [100, 32, 37, 202], [17, 31, 6, 0]]
[[100, 230, 246, 53], [23, 55, 93, 197], [55, 120, 248, 125], [236, 245, 199, 241]]
[[186, 245, 187, 191], [60, 42, 88, 23], [145, 21, 158, 67], [60, 37, 116, 100]]
[[52, 130, 245, 63], [8, 247, 112, 199], [25, 216, 176, 116], [114, 49, 209, 180]]
[[144, 113, 244, 241], [200, 205, 116, 245], [72, 39, 135, 228], [8, 203, 24, 47]]
[[221, 255, 196, 38], [5, 182, 113, 107], [89, 101, 119, 225], [254, 210, 114, 236]]
[[103, 178, 153, 203], [173, 28, 112, 226], [19, 154, 105, 241], [237, 101, 245, 93]]
[[129, 105, 149, 128], [69, 42, 65, 25], [22, 164, 208, 203], [151, 221, 228, 5]]
[[135, 142, 225, 233], [214, 91, 25, 7], [5, 82, 72, 152], [157, 119, 198, 7]]
[[252, 242, 171, 99], [130, 249, 153, 209], [219, 116, 73, 213], [138, 108, 188, 217]]
```

Ta thấy rằng output của 2 plaintext này không khác nhau là mấy chỉ thay đổi 1 byte

```python
                                       X
[[252, 242, 171, 99], [130, 249, 153, 214], [219, 116, 73, 213], [138, 108, 188, 217]]
                                       X
[[252, 242, 171, 99], [130, 249, 153, 209], [219, 116, 73, 213], [138, 108, 188, 217]]
```

Có thể chạy code này để kiểm chứng

```python
from aes import*
from pwn import *
from Crypto.Util.number import*

key = b'12345678abcdefgh'

AES = AES(key)
print("first")
ct = AES.encrypt(b'\x00'*16)[:16]
print("second")
x = AES.encrypt(b'\xff' + b'\x00'*15)

```

Ta encrypt(``b'\x00' + b'\xff' + b'\x00'*14``) ta cũng thu được kết quả tương ứng

```python
                                                                   X
[[252, 242, 171, 99], [130, 249, 153, 214], [219, 116, 73, 213], [138, 108, 188, 217]]
                                                                   X
[[252, 242, 171, 99], [130, 249, 153, 214], [219, 116, 73, 213], [29, 108, 188, 217]]
```

Từ đó, ta sẽ thu được sự ảnh hưởng thứ tự của plaintext tới ciphertext.

Mình sẽ gửi hết theo quy luật thế 16 lần coi sẽ được như thế nào nha.

```python
from aes import*
from pwn import *
from Crypto.Util.number import*

key = b'12345678abcdefgh'

AES = AES(key)
ct = AES.encrypt(b'\x00'*16)[:16]

lst = []
for i in range(16):
    payload = b"\x00"*i + b'\xff' + b'\x00'*(15-i)
    new_ct = AES.encrypt(payload)
    for j in range(16):
        if new_ct[j] != ct[j]:
            lst.append(j)
print(lst) 
```

```python
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff'
[7, 12, 5, 14, 11, 0, 9, 2, 15, 4, 13, 6, 3, 8, 1, 10]
```

Giờ ta sẽ tấn công từng ký tự của password.

```python
from aes import*
from pwn import *
from Crypto.Util.number import*

key = b'12345678abcdefgh'
password = b'abcdefghabcdefgh'

AES = AES(key)
ct = AES.encrypt(b'a'*16)[:16]
print(ct)
pass_enc = AES.encrypt(password)[:16]
print(xor(pass_enc,ct)[:8])
```

Ta thấy rằng, nếu đúng byte đầu tiên, thì byte thứ 8 của xor(pass_enc,ct) sẽ là byte 00, tiếp tục như thế với byte thứ 2 của password, thì byte thứ 13 của xor(pass_enc,ct) sẽ là 00. Từ đó ta tìm lại được password.

```python
from aes import*
from pwn import *
from Crypto.Util.number import*

lst = [7, 12, 5, 14, 11, 0, 9, 2, 15, 4, 13, 6, 3, 8, 1, 10]

pload = b''
for i in range(256):
    pload += bytes([i]*16)

# io = process(["python3","server.py"])
io = remote('challs.nusgreyhats.org', 35100)
io.recvuntil(b'm: ')
io.sendline(pload.hex().encode())
io.recvuntil(b'c: ')
ct = bytes.fromhex(io.recvline().rstrip().decode())[:-16]
io.recvuntil(b'c_p: ')
pass_enc = bytes.fromhex(io.recvline().rstrip().decode())[:16]

print(pass_enc)
recover_pass = b''
for count in range(16):
    for i in range(256):
        block = ct[i*16:i*16+16]
        plain = pload[i*16:i*16+16].hex()
        x = xor(block,pass_enc)
        if x[lst[count]] == 0:
            recover_pass += long_to_bytes(pload[i*16+1])
            break
        print(f'recovered pw: {recover_pass}')


io.recvuntil(b'password: ')
io.sendline(recover_pass.hex().encode())
io.interactive()

```

**grey{mix_column_is_important_in_AES_ExB3Hf9q9I3m}**

## PRG

**server.py**

```python
from secrets import token_bytes, randbits
from param import A 
import numpy as np

FLAG = 'REDACTED'

A = np.array(A)

def print_art():
    print(r"""
            />_________________________________
    [########[]_________________________________>
            \>
    """)
  
def bytes_to_bits(s):
    return list(map(int, ''.join(format(x, '08b') for x in s)))

def bits_to_bytes(b):
    return bytes(int(''.join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8))

def prg(length):
    x = token_bytes(8); r = token_bytes(8); k = token_bytes(8)
    x = np.array(bytes_to_bits(x)); r = np.array(bytes_to_bits(r)); k = np.array(bytes_to_bits(k))
    output = []
    for i in range(length * 8):
        output.append(sum(x) % 2)
        if (i % 3 == 0): x = (A @ x + r) % 2
        if (i % 3 == 1): x = (A @ x + k) % 2
        if (i % 3 == 2): x = (A @ x + r + k) % 2
    output = output
    return bits_to_bytes(output).hex()
  
def true_random(length):
    return token_bytes(length).hex()

def main():
    try:
        print_art()
        print("I try to create my own PRG")
        print("This should be secure...")
        print("If you can win my security game for 100 times, then I will give you the flag")
        for i in range(100):
            print(f"Game {i}")
            print("Output: ", end="")
            game = randbits(1)
            if (game): print(prg(16))
            else: print(true_random(16))
            guess = int(input("What's your guess? (0/1): "))
            if guess != game:
                print("You lose")
                return
        print(f"Congrats! Here is your flag: {FLAG}")
    except Exception as e:
        return

if __name__ == "__main__":
    main()
```

**param.py**

```python
A = [
    [0,1,1,1,0,0,0,1,0,1,1,1,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,0,0,1,1,0,1,1,0,1,1,0,1,1,0,1,0,0,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,0,1,1,0],
    [1,1,1,1,1,1,0,1,0,0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,1,0,1,0,0,0,1,0,0,0,1,0,0,0,1,0,1,1,1,0,0,0,1,0,0,0,1,1,0,1],
    [0,1,0,1,1,1,0,1,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,1,0,0,0,1,1,0,0,1,1,1,1,1,0,1,0,0,1,1,0,0,1,1,0,1,0,1,1,1,0,1,1,0,0,0,0,0,1,1,0,0],
    [1,0,1,1,0,1,1,1,0,1,0,0,0,0,0,1,0,0,0,0,0,1,1,1,0,0,0,1,1,0,1,1,1,0,1,1,0,1,0,1,0,0,0,0,0,1,0,0,0,1,1,0,1,1,0,0,1,0,1,0,1,1,1,1],
    [0,0,0,1,1,0,1,1,1,1,1,1,1,1,0,0,1,0,1,0,0,0,1,1,0,0,0,1,1,1,1,0,1,1,1,0,1,1,0,1,1,1,0,1,1,1,1,1,1,1,0,0,1,1,1,1,1,1,0,1,1,0,0,1],
    [0,1,0,1,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,1,1,0,0,1,1,1,0,1,0,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,1,1,1,0,0],
    [0,0,1,0,0,0,1,0,0,0,0,1,0,0,1,0,1,0,0,0,1,0,1,0,1,0,1,0,0,0,1,0,0,1,1,1,1,0,0,1,0,0,0,1,0,1,0,1,1,0,1,1,0,0,0,0,0,0,1,0,1,1,0,0],
    [1,1,1,0,0,0,1,1,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,1,1,1,1,0,1,1,1,1,0,1,0,1,0,0,1,1,1,0,1,0,1,1,1,0,1,0,1,0,0,1,1,1,0,1,0,1,1,1,1,1],
    [1,1,1,1,1,1,0,1,1,1,0,0,0,0,1,1,0,0,1,1,1,0,0,0,1,1,0,0,1,1,1,1,1,0,1,0,0,0,0,0,1,1,1,1,0,0,1,1,1,1,1,0,1,1,1,1,1,1,0,1,0,1,1,1],
    [1,1,0,0,0,0,0,1,1,1,1,0,0,0,0,0,1,0,1,0,1,1,1,0,0,0,1,1,0,1,1,0,1,1,1,1,0,0,1,0,1,1,0,0,1,1,0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,1,0],
    [1,1,0,1,0,0,1,1,1,0,1,1,0,1,1,0,0,1,1,1,1,1,0,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,1,1,0,1,1,1,0,0,0,1,0,0,0,0,1],
    [0,0,1,0,0,0,1,1,0,1,1,1,0,1,1,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,0,1,1,0,1,1,0,0,1,1,0,1,1,0,0,1,0,0,1],
    [0,1,1,1,0,0,0,0,0,1,0,0,0,0,1,0,1,0,0,0,1,0,1,0,0,1,0,1,0,0,1,1,1,1,1,1,1,0,0,1,1,1,0,0,0,1,1,1,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,1],
    [1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,0,0,0,0,1,0,0,0,0,0,0,1,1,0,1,1,1,0,0,0,1,0,0,0,0,0,0,1,1,1,0,1,0,1,1,0,1,0,1,1,1],
    [1,1,1,0,1,1,1,0,1,0,1,1,0,0,0,0,1,1,0,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,0,0,1,0,0,1,0,0,1,0,1,0,0,1,0,0,1,0,0,1,0,1,1,1],
    [0,1,0,0,0,0,1,1,0,1,0,1,1,1,0,1,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1,0,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,1,0,0,0,0,1,0,1,0],
    [1,0,0,1,0,1,1,1,1,1,1,1,0,0,0,0,1,0,1,0,1,1,1,1,1,1,1,1,0,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,1,1,0,1,1,1,1,0,1,0,1,0,0,1,1,0,1,1,0],
    [0,0,1,1,0,1,0,1,0,1,1,1,1,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,0,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,0,0,1,1,1,0,1,0,1,1,1,0,0],
    [1,0,0,1,1,0,1,1,0,0,0,1,0,0,1,1,0,1,1,0,1,1,0,1,1,0,0,0,0,1,1,1,0,1,0,1,1,0,0,0,1,1,1,0,1,1,1,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,1,0],
    [0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,1,1,1,1,1,0,0,1,1,1,1,1,0,0,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,0,1,1,1,0,1,0,1,0],
    [0,0,1,0,1,0,0,1,0,1,0,1,0,0,1,1,0,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,1,1,1,0,1,1,1,0,1,0,0,0,1,0,1,0,0,1,0,1,0,1,1,1,1,0,0,0,1,1,0,0],
    [1,0,0,1,1,0,1,1,0,0,0,1,1,1,0,1,0,1,1,1,1,0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,1,0,1,0,0,0,0,0,1,1,0,1,1,1,1,0,1,1,0,0,1,1,0,1,0],
    [0,0,0,1,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,1,0,0,1,1,0,1,1,1,0,1,1,0,1,1,0,0,0,0,0,0,0,1,0,0,1,0,1,0,0,0,0,1,0,0,1,1,0,0,0,1,0,0,0,0],
    [0,1,0,1,0,1,1,1,0,1,0,1,1,0,0,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,1,1,1,0,0,1,1,0,0,0,0,0,1,0,1,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0,1,0,1,0],
    [1,0,0,1,1,1,0,1,0,0,1,1,1,0,0,1,1,1,1,1,1,1,0,1,1,0,0,0,0,0,0,1,1,0,1,1,0,1,1,1,0,0,0,0,1,0,1,1,1,0,1,1,1,1,0,1,0,1,1,0,1,0,0,1],
    [0,1,0,0,0,1,1,1,1,0,1,1,0,0,1,1,1,0,0,1,0,1,0,1,0,1,1,0,1,0,1,1,0,1,0,1,1,1,1,1,0,1,1,0,0,0,0,1,0,1,0,0,0,0,1,0,0,1,0,1,0,1,0,0],
    [0,0,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,1,1,1,0,1,0,0,1,1,1,1,1,1,0,0,0,1,1,0,1,0,1,0,1,1,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,1,0,1,0,1],
    [1,1,0,0,1,0,0,1,1,0,0,0,0,0,1,0,1,1,0,1,0,1,1,0,0,0,1,1,1,0,1,1,0,1,0,1,0,1,1,0,1,0,0,0,0,1,1,0,1,1,1,0,1,0,1,0,1,0,0,0,0,0,0,0],
    [0,0,0,1,0,0,1,0,1,0,0,1,1,0,1,1,1,0,0,1,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,1,0,1,0,1,0],
    [0,1,1,0,1,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,0,1,1,0,1,0,1,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,0,0,0,0],
    [1,0,1,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,1,1,0,1,0,0,0,0,0,0,1,1,0,1,0,1,1,1,0,1,0,0,1,0,0,1,0,0,1,1,1,0,0,1,0,0,0,0,1,1,0,1,1,1,0,1],
    [0,0,1,1,0,0,1,0,1,1,0,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,1,0,0,0,0,1,0,1,1,0,0,0,0,0,0,0,1,0,1,0,1,0,1,1,1,1,1,0,1,0,1,1,0,1,0,0,1],
    [1,1,1,1,0,0,0,0,0,1,0,0,1,1,0,1,1,0,1,0,0,0,0,1,1,1,1,0,1,1,0,0,1,1,0,1,1,1,0,0,1,1,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,0,1,1,1,1,0,0],
    [1,0,1,0,1,1,1,1,0,1,0,0,1,0,0,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,0,1,1,1,0,1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,1,0,1,0,1,1],
    [1,1,0,1,0,1,0,1,0,0,1,1,1,1,1,0,0,0,1,0,1,1,0,1,1,0,0,0,0,1,0,1,1,1,0,0,1,1,1,0,0,0,1,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,0,0,0,1],
    [0,1,1,0,0,0,1,1,1,0,1,1,1,0,1,0,0,0,0,1,0,0,1,0,0,1,0,1,1,1,0,0,1,1,0,0,1,0,0,1,0,0,0,1,0,1,1,0,0,0,1,0,0,0,0,0,1,0,0,0,1,0,1,1],
    [0,0,0,1,1,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,0,1,0,0,0,1,0,1,1,0,0,1,1,1,1,1,0,0,1,1,1,0,1,0,1,1,1,1,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1],
    [0,1,1,0,0,1,0,1,1,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,1,1,1,1,0,1,0,0,1,1,1,1,0,0,1,0,0,1,0,0,0,0,0,1,0,1,1,1,0,1,0,1],
    [1,1,0,0,0,1,0,1,0,0,0,1,1,0,1,0,1,1,1,1,0,0,0,0,1,0,1,1,1,0,0,0,0,0,0,0,0,0,1,1,1,1,0,0,0,0,0,1,1,0,1,1,0,1,0,0,0,1,1,1,1,1,0,0],
    [1,0,1,1,1,1,1,1,0,0,1,0,0,0,1,1,1,0,1,1,0,1,0,1,0,1,0,0,0,0,1,1,0,0,1,1,0,1,0,1,0,0,0,1,1,1,0,0,0,0,0,0,1,0,1,1,0,1,1,1,1,0,0,0],
    [1,0,1,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,1,0,0,1,1,1,1,1,0,0,0,1,1,0,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1,1,1,1,0,1,1,1,0],
    [1,0,0,1,1,0,1,1,1,1,0,1,1,0,1,1,0,1,0,1,1,1,1,0,1,1,1,0,0,1,0,0,0,1,0,0,1,0,1,0,0,1,1,1,0,1,0,0,0,0,1,1,1,0,1,1,0,0,0,0,0,1,0,1],
    [1,1,0,1,0,0,1,0,0,0,1,0,1,1,1,1,0,0,0,1,1,0,1,0,0,1,0,0,1,0,0,1,0,0,0,1,0,0,1,1,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,1,1,1,0,0,0,0],
    [1,1,1,1,1,0,1,1,1,0,0,0,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,0,0,0,0,1,1,1,0,0,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1,0,0,1,1,1,1,1,1,0,0,0,1,1],
    [0,0,1,0,1,1,0,0,1,0,1,1,0,0,1,0,0,0,1,0,1,0,0,0,0,1,1,0,1,1,0,1,0,1,0,0,1,0,0,1,1,1,0,0,1,1,0,1,1,1,1,0,0,1,1,0,0,1,0,1,0,0,0,1],
    [0,0,0,0,1,0,1,0,0,0,0,1,0,1,1,1,0,0,0,0,0,1,1,1,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,1,0,1,0,1,1,1,1,0,1,0,0,0,1,1,1,1,0,1,1,1,1,1],
    [1,0,1,0,0,0,1,0,0,0,1,0,1,1,0,1,0,0,0,0,0,1,0,0,0,1,1,0,1,1,1,1,0,0,0,0,0,1,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,1,0,0,0,0],
    [0,1,0,1,0,0,0,0,0,1,1,0,0,1,1,1,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,0,0,1,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,1,0,1,1,1,1,0,1,0],
    [1,0,0,1,1,1,1,1,1,1,1,1,1,0,1,1,0,0,1,1,1,1,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,0,0,0,1,0,1,1,1,1,0,1,1,1,0,0,0,1,0,1,1,1,1,1,0,0,1,1],
    [0,0,1,0,1,1,0,1,0,1,1,1,1,0,0,0,0,1,0,0,0,1,0,0,1,1,1,1,0,0,1,1,0,0,1,1,0,0,0,0,0,1,1,0,1,0,0,1,1,0,0,0,0,0,1,1,0,1,1,1,0,1,0,0],
    [1,1,0,1,1,1,0,1,0,1,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,0,0,0,1,1,1,1,0,1,1,1,0,1,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,0],
    [0,1,0,0,0,1,1,0,1,0,0,1,0,1,0,1,1,1,1,1,0,1,0,1,0,1,0,0,1,1,1,0,1,0,0,0,1,0,0,1,1,1,0,1,1,1,1,0,1,1,0,0,1,0,0,1,1,0,1,0,1,0,1,1],
    [0,1,0,1,1,1,1,0,0,1,0,0,1,0,1,0,0,0,0,0,0,1,1,0,0,0,0,1,1,1,0,0,1,1,1,1,1,1,1,1,0,1,1,0,1,1,1,1,0,0,0,1,1,0,0,0,0,0,0,0,1,1,1,1],
    [1,1,1,1,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,0,0,1,0,1,0,1,0,1,1,0,0,1,1,0,0,1,1,0,1,0,0,0,0,1,1,0,1,0,0,1,1,0,1,0,1,0,0,1,1,0,0,0,0,0],
    [0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,1,1,0,0,0,1,1,0,0,1,1,1,1,0,0,1,0,1,0,0,0,1,0,1,0,0,1,1,0,0,1,1,1,1,0,1,1,0,1,1,0,1,0,1,1,1,0],
    [1,1,1,0,1,1,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,1,1,0,1,0,1,0,0,0,0,1,1,1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,0,0,0,0,1,0,1,1,0,1,1],
    [0,1,0,0,1,1,1,0,1,0,1,1,0,1,0,0,1,1,0,0,0,0,0,0,0,0,1,0,1,0,0,1,0,1,0,1,1,1,1,1,0,1,0,0,1,1,0,0,1,1,1,0,0,0,0,1,0,1,1,0,1,1,0,1],
    [0,1,1,1,0,0,0,1,0,1,1,1,0,0,1,1,0,0,0,0,0,1,0,1,1,0,0,0,1,1,1,1,1,0,0,0,0,1,1,0,1,0,1,1,1,1,0,1,0,1,1,0,1,0,0,1,0,0,1,0,0,0,1,0],
    [0,0,0,0,0,0,0,0,1,0,0,1,1,1,0,1,1,1,1,1,1,1,0,0,1,0,0,1,1,0,1,0,0,0,0,0,0,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,1,0,1,1,1,1,0,1,1,0,1,0],
    [1,1,0,1,0,1,0,1,0,0,1,0,0,1,0,1,1,1,1,1,0,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,1,1,1,1,1,1,0,1,0,1,0,0,1,0,1,1,1,0,0,1,0,0,0,0,0,0,0,1],
    [1,0,0,0,1,0,0,1,1,1,0,1,1,0,0,0,1,0,0,1,0,1,1,0,0,1,0,1,0,1,0,0,1,0,0,0,1,0,0,1,0,1,1,1,1,1,0,0,1,0,0,0,0,1,0,0,0,0,1,0,1,0,0,1],
    [1,0,0,1,0,0,0,1,1,1,1,0,0,1,0,1,0,1,1,1,1,0,1,1,0,1,0,1,0,1,0,1,1,1,1,1,0,1,1,1,1,0,1,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,0,0],
    [1,1,1,1,1,1,1,1,0,1,1,1,1,0,0,1,0,1,1,1,0,0,0,0,1,1,1,0,1,1,0,0,1,0,1,1,1,1,1,0,0,1,0,1,0,0,1,0,1,0,0,0,1,1,0,1,1,0,1,1,1,1,0,1],
    [0,1,1,0,1,1,0,1,0,1,1,1,0,0,1,0,0,0,1,1,0,0,0,1,1,0,1,0,1,1,1,1,0,1,0,0,1,0,0,1,0,1,0,1,0,1,1,1,0,0,1,1,1,1,1,0,1,1,0,1,0,1,1,0]
]
```

Bạn có thể đọc 2 bài writeup này trước
https://github.com/Warriii/CTF-Writeups/blob/main/NUS%20Greyhats/GreyCTFQualifiers2024Writeups/crypto_prg.md

https://greysome.github.io/2024/04/24/grey-ctf-quals-2024.html#mjx-eqn%3Aeq%3A4

Bài này đọc ra thì chả thấy có cách tấn công hay là định lý cao siêu gì, chỉ là lập một ma trận, sau đó sẽ lấy kết quả của output, sau đó lập hệ phương trình. Nếu có nghiệm thì sẽ trả về 1 còn lại thì là 0.

Vấn đề khó là cách để lập ra ma trận đó để mỗi khi mình có output thì sẽ có thể lập thành hệ phương trình luôn vì biến x được sử dụng nhiều lần và lặp lại nhiều trong vòng for, thế nên nó sẽ cộng dồn lại nếu như mình đặt theo ẩn

Bài này mình đã mò theo kiểu làm z3-solver chứ không dùng sage như 2 bài wu trên, tuy chậm hơn rất nhiều nhưng vẫn ra kết quả đúng và mình cũng học thêm chút về z3.

Trước tiên, mình sẽ tạo 192 ẩn sau đó chia ra cho 3 biến cần tìm là x, r, k. Vì có lúc cần r + k nên mình cho nó 1 biến luôn.

```python
vec = [BitVec(f'x{i}', 1) for i in range(192)]
x = vec[:64]
r = vec[64:128]
k = vec[128:]
r_k_sum = [r[i] + k[i] for i in range(64)]
```

Đoạn code này khiến mình mất thời gian nhất, vì mình chưa quen dùng ma trận trong z3, nhất là trong trường nguyên 2 nữa.

```python
M = []

for i in trange(128):
    eqn = 0
    for j in range(64):
        eqn += x[j]
    M.append(eqn)
    if i % 3 == 0:
        x = [(Sum([A[i, j] * x[j] for j in range(64)]) + r[i]) % 2 for i in range(64)]
    if i % 3 == 1:
        x = [(Sum([A[i, j] * x[j] for j in range(64)]) + k[i]) % 2 for i in range(64)]
    if i % 3 == 2:
        x = [(Sum([A[i, j] * x[j] for j in range(64)]) + r_k_sum[i]) % 2 for i in range(64)]

```

Tạo xong ma trận rồi, giờ mình mới kết nối với server, nhận giá trị đầu ra rồi bắt đầu tính toán thôi.

Full sốt không che cho anh em.

```python
from z3 import *
import numpy as np
from param import *
from tqdm import trange
from pwn import*

def bytes_to_bits(s):
    return list(map(int, ''.join(format(x, '08b') for x in s)))
def bits_to_bytes(b):
    return bytes(int(''.join(map(str, b[i:i+8])), 2) for i in range(0, len(b), 8))

A = np.array(A) % 2

vec = [BitVec(f'x{i}', 1) for i in range(192)]
x = vec[:64]
r = vec[64:128]
k = vec[128:]

r_k_sum = [r[i] + k[i] for i in range(64)]

print(x)
print(r_k_sum)
print(k)

M = []

for i in trange(128):
    eqn = 0
    for j in range(64):
        eqn += x[j]
    M.append(eqn)
    if i % 3 == 0:
        x = [(Sum([A[i, j] * x[j] for j in range(64)]) + r[i]) % 2 for i in range(64)]
    if i % 3 == 1:
        x = [(Sum([A[i, j] * x[j] for j in range(64)]) + k[i]) % 2 for i in range(64)]
    if i % 3 == 2:
        x = [(Sum([A[i, j] * x[j] for j in range(64)]) + r_k_sum[i]) % 2 for i in range(64)]

# io = process(["python3","server.py"])
io = remote("challs.nusgreyhats.org", (35101))
for round in range(100):
    io.recvuntil(b'Output: ')
    test_str = io.recvline().rstrip().decode()
    test_bits = bytes_to_bits(bytes.fromhex(test_str))
    out = np.array(test_bits)
    print(f'test_{round+1}: {test_str}')
    s = Solver()
    for i in trange(len(M)):
        s.add(M[i] == out[i])


    count = 0
    if s.check() == sat:
        # m = s.model()
        # result_x = ""
        # result_r = ""
        # result_k = ""
        # for i in range(64):
        #     result_x += str(m.evaluate(x[i], model_completion=True)) + " "
        #     result_r += str(m.evaluate(r[i], model_completion=True)) + " "
        #     result_k += str(m.evaluate(k[i], model_completion=True)) + " "
        # print(result_x)
        # print(result_r)
        # print(result_k)
        # print()
        io.sendline(b'1')
      
      
    else:
        io.sendline(b'0')
io.interactive()
```

Bạn cũng có thể in ra coi nghiệm như thế nào, vì chỉ có 2 giá trị nên có thể hệ này sẽ có rất nhiều nghiệm, có thế không giống như bạn test thử (vì mình thử rồi), nhưng nhỡ có một trường hợp trùng với ``true_random()`` thì sao nhỉ. Thui ra flag là vẫn ngon rồi hihihii.

**Flag: grey{Not_so_easy_to_construct_a_secure_PRG_LaQSqprzmTjBZs8ygMkGuw}**
