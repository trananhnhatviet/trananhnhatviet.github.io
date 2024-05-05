---
title: UMASS CTF 2024 - Writeups
date: 2024-05-04 01-10-28
categories: [CTF]
tags: [cryptography,UMASS]
image: /assets/image/UMASS.png
math: true
---


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


## Reader exercise

```python
from Crypto.Util.number import *
from Crypto.Random.random import *


class Polynomial:
    def __init__(self, entries):
        self.entries = entries

    def __add__(self, other):
        if len(self.entries) < len(other.entries):
            return other + self
        return Polynomial(
            [x if y == 0 else (y if x == 0 else x + y) for x, y in zip(self.entries, other.entries)] +
            self.entries[len(other.entries):]
        )

    def __neg__(self):
        return Polynomial([-x for x in self.entries])

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, o):
        result = Polynomial([])
        for power in range(len(self.entries)):
            product = [0] * power + [self.entries[power] * y for y in o.entries]
            result = result + Polynomial(product)
        return result

    def __mod__(self, other):
        self.entries = [x % other for x in self.entries]
        return self

    def __str__(self):
        return str(self.entries)

    def __repr__(self):
        return str(self)

    def __call__(self, *args, **kwargs):
        start = 1
        s = self.entries[0]
        for i in self.entries[1:]:
            start *= args[0]
            s += i * start
        return s

    def degree(self):
        i = len(self.entries)
        while i > 0:
            i -= 1
            if self.entries[i] != 0:
                break
        return i


# Oh no this got corrupted :(
def gen_pair(deg, mod):

if __name__ == "__main__":
    with open("flag.txt", "r") as f:
        FLAG = f.read()
    size = 500
    base = 16
    degree = 8
    print(f"Gimme a sec to generate the prime...")
    while True:
        n = getPrime(size)
        if n % (base * 2) == 1:
            break
    print(f"n = {n}")

    p, q = gen_pair(degree, n)

    assert isinstance(p, Polynomial) and isinstance(q, Polynomial)
    assert p.degree() == degree
    assert q.degree() < p.degree()

    p_squared = p * p
    q_squared = q * q
    while True:
        decision = input("What would you like to do?\n")
        if decision == "challenge":
            challenge = int(input("I will never fail your challenges!\n"))
            proof = (p_squared(challenge) + q_squared(challenge)) % n
            assert proof == (pow(challenge, base, n) + 1) % n
            print(f"See? {proof}")
        elif decision == "verify":
            token = getRandomNBitInteger(size - 1) % n
            print("Here's how verification works: ")
            print(f"I give you:")
            print(f"token = {token}")
            print(f"You should give back:")
            print(f"p(token) = {p(token) % n}")
            print(f"q(token) = {q(token) % n}")

            print(f"Simple enough, right?")
            token = getRandomNBitInteger(size) % n
            print(f"token = {token}")
            p_attempt = int(input("p(token) = "))
            q_attempt = int(input("q(token) = "))
            assert p_attempt == p(token) % n and q_attempt == q(token) % n
            print("Great job!")
            print(FLAG)
            break
        else:
            print("Probably not that...")
```

Chall này đã giấu đi phần tạo đa thức, thế nên nếu chạy local thì không chạy được đâu.

Ta có rằng $$n = 32*k + 1$$.

p và q đều là các đa thức, p thì có bậc là 8, còn q thì thấp hơn 8.

Ngoài ra, ta có đoạn code này
```python
if decision == "challenge":
            challenge = int(input("I will never fail your challenges!\n"))
            proof = (p_squared(challenge) + q_squared(challenge)) % n
            assert proof == (pow(challenge, base, n) + 1) % n
            print(f"See? {proof}")
```

Từ đó ta có được rằng $$p^2(x) + q^2(x) \equiv x^{16} + 1 \mod n$$

Ta sẽ được các giá trị $$p(x)$$ và $$q(x)$$ với $$x$$ là giá trị được cho trước khi chọn mode verify.

Sau đó sẽ cho 1 giá trị $$x$$ ngẫu nhiên nữa, và ta phải tìm được $$p(x)$$ và $$q(x)$$.

Ta có, $$n = 32*k + 1$$ và n là số nguyên tố, ta có được nhóm cấp số nhân là 32k. Có nghĩa là, sẽ có 1 giá trị là $$w$$ sao cho $$w^{32} \equiv 1 \mod n$$ (primitive root of unity of order 32).

Từ đó có rằng $$w^{16} \equiv -1 \mod n$$ và $$(w^{16})^2 \equiv 1 \mod n$$. Từ đó ta có tiếp rằng:

$$(w^{2k+1})^{16} \equiv (w^{16})^{2k+1} \equiv -1^{2k+1} \equiv -1 \mod n$$

Lập phương trình $$x^{16} + 1 = 0$$, ta thấy được rằng, mọi giá trị $$w^{2k+1}$$ đều là nghiệm của phương trình trên (kể cả $$w^{2*(2k+1) + 1}$$). Từ đó ta có được biểu thức như sau:

$$x^{16} + 1  \equiv (x-w)(x-w^3)...(x-w^{31}) \mod n$$

$$p^2(x) + q^2(x) \equiv (x-w)(x-w^3)...(x-w^{31}) \mod n$$

Và giờ factor giá trị $$x^{16} + 1$$ làm sao. Sage lo tất, bạn chỉ cần code như này, nó sẽ factor trong vành số nguyên tố n.

```sage
n = 2294505405318355842228536139242959225512907322770136086190040085726899066287792493096830186073306083576178909384425871692714131370600330072123330577121

R.<x> = IntegerModRing(n)[]
l = factor(x^16 + 1)

```

Sau đó, ta đã có 16 phần tử như trên rồi, ta sẽ bruteforce 8 vòng for =))). Ta sẽ lựa chọn lần lượt 8 giá trị trong 16 giá trị đó.

```python
for i1 in range(0,16):
    for i2 in range(0,i1):
        for i3 in range(0,i2):
            for i4 in range(0,i3):
                for i5 in range(0, i4):
                    for i6 in range(0, i5):
                        for i7 in range(0, i6):
                            for i8 in range(0, i7):
                                pol = R('1')
                                pol2 = R('1')
                                choice = [i8, i7, i6, i5, i4, i3, i2, i1]
                                print(choice)
                                for i in range(16):
                                    if i in choice:
                                        pol*=R(l[i][0])    
                                    else:
                                        pol2*=R(l[i][0])
```

Thế pol2 thì sẽ có bậc 8 mất, phải làm sao đây. Đừng lo, để giảm bậc thì ta chỉ cần thêm 1 dòng lệnh này nữa.

```python
                                pol,pol2= pol+pol2,pol-pol2
```

Sau đó chỉ cần căn bậc 2 trong trường số nguyên tố là sẽ thu được đa thức p rồi.
```python
pol = pol * pow(2, -1, n)
print(pol)
```

Giờ ta chỉ cần lấy giá trị x, sau đó lấy giá trị p(x), sau đó ta sẽ bruteforce kiểm tra đa thức nào đúng, nếu đúng thì ta sẽ lấy token tiếp theo nhập vào là sẽ thu được flag. Vì có nhiều trường hợp, thế nên sẽ có lúc code chạy không ra flag. Thế nên hãy chạy nhiều lần nhóe.

```python
from pwn import*

io = process(["python3", "real_chal.py"])

io.recvuntil(b'n = ')
n = int(io.recvuntil(b'\n',drop=True).decode())

io.sendline(b'verify')

io.recvuntil(b'I give you:\n')
token = int(io.recvline().strip().split(b'token = ')[1].decode())

io.recvuntil(b'You should give back:\n')
pt = int(io.recvline().strip().split(b'p(token) = ')[1].decode())

io.recvuntil(b'Simple enough, right?\n')
new_token = int(io.recvline().strip().split(b'token = ')[1].decode())


R.<x> = IntegerModRing(n)[]
l = factor(x^16 + 1)

for i1 in range(0,16):
    for i2 in range(0,i1):
        for i3 in range(0,i2):
            for i4 in range(0,i3):
                for i5 in range(0, i4):
                    for i6 in range(0, i5):
                        for i7 in range(0, i6):
                            for i8 in range(0, i7):
                                pol = R('1')
                                pol2 = R('1')
                                choice = [i8, i7, i6, i5, i4, i3, i2, i1]
                                for i in range(16):
                                    if i in choice:
                                        pol*=R(l[i][0])    
                                    else:
                                        pol2*=R(l[i][0])
                                pol,pol2= pol+pol2,pol-pol2
                    
                                pol = pol * pow(2, -1, n)
                                val = pol(token)
                                if val == pt%n:
                                    print(pol)
                                    pval = (pol(new_token))%n
                                    qval = (pow(new_token, 16, n) + 1 - pow(pval, 2, n)) % n
                                    qval = Mod(qval, n).sqrt()
                                    io.recvuntil(b'p(token) = ')
                                    io.sendline(str(pval).encode())
                                    io.recvuntil(b'q(token) = ')
                                    io.sendline(str(qval).encode())
                                    
                                    io.recvline()
                                    io.interactive()
```

![image](/assets/image/UMASS3.png)

**Flag: UMASS{1n5p1r3d_6y_pu7n@m_b4_2007}**

Code để bạn chạy local đây nha.

```python
from Crypto.Util.number import *
from Crypto.Random.random import *


class Polynomial:
    def __init__(self, entries):
        self.entries = entries

    def __add__(self, other):
        if len(self.entries) < len(other.entries):
            return other + self
        return Polynomial(
            [x if y == 0 else (y if x == 0 else x + y) for x, y in zip(self.entries, other.entries)] +
            self.entries[len(other.entries):]
        )

    def __neg__(self):
        return Polynomial([-x for x in self.entries])

    def __sub__(self, other):
        return self + (-other)

    def __mul__(self, o):
        result = Polynomial([])
        for power in range(len(self.entries)):
            product = [0] * power + [self.entries[power] * y for y in o.entries]
            result = result + Polynomial(product)
        return result

    def __mod__(self, other):
        self.entries = [x % other for x in self.entries]
        return self

    def __str__(self):
        return str(self.entries)

    def __repr__(self):
        return str(self)

    def __call__(self, *args, **kwargs):
        start = 1
        s = self.entries[0]
        for i in self.entries[1:]:
            start *= args[0]
            s += i * start
        return s

    def degree(self):
        i = len(self.entries)
        while i > 0:
            i -= 1
            if self.entries[i] != 0:
                break
        return i


def gen_pair(deg, mod):
    while True:
        r = pow(getPrime(10), (n - 1) // (deg * 4), n)
        if pow(r, deg * 2, n) != 1:
            break
    piq = Polynomial([1])
    p_iq = Polynomial([1])
    inverse_2 = Polynomial([pow(2, -1, mod)])
    p_sign = Polynomial([1]) if randint(0, 1) == 1 else Polynomial([mod - 1])
    q_sign = Polynomial([1]) if randint(0, 1) == 1 else Polynomial([mod - 1])
    u = [Polynomial([pow(r, 2 * k + 1, mod), 1]) for k in range(deg * 2)]
    choices = sample(u, deg)
    for factor in u:
        if factor in choices:
            piq = piq * factor
        else:
            p_iq = p_iq * factor
    return ((piq + p_iq) * p_sign * inverse_2) % mod, ((piq - p_iq) * q_sign * inverse_2 * Polynomial([pow(r, deg, mod)])) % mod


if __name__ == "__main__":
    FLAG = "UMASS{1n5p1r3d_6y_pu7n@m_b4_2007}"
    size = 500
    base = 16
    degree = 8
    print(f"Gimme a sec to generate the prime...")
    while True:
        n = getPrime(size)
        if n % (base * 2) == 1:
            break
    print(f"n = {n}")
    p, q = gen_pair(degree, n)
    
    assert isinstance(p, Polynomial) and isinstance(q, Polynomial)
    assert p.degree() == degree
    assert q.degree() < p.degree()

    p_squared = p * p
    q_squared = q * q
    while True:
        decision = input("What would you like to do?\n")
        if decision == "challenge":
            challenge = int(input("I will never fail your challenges!\n"))
            proof = (p_squared(challenge) + q_squared(challenge)) % n
            assert proof == (pow(challenge, base, n) + 1) % n
            print(f"See? {proof}")
        elif decision == "verify":
            token = getRandomNBitInteger(size - 1) % n
            print("Here's how verification works: ")
            print(f"I give you:")
            print(f"token = {token}")
            print(f"You should give back:")
            print(f"p(token) = {p(token) % n}")
            print(f"q(token) = {q(token) % n}")

            print(f"Simple enough, right?")
            token = getRandomNBitInteger(size) % n
            print(f"token = {token}")
            p_attempt = int(input("p(token) = "))
            q_attempt = int(input("q(token) = "))
            assert p_attempt == p(token) % n and q_attempt == q(token) % n
            print("Great job!")
            print(FLAG)
            break
        else:
            print("Probably not that...")


```