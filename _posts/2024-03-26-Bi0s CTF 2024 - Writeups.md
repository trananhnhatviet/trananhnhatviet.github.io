---
title: Bi0s CTF 2024 - Writeups
date: 2024-03-26 00-40-56
categories: [CTF]
tags: [cryptography,HTB]
image: /assets/image/bi0s.png
math: true
---


## Challengename

Source code của chall như sau

```python
from ecdsa.ecdsa import Public_key, Private_key
from ecdsa import ellipticcurve
from hashlib import md5
import random
import os
import json

flag = open("flag", "rb").read()[:-1]

magic = os.urandom(16)

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = ##REDACTED##
b = ##REDACTED##
G = ##REDACTED##

q = G.order()

def bigsur(a,b):
    a,b = [[a,b],[b,a]][len(a) < len(b)]
    return bytes([i ^ j for i,j in zip(a,bytes([int(bin(int(b.hex(),16))[2:].zfill(len(f'{int(a.hex(), 16):b}'))[:len(a) - len(b)] + bin(int(b.hex(),16))[2:].zfill(len(bin(int(a.hex(), 16))[2:]))[:len(bin(int(a.hex(), 16))[2:]) - len(bin(int(b.hex(), 16))[2:])][i:i+8], 2) for i in range(0,len(bin(int(a.hex(), 16))[2:]) - len(bin(int(b.hex(), 16))[2:]),8)]) + b)])

def bytes_to_long(s):
    return int.from_bytes(s, 'big')

def genkeys():
    d = random.randint(1,q-1)
    pubkey = Public_key(G, d*G)
    return pubkey, Private_key(pubkey, d)

def sign(msg,nonce,privkey):
    hsh = md5(msg).digest()
    nunce = md5(bigsur(nonce,magic)).digest()
    sig = privkey.sign(bytes_to_long(hsh), bytes_to_long(nunce))
    return json.dumps({"msg": msg.hex(), "r": hex(sig.r), "s": hex(sig.s)})

def enc(privkey):
    x = int(flag.hex(),16)
    y = pow((x**3 + a*x + b) % p, (p+3)//4, p)
    F = ellipticcurve.Point('--REDACTED--', x, y)
    Q = F * privkey.secret_multiplier
    return (int(Q.x()), int(Q.y()))

pubkey, privkey = genkeys()
print("Public key:",(int(pubkey.point.x()),int(pubkey.point.y())))
print("Encrypted flag:",enc(privkey))

nonces = set()

for _ in '01':
    try:
        msg = bytes.fromhex(input("Message: "))
        nonce = bytes.fromhex(input("Nonce: "))
        if nonce in nonces:
            print("Nonce already used")
            continue
        nonces.add(nonce)
        print(sign(msg,nonce,privkey))
    except ValueError:
        print("No hex?")
        exit()
```

Bây giờ, ta bị giấu mất các hệ số của đường cong, ta phải tìm lại được a, b, và điểm G.

Ta có được output như sau, mình lấy 1 trường hợp thui nha, tại netcat thì ra nhiều điểm khác nhau
7472616e616e68
6e6861747a69747474

```yaml
Public key: (62074580829368582344059231535288679141854304453511261626881417078003669760040, 226249697667264697300099616199091032472367422876468248704729481898424740978)
Encrypted flag: (80287585214899514117739968699898788173171686319245191029720093652663358176191, 78593019850865466334887789419596022034295179434341282152257703613890819344938)
Message: 7472616e616e68
Nonce: 00
{"msg": "7472616e616e68", "r": "0x8d3cb76e42b44cb553ade47f54317c1f924cb1f328422a403781e1bd7017d71d", "s": "0xe0ad72631b049d0461142c9af0fa605b588d0695be99d76c3320bae3fb3b8dcf"}
Message: 6e6861747a69747474
Nonce: 0000
{"msg": "6e6861747a69747474", "r": "0x8d3cb76e42b44cb553ade47f54317c1f924cb1f328422a403781e1bd7017d71d", "s": "0xf40567aae8f2a85d7b1c624cb9678a9377753fc4422f6fa0bb81f56de9cb0d5f"}

```

Thì ta được ta có 2 điểm trên đường cong, từ đó ta có được hệ như sau

$$y_1^2 = x_1^3 + ax_1 + b$$

$$y_2^2 = x_2^3 + ax_2 + b$$

Trừ 2 vế ta được:

$$(y_1^2 - y_2^2) = (x_1^3 - x_2^3) + a(x_1 - x_2)$$

Thay số vào rồi mình tìm được giá trị a nhaaa

Có được a rồi thì mình thay vào đường cong là sẽ thu được b nha

$$y_2^2 - x_2^3 - ax_2 = b$$

```yaml
sage: x1 = 62074580829368582344059231535288679141854304453511261626881417078003669760040
sage: y1 = 226249697667264697300099616199091032472367422876468248704729481898424740978
sage: x2 = 80287585214899514117739968699898788173171686319245191029720093652663358176191
sage: y2 = 78593019850865466334887789419596022034295179434341282152257703613890819344938
sage: p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
sage:
sage: ((y1^2 - y2^2)-(x1^3-x2^3))%p
54639013156592795321042211493830327093952145597201788208516029723979065248453
sage: inverse_mod(x1-x2,p)
110394729342389623135386530330724442026697300440596599519364760623105599517533
sage: (54639013156592795321042211493830327093952145597201788208516029723979065248453*110394729
....: 342389623135386530330724442026697300440596599519364760623105599517533)%p
115792089210356248762697446949407573530086143415290314195533631308867097853948
sage: a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
sage: b = y2^2 - x2^3 - a*x2
sage: n
<function numerical_approx at 0x7f8602cb4700>
sage: b
-517541509172278353837322976445306630893606020082443635100444562615446483964660266092691083682905263177697996252260475724215503247617815238531561262586484929690043313108695439871968309220258853078678068617527449419818350910053664095
sage: b%p
41058363725152142129326129780047268409114441015993725554835256314039467401291
sage: b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
sage: a,b
(115792089210356248762697446949407573530086143415290314195533631308867097853948,
 41058363725152142129326129780047268409114441015993725554835256314039467401291)
sage:
```

```yaml
a = 115792089210356248762697446949407573530086143415290314195533631308867097853948
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
```

Có a,b rồi, mình sẽ search trên google và được đường [**LINK**](https://neuromancer.sk/std/secg/secp256r1) này.

Từ đó mình có được các thông số của nó gồm:

```python
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a =
0 =xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
0 =xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
h = 0x1
```

Bài này thuộc dạng ECDSA with repeat Nonce, thì để repeat được nonce, ta chỉ cần nhập nonce thứ nhất là `00` và nonce thứ hai là `0000`. Từ đó, ta có thể làm theo như đường [**link**](https://crypto.stackexchange.com/questions/71764/is-it-safe-to-reuse-a-ecdsa-nonce-for-two-signatures-if-the-public-keys-are-diff) này

Ta có được 2 giá trị là $$r_1$$ $$s_1$$ $$r_2$$ $$s_2$$, với $$x_1$$ $$x_2$$ là private key, $$k$$ là nonce, thì ta có được rằng

$$s_1 = k^{-1}(H(m_1) + r_1x_1)$$

$$s_2 = k^{-1}(H(m_2) + r_2x_2)$$

Ta có được rằng
$$\frac{s_1}{s_2} = \frac{k^{-1}(H(m_1) + r_1x_1)}{k^{-1}(H(m_2) + r_2x_2)}
$$

$$\frac{s_1(H(m_2) + r_2x_2)}{s_2} = H(m_1) + r_1x_1$$

$$\frac{s_1(H(m_2) + r_2x_2) - s_2H(m_1)}{r_1s_2} = x_1$$

Giờ ta thay $$x_1$$ vào $$s_1 = k^{-1}(H(m_1) + r_1x_1)$$

$$s_1 = k^{-1}(h_1 + r_1\frac{s_1(h_2 + r_2x_2) - s_2h_1}{r_1s_2})
$$

Ta có hết tất cả giá trị rồi, giờ tìm lại $$x_2$$ thuiii, mình dựa vào code này để tìm lại được $$x_2$$

```python
from Crypto.Util.number import*
from hashlib import md5
from ecdsa.numbertheory import inverse_mod
s1 = 0xe0ad72631b049d0461142c9af0fa605b588d0695be99d76c3320bae3fb3b8dcf
s2 = 0xf40567aae8f2a85d7b1c624cb9678a9377753fc4422f6fa0bb81f56de9cb0d5f
r = 0x8d3cb76e42b44cb553ade47f54317c1f924cb1f328422a403781e1bd7017d71d
m1 = b"trananh"
m2 = b"nhatzittt"
messageHash1 = int((md5(m1).hexdigest()),16)
messageHash2 = int((md5(m2).hexdigest()),16)

numerator = (((s2 * messageHash1) % publicKeyOrderInteger) -
                 ((s1 * messageHash2) % publicKeyOrderInteger))
denominator = inverse_mod(
        r * ((s1 - s2) % publicKeyOrderInteger), publicKeyOrderInteger)

privateKey = numerator * denominator % publicKeyOrderInteger
print(privateKey)
```

Ta tìm được khóa $$d = 103753787388531709442718751260758444024424117994950490803615988887467390909036$$
Ta thấy rằng $$Encrypted flag = Private Key*Flag$$, thế nên, giờ ta chỉ cần inverse(privatekey, G.order()) rồi nhân lại với Encrypt Flag là thu được Flag thôiii

```python
Q = E(80287585214899514117739968699898788173171686319245191029720093652663358176191, 78593019850865466334887789419596022034295179434341282152257703613890819344938)
P = int(pow(privateKey,-1,publicKeyOrderInteger))*Q
print(P)
```

```python
(173877001943961524508797336940865009214794735500137102852359845041518430077 : 105483079702178112911417165737195582105029489466258484095154775234948912280405 : 1)
```

Flag là tọa độ x

**Flag: bi0sctf{https://bit.ly/3I0zwtG}**