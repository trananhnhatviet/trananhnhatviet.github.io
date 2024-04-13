---
title: TAMUCTF2024 - Writeups
date: 2024-04-13 15-43-38
categories: [CTF]
tags: [cryptography,TAMUCTF]
image: /assets/image/OIP.jpg
math: true
---

# TAMUctf 2024

## Truncated 1

Public Pem
```yaml
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA64u2qOSKwRf6GWPrq9ZX
uWqvooTq2uz/3obioiWMY2l2tLpi2Jgiq7F40t9QHLuIzcggU6bRH5Cn2gsh1DtE
UQYLMkszbp88akQqpPEa7t6leIqnT8Z4rFqj6sRpdYSQS8U2FzAzWDRvhY4oEliw
comX84WCVh8BKe38qOqN1QvhZVBY00JoUk2x/HBFNCA8VpEZIeTSKvH0Rc/Dzy5h
KoHBRaL8bBLYjhqO2PNfAkvHewJIqRyqtXXbedqqDn6vp9JX4lVcS5n/i95kQN98
JYn2RSuhTxk+v1ZHpEiSLImzc+9aOAPPtsikZPsah6JOnjDbhctfZGRn1MfFfzOd
UwIDAQAB
-----END PUBLIC KEY-----

```

Private Pem
```yaml
ZXPI0zfM5EJkeooRvNr3RKQEoQKBgQD0WrYbxhBveSRYvkOV0+omfutwS6wIoCme
CYCq5MboHdZn8NDCHy+Y66b+G/GMZJewqEKQSLwHcAjKHxouneFXp6AxV0rkBWtO
RNnjXfthsWXvOgBJzGm8CJQS+xVtUpYc4l1QnYaQpc0/SClSTPG775H5DnJ8t4rK
oNQur+/pcwKBgD1BU0AjW6x+GYPXUzA0/tXQpu5XaAMxkinhiiOJWT/AExzJU8Jt
eQULJ3EDENG6acSuwMhm0WMLhQ0JG6gIejRyOBZSIqjESWGHPmkU1XbUDz0iLb1h
HTqJMAWYKWJs4RnJbx6NGJAhd2Ni4CyOGmujYpqNnp1qfZNhmcj/VOeBAoGBAJgD
stU2c9UVlTIMM7mLG1kVjlzPBtha42ko2j32k3Ol1FPXcdfCVPcaa0ockjnX/rJt
CvP9+9PYs+8iSESF/cFtS/BGMRYH9Qi9NpwHRLMzDIo2GCXRIFpVL+FbCKp5PV/8
xza2uRdVvolG2EYWDjDvym0Zusmx2YtTYI0m8ObXAoGAZ6T8aF6GAZ0s814ZfEcy
zZGrZZQ/MJ7W8ZGdU1/y+204LzfGsW+d+sTPfQPYhn03/qU3SFhP095sYzELeOOZ
3yITOftHEdMP3XffnAudgn3tBHrtu0EsVFL44H7CWe4hx3M49M0lfERD60lPwUG1
8hY5qcthSko1f1WkTgN7Rrs=
-----END PRIVATE KEY-----

```

Ciphertext 
```yaml
714491305fdb5358db68f5ffd0e9a7dbedf55857c41d432549de5575f411d3d876663dbf958e70518b78ecdc5bad98dd9e52100b2a9fcdd6a7a14e1d532ae6d559943a5e8c64cdb673eb912ccb96dcfbfe99a289bc5c78c6dade4d7916f6c405420e02be90326b5fcea7cfac25cfdca27f9c1d709f4e19a282af583f23d58d21025601d912ffcde9e0c6c589bef3ddde713d193dba55342acc8d7268818063505873b673f8204584bbb91ee2406b3be8e24f68e33b8bd8bc7b849cd6cbff7801d68d3f107b5aba24d0e902b2281a0ef2f6ee5400b6df32215f15083c983e02291e752fe83fba54ecd4bb9f9184a1460ebd1710b3baf86a506e7ff9e3f929e9fd
```

Để giải bài này, bạn nên đọc 2 đường link sau đây [**Link 1**](https://lilthawg29.wordpress.com/2022/08/03/write-up-crypto-challenge-bro-key-n-uiuctf-2022/) [**Link 2**](https://blog.cryptohack.org/twitter-secrets)

Thì bài này, mình có chuyển hết các b64 kia ra thành hexa, thì mình được như thế này
```
6573c8d337cce442647a8a11bcdaf744a404a102818100f45ab61bc6106f792458be4395d3ea267eeb704bac08a0299e0980aae4c6e81dd667f0d0c21f2f98eba6fe1bf18c6497b0a8429048bc077008ca1f1a2e9de157a7a031574ae4056b4e44d9e35dfb61b165ef3a0049cc69bc089412fb156d52961ce25d509d8690a5cd3f4829524cf1bbef91f90e727cb78acaa0d42eafefe9730281803d415340235bac7e1983d7533034fed5d0a6ee576803319229e18a2389593fc0131cc953c26d79050b27710310d1ba69c4aec0c866d1630b850d091ba8087a347238165222a8c44961873e6914d576d40f3d222dbd611d3a8930059829626ce119c96f1e8d189021776362e02c8e1a6ba3629a8d9e9d6a7d936199c8ff54e781028181009803b2d53673d51595320c33b98b1b59158e5ccf06d85ae36928da3df69373a5d453d771d7c254f71a6b4a1c9239d7feb26d0af3fdfbd3d8b3ef22484485fdc16d4bf046311607f508bd369c0744b3330c8a361825d1205a552fe15b08aa793d5ffcc736b6b91755be8946d846160e30efca6d19bac9b1d98b53608d26f0e6d702818067a4fc685e86019d2cf35e197c4732cd91ab65943f309ed6f1919d535ff2fb6d382f37c6b16f9dfac4cf7d03d8867d37fea53748584fd3de6c63310b78e399df221339fb4711d30fdd77df9c0b9d827ded047aedbb412c5452f8e07ec259ee21c77338f4cd257c4443eb494fc141b5f21639a9cb614a4a357f55a44e037b46bb
```

![image](https://hackmd.io/_uploads/rJ6T5tWlR.png)

Như đã đọc ở các link trên, thì mình thu được một số là ``f45ab61bc6106f792458be4395d3ea267eeb704bac08a0299e0980aae4c6e81dd667f0d0c21f2f98eba6fe1bf18c6497b0a8429048bc077008ca1f1a2e9de157a7a031574ae4056b4e44d9e35dfb61b165ef3a0049cc69bc089412fb156d52961ce25d509d8690a5cd3f4829524cf1bbef91f90e727cb78acaa0d42eafefe973``. Thử check thì nó đúng là số nguyên tố thật =)))

Có được 1 số nguyên tố rồi thì factor lấy flag thôi

```python
from Crypto.Util.number import*

n = 29734896968835471849519668982209749626034019091045121453339204371033525547365934320858691041200454999076622505201136057407298827285395741532551534518463484678760035869990291983949525266914043458453940075436588024861403406949534792381108334145299173773264570084046647961072439989133604778249265945328909511017535287801325822208335050548292353849014700030433786853362747592975935470977637859711752376734809094538170961169739693665960562409901877803453161486673058941355274194631255810710502049768661315142732397148462212204222004648325598030904035645361477163752982132033922762048054507550272426225368721428080326057299
e = 65537
p = 0xf45ab61bc6106f792458be4395d3ea267eeb704bac08a0299e0980aae4c6e81dd667f0d0c21f2f98eba6fe1bf18c6497b0a8429048bc077008ca1f1a2e9de157a7a031574ae4056b4e44d9e35dfb61b165ef3a0049cc69bc089412fb156d52961ce25d509d8690a5cd3f4829524cf1bbef91f90e727cb78acaa0d42eafefe973
q = n//p

with (open('flag.txt.enc','rb')) as file:
    c = bytes_to_long(file.read())
d = inverse(65537,(p-1)*(q-1))
print(long_to_bytes(pow(c,d,n)))
```

**Flag: gigem{Q_Fr0M_Pr1V473_K3Y_89JD54}**

## Truncated 2

Private Pem
```
WXH2tecCgYBIlOn6LCaw4cYxztL4a+AgeoJ1HXB7AYg5Vl6T9VHfWW6dFvBVmaK/
sLuzAAZBOfOD3oXHk+BY2izOQamgOY5AvgW7m4JwP+gEFk9f9NdmI9DkxyD9cFzm
76zpeUiaizor1mMAd2mcCqjaYlDB3ohA0+Wvw024ZeBlDOCPgotJrQKBgFTU0ZgY
cNeZM05a5RdFJtKXnhTG7MdNe1lgD799tMBgSBw9OMg6pASOTGrUg6QW1DrsxY23
/ouePRFBh1OMArIskZf+Ov0jqD9umsM/q1XIR3ax3iOmBX6RxH42qyrHYArbv+tB
WdiwnYGJj5oE5HtnnL5pDa9qYFUfK4InhjN3AoGAZ2q2zPPhW9v75hq8fwVvLGjP
yDT4gGIz168dnCBLLMHsNv8y0twKQMY8UnqKBBIIkaC+j6zdCM+9CU3SEGC/TwQc
5iTOHmknFfuvRYN6WKOXbTQZJIx2aDHaRz4MZlpHOVFeHrmY9/s+y24U2nOG9kAC
zBzyXKI5PxT40b/mIGs=
-----END PRIVATE KEY-----

```

Public Pem
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy+KEz83nu2HZ1fy9jec/
twHw1bkdZJStKl9J2wIo21gvJmcr+VyUcozF8mJgZKTVBvu57GTd6PhcCjyqnbH3
KB63Nji2imT8DVzHaNVTBHu1c3jm/9dNBe6qp3SxSGozO00pE/27VOrEIRwM+595
kHIO7YKWfPbdXuSp5XyVAdX9+I1gtGNYLc+yjO5h5bwHm95Le0sW8/T/Sl2i/M5d
wlYwpidyBhIJ7WPKBcgiAe0etC9XKoA5JPmtv+U3BQ5k/75hGq6pL0vxYIS4WlU8
fij2aD3QooEQJyV+8dleXQ2q0MBKRPcQGLzuM6hFVc8DesPm3g84FiNeR+jdtNNQ
iwIDAQAB
-----END PUBLIC KEY-----

```

Ciphertext
```
8fc218616b26e118c01edc6bb761e61fd777acbf2b34cb03524c3296a15fb3710261488b2fc655476691de563d081d4a62fe071573a7f2b3951c5d9f807d2594d6971fd8f06e87e0ecb8a37bdaad0d5511f83510c2d9f242f98f8e8917c3441ea5b762d95827920fb095cfb2c421222bb3895d76f4563d7ec9b30aa0cda0907ca66e65e7c7fd99d808a8709062950041dd6568ecee50929aada3fad253b9d2e28bee328e03b9db418b22f3f3db83e827eeae10af860a1754f2efd58f15849a76a3f7217becb139c44027efa0a508e8c68739ef0dd8a51ae1434113f457d250a219449e43bfd461bf751929f1aef98b07b5573464a9dee18e7bf40244be4a340f
```

Ban nãy tìm bằng mắt mù mắt quá, giờ mình dùng code để tìm.

```python
from Crypto.Util.number import bytes_to_long, isPrime
import base64

def chia_doi_4_ky_tu(chuoi):
    return [chuoi[i:i+4] for i in range(0, len(chuoi), 4)]

privet_key1 = b"""WXH2tecCgYBIlOn6LCaw4cYxztL4a+AgeoJ1HXB7AYg5Vl6T9VHfWW6dFvBVmaK/
sLuzAAZBOfOD3oXHk+BY2izOQamgOY5AvgW7m4JwP+gEFk9f9NdmI9DkxyD9cFzm
76zpeUiaizor1mMAd2mcCqjaYlDB3ohA0+Wvw024ZeBlDOCPgotJrQKBgFTU0ZgY
cNeZM05a5RdFJtKXnhTG7MdNe1lgD799tMBgSBw9OMg6pASOTGrUg6QW1DrsxY23
/ouePRFBh1OMArIskZf+Ov0jqD9umsM/q1XIR3ax3iOmBX6RxH42qyrHYArbv+tB
WdiwnYGJj5oE5HtnnL5pDa9qYFUfK4InhjN3AoGAZ2q2zPPhW9v75hq8fwVvLGjP
yDT4gGIz168dnCBLLMHsNv8y0twKQMY8UnqKBBIIkaC+j6zdCM+9CU3SEGC/TwQc
5iTOHmknFfuvRYN6WKOXbTQZJIx2aDHaRz4MZlpHOVFeHrmY9/s+y24U2nOG9kAC
zBzyXKI5PxT40b/mIGs="""

data = ((base64.b64decode(privet_key1))).hex()
lst = chia_doi_4_ky_tu(data)
print(data)
x = []
for i in lst:
    if i not in x:
        x.append(i)
    else:
        print(i)
        
```

Mình thấy được có 2 byte đặc biệt là ``8180``, từ đó mình thấy được byte đặc biệt của nó là ``028180``

![image](https://hackmd.io/_uploads/r1tKnK-lA.png)


Mình thu được 3 đoạn có độ dài bằng nhau. Nghi ngờ là ``dp`` và ``dq``.
```
# 4894e9fa2c26b0e1c631ced2f86be0207a82751d707b018839565e93f551df596e9d16f05599a2bfb0bbb300064139f383de85c793e058da2cce41a9a0398e40be05bb9b82703fe804164f5ff4d76623d0e4c720fd705ce6eface979489a8b3a2bd6630077699c0aa8da6250c1de8840d3e5afc34db865e0650ce08f828b49ad
# 54d4d1981870d799334e5ae5174526d2979e14c6ecc74d7b59600fbf7db4c060481c3d38c83aa4048e4c6ad483a416d43aecc58db7fe8b9e3d114187538c02b22c9197fe3afd23a83f6e9ac33fab55c84776b1de23a6057e91c47e36ab2ac7600adbbfeb4159d8b09d81898f9a04e47b679cbe690daf6a60551f2b8227863377
# 676ab6ccf3e15bdbfbe61abc7f056f2c68cfc834f8806233d7af1d9c204b2cc1ec36ff32d2dc0a40c63c527a8a04120891a0be8facdd08cfbd094dd21060bf4f041ce624ce1e692715fbaf45837a58a3976d3419248c766831da473e0c665a4739515e1eb998f7fb3ecb6e14da7386f64002cc1cf25ca2393f14f8d1bfe6206b
```

Có được ``dp`` thì mình tìm lại được p rồi tìm flag thôi.

```python
from Crypto.Util.number import*

n = 25738076489477390048107389684996103882556969202513166288259522036337632736404168235030854616722305580161628671792338702584031628109920559959142086244929697000719839651284769225292474824312234101039383526660410096665677108899401181859913502426847877961086164703198858818644081120668614573404426468513602005820885294275008357193783600514925643269093575426795017766522751748746504263462858714066992146006524560800527477669712171172719903914727042988942644713692028132153937805550877286612258743238152980687480412165259102950423845139742038860174525053539636028083341480124394591958643772596948645492958078465902879395979

dp = 0x4894e9fa2c26b0e1c631ced2f86be0207a82751d707b018839565e93f551df596e9d16f05599a2bfb0bbb300064139f383de85c793e058da2cce41a9a0398e40be05bb9b82703fe804164f5ff4d76623d0e4c720fd705ce6eface979489a8b3a2bd6630077699c0aa8da6250c1de8840d3e5afc34db865e0650ce08f828b49ad

e = 65537
for kp in range(1,e):
    x = (e*dp-1)//kp+1
    if n%x == 0:
        print(x)
        break
p = x
q = n//p


with (open('flag.txt.enc','rb')) as file:
    c = bytes_to_long(file.read())
d = inverse(65537,(p-1)*(q-1))
print(long_to_bytes(pow(c,d,n)))
```

**Flag: gigem{DP_DQ_r54_7rUNC473D_SDA79}**

## Criminal

```python
from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20_Poly1305
from pathlib import Path
from zlib import compress

flag = Path("flag.txt").read_bytes()
key = get_random_bytes(32)

try:
    while True:
        append = input("Append whatever you want to the flag: ").encode()
        # gotta save on bandwidth!
        m = compress(flag + append)
        cipher = ChaCha20_Poly1305.new(key=key)
        cipher.update(m)
        c, tag = cipher.encrypt_and_digest(m)
        res = cipher.nonce + tag + c
        print(b64encode(res).decode())
except (KeyboardInterrupt, EOFError):
    pass

```


Chall này mình sẽ khai thác hàm compress của zlib. Mình cũng không có hiểu thuật toán của cái này lắm, nhưng mà, khi compress, hàm này sẽ rút gọn các ký tự gần nhau mà giống nhau. Bạn có thể chạy thử code này.

```python
from base64 import b64encode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20_Poly1305
from pathlib import Path
from zlib import compress

flag = Path("flag.txt").read_bytes()
key = get_random_bytes(32)

try:
    while True:
        append = input("Append whatever you want to the flag: ").encode()
        # gotta save on bandwidth!
        flag = b'gigem{Q_Fr0M_Pr1V473_K3Y_89JD54}'
        m = compress(flag + append)
        print(len(m))
        # cipher = ChaCha20_Poly1305.new(key=key)
        # cipher.update(m)
        # c, tag = cipher.encrypt_and_digest(m)
        # res = cipher.nonce + tag + c
        # print(b64encode(res).decode())
except (KeyboardInterrupt, EOFError):
    pass

```

![image](https://hackmd.io/_uploads/rJCB-c-l0.png)


Vì thế, ta sẽ bruteforce các ký tự, nếu ngắn hơn thì sẽ lấy nha.

```python
from pwn import*
from base64 import *

io = remote("tamuctf.com", 443, ssl=True, sni="criminal")

alpha = "{abcdefghijklmnopqrstuvwxyz_"

flag = b'}'
first_chr = b''
while first_chr != b'{':
    send = b';'+ flag
    out = send*4
    io.recvuntil(b'Append whatever you want to the flag: ')
    io.sendline(out)
    data = io.recvuntil(b'\n',drop=True).decode()
    data = base64.b64decode(data)
    for c in alpha:
        send = c.encode() + flag
        out = send*4
        io.recvuntil(b'Append whatever you want to the flag: ')
        io.sendline(out)   
        data2 = io.recvuntil(b'\n',drop=True).decode()
        data2 = base64.b64decode(data2)
        if len(data2) < len(data):
            flag =  c.encode()  +flag
            first_chr = c.encode()
            break
    print(flag)        
print(b'gigem' + flag)
```

**Flag: gigem{foiled_again}**

## pcg

```python
from secrets import randbelow
from Crypto.Util.number import getPrime
import sys

SIZE = 256
class PCG: # Polynomial Congruential Generator
    def __init__(self):
        self.m = getPrime(256)
        self.coeff = [randbelow(self.m-1) for _ in range(SIZE)]
        self.x = randbelow(self.m-1)
    def __call__(self):
        newx = 0
        for c in self.coeff:
            newx *= self.x
            newx += c
            newx %= self.m
        self.x = newx
        return self.x
    def printm(self):
        print(self.m)
        return
pcg = PCG()

print(pcg.m)
for i in range(SIZE*3):
    print(pcg())

sys.stdout.flush()
correct = True
for i in range(SIZE // 2):
    guess = int(input())
    if guess != pcg():
        correct = False

if correct:
    print(open('flag.txt','r').read())
else:
    print("you failed")
sys.stdout.flush()
```

Bài này thuộc dạng LCG, nhưng mà nó nâng cấp cải tiến hơn. Ban đầu, sẽ có 1 giá trị m là số nguyên tố, sau đó sẽ có 256 giá trị coeff cùng với đó là một giá trị $$x_0$$ ban đầu. Số m được công khai.

Sau đó, ta sẽ được 768 giá trị đầu ra của thuật toán sinh số này, tức là bạn sẽ có $$[x_1, x_2, ..., x_{768}]$$. 

Nhìn lại hàm ``__call__(self)``

```python
def __call__(self):
        newx = 0
        for c in self.coeff:
            newx *= self.x
            newx += c
            newx %= self.m
        self.x = newx
        return self.x
```

Bằng cách tính toán trên, ta sẽ được số $$x_1$$ như sau:

$$x_1 = (((newx*x_0) + c_0)*x_0+c_1)...$$

Mà $$newx = 0$$, từ đó ta được:

$$x_1 = (c_0*x_0+c_2)*x_0...$$

$$\iff x_1 = c_0*x_0^{255} + c_1*x_0^{254} + ...+ x_0*c_{254} + c_{255}$$

Từ đó, ta có được

$$ x_2 = c_0*x_1^{255} + c_1*x_1^{254} + ...+ x_1*c_{254} + c_{255}$$

$$ x_3 = c_0*x_2^{255} + c_1*x_2^{254} + ...+ x_2*c_{254} + c_{255}$$

$$ x_4 = c_0*x_3^{255} + c_1*x_3^{254} + ...+ x_3*c_{254} + c_{255}$$

$$ x_5 = c_0*x_4^{255} + c_1*x_4^{254} + ...+ x_4*c_{254} + c_{255}$$

$$..........$$

$$ x_{257} = c_0*x_{256}^{255} + c_1*x_{256}^{254} + ...+ x_{256}*c_{254} + c_{255}$$

Từ đó, ta sẽ có hệ phương trình

$$\begin{equation*}
    \begin{bmatrix}
        x_1^{255} & x_1^{254} & ... & x_1 & 1 \\
        x_2^{255} & x_2^{254} & ... & x_2 & 1 \\
        \vdots & \vdots \\
    x_{256}^{255} & x_{256}^{254} & ... & x_{256} & 1 \\
    \end{bmatrix}
    =
    \begin{bmatrix}
         x_2 \\
        x_3 \\
        \vdots  \\
        x_{257}
    \end{bmatrix}
\end{equation*}$$

Lưu ý, phải giải trong trường hữu hạn m.

```python
from pwn import *
from sage.all import *
from secrets import randbelow
from Crypto.Util.number import *

SIZE = 256
class PCG: # Polynomial Congruential Generator
    def __init__(self, m, coeff, x):
        self.m = m
        self.coeff = coeff
        self.x = x
    def __call__(self):
        newx = 0
        for c in self.coeff:
            newx *= self.x
            newx += c
            newx %= self.m
        self.x = newx
        return self.x
    def printm(self):
        print(self.m)
        return


io = remote("tamuctf.com", 443, ssl=True, sni="pcg")

vals = []
m = int(io.recvline())
SIZE = 256
for i in range(SIZE*3):
    vals.append(int(io.recvline()))
vals = vals[1:]

F = GF(m)
M = []
for i in range(256):
    x = vals[i]
    lst = []
    for j in range(SIZE):
        lst.append(F(x**(SIZE-1-j)))
    M.append(lst)
M = Matrix(F,M)

y = []
for i in range(SIZE):
    y.append(vals[i+1])
y = vector(F,y)

arr = M.solve_right(y)

pcg = PCG(m=m,coeff=arr,x=vals[-1])

for _ in range(256//2):
    io.sendline(str(pcg()).encode())
io.interactive()
```

**Flag: gigem{p0lyn0m1al5_4r3_funny}**


## qcg

```python
from secrets import randbelow

class QCG:
    def __init__(self):
        self.m = randbelow(pow(2,256)-1)
        self.a = randbelow(self.m-1)
        self.b = randbelow(self.m-1)
        self.c = randbelow(self.m-1)
        self.x = randbelow(self.m-1)
    def __call__(self):
        self.x = (self.a*self.x**2+self.b*self.x+self.c) % self.m
        return self.x
qcg = QCG()

for i in range(10):
    print(qcg())

correct = True
for i in range(5):
    guess = int(input())
    if guess != qcg():
        correct = False
if correct:
    print(open('flag.txt','r').read())
else:
    print("You failed")
```

Đây lại là một bài về LCG nhưng mà cải tiến hơn. Công thức tổng quát sẽ như sau

$$X_n = a*x_{n-1}^2 + b*x_{n-1} + c \mod m$$

Bài này khá giống bài trên, nhưng mà lại không có m, giờ ta phải tìm lại giá trị m của bài này.

Bài sẽ cho ta 10 giá trị của x. Sau đó sẽ phải đoán 5 lần tiếp theo. Giờ ta sẽ lợi dụng 10 giá trị kia để thực hiện crack.

Bài này sử dụng **Groebner basis** để tìm lại các giá trị ban đầu của bài này.

Bạn cũng có thể tham khảo đoạn code này.

```yaml
ZnJvbSBwd24gaW1wb3J0ICoKZnJvbSBzYWdlLmFsbCBpbXBvcnQgKgoKaW8gPSByZW1vdGUoInRhbXVjdGYuY29tIiwgNDQzLCBzc2w9VHJ1ZSwgc25pPSJxY2ciKQpzYW1wbGVzID0gW2ludChpby5yZWN2bGluZVMoKS5zdHJpcCgpKSBmb3IgXyBpbiByYW5nZSgxMCldCgpSLCAoYSwgYiwgYywgeCkgPSBaWlsnYSwgYiwgYywgeCddLm9iamdlbnMoKQpmID0gYSp4KioyICsgYip4ICsgYwoKIyB0aGUgcG9seW5vbWlhbHMgZ3JvdyBleHBvbmVudGlhbGx5IHNvIHdlIGRvbnQgdXNlIGFsbCAxMApuID0gNwpTID0gW3hdCmZvciBfIGluIHJhbmdlKG4pOiBTLmFwcGVuZChmKHg9U1stMV0pKQoKSSA9IFIuaWRlYWwoW1NbaV0gLSBzYW1wbGVzW2ldIGZvciBpIGluIHJhbmdlKG4pXSkKZm9yIG0gaW4gSS5ncm9lYm5lcl9iYXNpcygpOgogICAgaWYgbm90IG0uaXNfY29uc3RhbnQoKTogY29udGludWUKICAgIG0gPSBaWihtKQogICAgYnJlYWsKZWxzZTogZXhpdCgnOignKQoKIyB3aXRoIG0gcmVjb3ZlcmVkIHdlIGNhbiBqdXN0IExMTCB0byBmaW5kIGNvZWZmaWNpZW50cwpMID0gYmxvY2tfbWF0cml4KFpaLCBbCiAgICBbbWF0cml4KDMsIDksIGxhbWJkYSBpLCBqOiBzYW1wbGVzW2pdKippKSwgIGlkZW50aXR5X21hdHJpeCgzKSwgMF0sCiAgICBbaWRlbnRpdHlfbWF0cml4KDkpKm0sICAgICAgICAgICAgICAgICAgICAgIDAsICAgICAgICAgICAgICAgICAgMF0sCiAgICBbLW1hdHJpeChzYW1wbGVzWzE6XSksICAgICAgICAgICAgICAgICAgICAgIDAsICAgICAgICAgICAgICAgICAgMV0KXSkKClcgPSBkaWFnb25hbF9tYXRyaXgoW21dKjkgKyBbMV0qMyArIFttKioyXSkKCmZvciB2IGluIChMKlcpLkxMTCgpL1c6CiAgICBpZiBhYnModlstMV0pID09IDEgYW5kIGFsbCh4PT0wIGZvciB4IGluIHZbOjldKToKICAgICAgICB2ICo9IHNpZ24odlstMV0pCiAgICAgICAgYywgYiwgYSA9IFt4JW0gZm9yIHggaW4gdls5Oi0xXV0KICAgICAgICBicmVhawplbHNlOiBleGl0KCc6KCcpCgp4ID0gc2FtcGxlc1stMV0KZm9yIF8gaW4gcmFuZ2UoNSk6CiAgICB4ID0gKGEqeCoqMiArIGIqeCArIGMpICUgbQogICAgaW8uc2VuZGxpbmUoc3RyKHgpKQpwcmludChpby5yZWN2YWxsKCkuZGVjb2RlKCkuc3RyaXAoKSk=
```

Code này nên chạy nhiều lần vì có lúc không thể recover lại giá trị m.


```python
from pwn import * 

class QCG:
    def __init__(self, m, a, b, c, seed):
        self.m = m
        self.a = a
        self.b = b
        self.c = c
        self.x = seed
    def __call__(self):
        self.x = (self.a*self.x**2+self.b*self.x+self.c) % self.m
        return self.x


io = process(['python3','qcg.py'])

x_list = []
for i in range(10):
    x_list.append(int(io.recvline().strip()))

eqn = ''
for i in range(9):
    eqn += f'x_list[{i}]**2*a + x_list[{i}]*b  + c - x_list[{i+1}]' 
    if i != 8: 
        eqn += ','

P.<a,b,c> = PolynomialRing(ZZ,order='lex')
I = ideal(eval(eqn))

solved = I.groebner_basis()
m = int(solved[-1]) 
a = int(m-int(solved[0]-a))
b = int(m-int(solved[1]-b))
c = int(m-int(solved[2]-c))
seed = x_list[-1]

qcg = QCG(m,a,b,c,seed)

for i in range(5):
    io.sendline(str(qcg()).encode())
io.interactive()


```

**gigem{lcg_but_h4rd3r_101}**

## Emoji Group

```python
from secrets import multiply, g, identity, inverse, valid
from random import getrandbits

def power(p,x):
    out = identity
    while x:
        if x & 1:
            out = multiply(out,p)
        p = multiply(p,p)
        x >>= 1
    return out

def encrypt(msg,e):
    generator = power(g,e)
    out = generator
    for c in msg:
        out += power(generator,ord(c))
    return out

def decrypt(ct,d):
    chars = [power(g,i) for i in range(256)]
    plaintext = ""
    pt = power(ct[0],d)
    if pt != g:
        raise Exception("Invalid ciphertext")
    for c in ct[1:]:
        pt = power(c,d)
        plaintext += chr(chars.index(pt))
    return plaintext

print("Give me a message to encrypt:")
msg = input()
e = 0
while not valid(e):
    e = getrandbits(32)
ct = encrypt(msg,e)
print(f"Your cipher text is:",ct)
d = inverse(e)
print(f"The original message was:",decrypt(ct,d))

with open("flag.txt","r") as flag:
    e = 0
    while not valid(e):
        e = getrandbits(32)
    print("The flag is:",encrypt(flag.read(),e))
```

Bài này ban đầu mình khá là lăn tăn, tại bị ẩn nhiều hàm, thế nhưng, sau khi tham khảo solution của anh Quốc đzoai thì mình phát hiện ra một điều. Đó là, ciphertext sẽ luôn có 1 giá trị đầu là **Generator** ở đầu tiên. Giờ ta chỉ cần gửi hết các giá trị trong printable, sau đó sẽ thu được ciphertext bao gồm ``Gen + pow(gen,char)``. Nếu mà thu được flag mà có ký tự Gen mà giống gen trong ciphertext, ta có thể recover lại flag.

```python
from pwn import *

printable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}"

context.log_level = "error"

while True:
    conn = process(["python3","emoji_group.py"])
    conn.sendlineafter(b'encrypt:\n', printable.encode())
    conn.recvuntil(b'text is: ')
    ct = conn.recvline().decode().strip()  
    conn.recvuntil(b'flag is: ')
    flag = conn.recvline().decode().strip()

    if ct[0] == flag[0]:
        ct = ct[1:]
        flag = flag[1:]
        print("FOUND GEN")
        pt = ''
        for i in flag:
            try:
                pt += printable[ct.index(i)]
            except ValueError:
                pt += '_' 
        print(pt)
        break
    else:
        print("hello")

    conn.close()

```

**gigem{h0p3_y0u_d1dn7_s0lv3_by_h4nd}**


## Smooth Signature

```python
from Crypto.Util.number import getPrime,long_to_bytes,bytes_to_long
from math import lcm,gcd
from secrets import randbelow
from hashlib import sha256

NUM_BITS = 2048

def getModulus(bits):
    n = 1
    primes = []
    while n.bit_length() < bits:
        p = getPrime(24)
        if p not in primes:
            n *= p
            primes.append(p)
    return n,primes

def sign(n,msg,d):
    h = bytes_to_long(sha256(msg).digest())
    k = randbelow(q-2)+1
    x = pow(h,k,n)
    r = pow(x,d,n)
    s = pow(h+x,d,n)
    return r,s

def verify(n,msg,e,r,s):
    h = bytes_to_long(sha256(msg).digest())
    v1 = pow(r,e,n)
    v2 = pow(s,e,n)
    return v2 == (v1 + h) % n

n,primes = getModulus(NUM_BITS)

q = 1
for p in primes:
    q = lcm(q,p-1)
msgs = []
e = 65537
d = pow(e,-1,q)

print(f"The modulus is ... a mystery left for you to unfold. ")
print(f"Your verification exponent {e = }")
msg = input("Give the oracle a message to sign: ").encode()
msgs.append(msg)
r,s = sign(n,msg,d)
print(f"Your verification signature is ({r}, {s})")

msg = input("Give the oracle another message to sign: ").encode()
msgs.append(msg)
r,s = sign(n,msg,d)
print(f"Your second verification signature is ({r}, {s})")

comm = input("Ask the oracle a question: ").encode()
r,s = input("Give the verification signature: ").split(",")
r,s = int(r),int(s)

if comm in msgs:
    print("Hey, no cheating")
    exit()
if verify(n,comm,e,r,s):
    if comm == b"What is the flag?":
        print("The flag is: ",end="")
        with open("flag.txt","r") as flag:
            print(flag.read())
    else:
        print("Not the right question.")
else:
    print("Invalid signature")

```


Bài này, giá trị n là tích của nhiều số nguyên tố 24 bits. Ta thấy rằng, sẽ có hàm ``verify`` để check xem đúng sign không.

Ta có $$n = p_1*p_2*...p_n$$ để check = true thì:

$$\hspace{1.2cm}r^e + h(msg) = s^e \mod n$$

$$\iff r^e + h(msg)= s^e \mod p_i$$

Giờ ta chỉ cần brute tìm lại các giá trị p, sau đó chỉ cần nhân lại hết là sẽ thu lại được giá trị n. Còn nếu bạn muốn chắc chắn hơn thì có thể làm thế 2 lần, sau đó lấy gcd là được.

```python
from pwn import *
from hashlib import sha256
from Crypto.Util.number import *
from Crypto.Util.number import *
from math import lcm,gcd,prod
from secrets import randbelow


def verify(n,msg,e,r,s):
    h = bytes_to_long(sha256(msg).digest())
    v1 = pow(r,e,n)
    v2 = pow(s,e,n)
    return v2 == (v1 + h) % n

def sign(n,msg,d):
    h = bytes_to_long(sha256(msg).digest())
    k = randbelow(q-2)+1
    x = pow(h,k,n)
    r = pow(x,d,n)
    s = pow(h+x,d,n)
    return r,s

# io = remote("tamuctf.com", 443, ssl=True, sni="smooth-signatures")
io = process(['python3','smooth_signatures.py'])

e = 65537
msg = b'hello'
io.recvuntil(b'Give the oracle a message to sign: ')
io.sendline(msg)
io.recvuntil(b' is ')
r,s = eval(io.recvuntil(b'\n',drop=True).decode())
msg = b'hello'
io.recvuntil(b'Give the oracle another message to sign: ')
io.sendline(msg)
io.recvuntil(b' is ')
io.recvuntil(b'\n',drop=True)

primes = []
n = 1
for i in range(2**23,2**24):
    if verify(i,msg,e,r,s):
        primes.append(i)
        print("FOUND",i)
        n *= i
        if n.bit_length() >= 2048:
            print("DONE")
            break

q = 1
for p in primes:
    q = lcm(q,p-1)
e = 65537
d = pow(e,-1,q)
target = b'What is the flag?'
r_target, s_target = sign(n,target,d)

io.recvuntil(b'Ask the oracle a question: ')
io.sendline(target)
io.recvuntil(b'Give the verification signature: ')
io.sendline((str(r_target)+','+str(s_target)).encode())

io.interactive()
```

**Flag: gigem{sm00th_numb3rs_4r3_345y_70_f4c70r}**


## Jumbled

private.pem
```yaml
49 45 4e 42 47 2d 2d 2d 2d 2d 20 54 4b 41 45 49 50 56 20 52 0a 2d 4d 2d 0d 2d 59 2d 45 2d 44 42 41 49 41 76 49 41 49 45 47 6b 39 68 69 6b 42 71 4e 67 41 46 53 45 41 41 30 51 77 42 69 67 41 67 53 59 42 77 43 4b 51 42 43 49 41 41 45 6f 67 41 34 50 30 68 76 69 5a 46 71 4e 38 75 6f 4f 78 0d 4e 0a 48 6b 74 75 78 32 30 72 6a 37 50 67 69 59 2b 70 64 35 74 56 6b 50 44 39 74 66 2b 6e 77 31 66 47 79 50 77 6b 6f 6d 59 58 4f 72 51 31 59 79 6f 74 7a 6e 58 32 70 48 0d 54 36 4c 6b 36 55 2f 43 6b 45 33 5a 34 53 37 0a 6f 50 66 56 43 51 63 5a 44 7a 4a 63 6d 62 4a 36 31 6b 70 4d 70 6c 76 76 64 36 78 71 44 54 6c 2f 6a 74 6e 63 68 59 69 6b 4e 44 49 59 64 4c 79 42 41 71 53 79 0a 7a 0d 38 31 55 54 34 4b 56 50 30 61 6e 43 63 4c 6e 54 69 36 6e 75 6f 77 2f 70 53 37 7a 4c 50 76 63 62 67 4d 59 34 62 4d 58 4e 69 56 69 4f 48 76 4c 36 79 56 6a 6c 4f 56 77 65 49 32 4b 56 63 5a 32 74 77 31 38 75 2b 6f 63 68 0d 6a 30 0a 61 36 74 58 4e 34 5a 6e 79 6f 6b 32 68 64 6c 30 43 4f 61 2f 73 33 71 4e 56 36 4d 6a 34 36 52 72 38 67 61 46 30 34 57 73 62 4f 35 5a 42 47 65 69 57 6a 0a 66 2b 75 0d 76 42 69 49 49 6e 6f 6b 54 4a 31 4f 7a 69 6f 75 48 45 49 4a 63 34 4d 76 71 44 62 52 4b 50 42 65 4f 62 79 51 66 57 62 6d 4c 79 6b 41 74 59 2f 63 76 78 63 61 7a 2f 58 71 4a 59 4a 6b 61 4a 6c 36 64 36 78 2f 4f 74 0d 72 0a 71 56 41 42 45 4d 41 41 75 67 36 58 67 55 43 41 38 45 67 41 43 67 57 4b 69 47 2b 55 71 77 4c 53 47 74 79 49 72 61 65 6a 6f 33 78 6b 56 73 44 37 71 65 73 4d 2b 2f 0d 52 36 4d 2b 77 6a 6d 45 77 49 35 6e 47 5a 61 0a 74 64 77 5a 39 37 59 46 70 6b 33 2b 6b 72 4f 38 6b 45 6d 4f 2f 52 6e 63 47 6f 54 53 6f 53 63 33 4f 51 75 53 42 6c 67 65 42 64 42 5a 37 33 57 6e 48 75 31 58 0a 42 0d 75 74 51 6f 78 42 33 52 59 74 6a 71 2b 69 4e 72 42 41 49 52 6e 6a 36 78 4a 56 73 6f 49 31 6a 34 57 61 30 42 70 6d 4e 68 78 7a 70 46 2f 34 78 44 42 2b 71 57 59 6b 71 2f 61 39 47 48 37 57 69 4d 70 4c 32 68 43 51 52 55 0d 63 38 0a 56 2f 38 4f 45 30 4c 39 74 50 68 43 45 4e 74 49 44 31 46 43 43 6b 73 76 57 58 52 39 30 59 68 45 78 51 74 4e 45 39 44 62 55 4a 4b 79 4b 67 38 51 71 6c 0a 71 76 34 0d 59 4b 6c 61 33 73 4b 41 50 67 6a 62 34 32 61 41 4b 59 39 4a 78 48 39 4a 74 74 6b 73 30 59 58 44 70 6b 34 75 45 5a 6a 44 54 4b 4f 57 30 4a 31 78 31 51 68 53 42 50 63 7a 47 2b 52 39 68 71 5a 69 75 65 55 45 54 34 0d 65 0a 67 6f 2b 51 39 37 33 71 50 6a 47 58 58 49 46 71 4d 6a 4b 49 64 48 43 54 58 4a 2b 46 30 4b 45 2f 42 51 67 35 4b 32 5a 33 6e 55 42 74 64 2b 6a 6d 44 63 51 46 53 63 0d 2f 6a 66 77 62 55 4c 46 64 4b 6f 30 51 4d 38 0a 33 55 64 6c 34 42 49 56 45 52 34 7a 46 55 68 4c 4e 52 6a 79 50 46 52 41 68 44 53 7a 63 76 75 66 4d 2b 37 41 55 63 7a 52 4e 39 50 70 4d 2f 4d 42 63 45 41 63 0a 58 0d 4b 79 4b 50 6a 58 42 45 68 4b 49 71 61 6d 43 53 73 42 61 2f 69 55 4e 52 6a 4e 38 42 43 78 75 6f 4e 6b 62 6c 2b 67 66 6c 58 45 73 39 6f 75 33 4b 46 63 44 70 6d 35 38 62 4b 51 6d 31 57 68 6a 38 6e 71 48 4e 56 67 64 4c 0d 74 36 0a 6d 49 49 32 67 6e 6a 7a 48 37 77 70 4b 67 67 58 32 63 61 68 45 4a 68 77 6e 44 67 63 42 51 46 49 63 37 55 72 65 69 69 71 32 4b 78 7a 36 70 66 6e 34 45 0a 79 68 31 0d 36 54 43 74 67 69 4c 53 42 4b 71 55 74 43 6f 6e 36 52 34 74 5a 45 49 65 5a 2f 37 59 59 35 42 45 78 67 5a 62 68 50 4d 50 77 2b 76 71 6e 37 45 57 47 61 48 58 52 73 37 30 72 68 64 34 59 56 39 79 63 69 4e 4e 54 54 0d 4b 0a 31 73 54 6e 6c 34 30 75 77 65 72 66 5a 69 70 2f 38 75 64 76 69 47 30 51 42 64 44 30 78 69 36 53 2b 76 4a 70 49 58 36 72 4c 58 70 7a 69 53 31 56 6f 4b 44 55 39 4e 0d 75 76 4a 6f 39 64 52 64 72 58 45 78 53 75 72 0a 50 33 41 72 78 59 67 4b 42 51 42 50 6e 6b 65 51 74 6e 56 79 70 74 63 62 47 75 31 6a 6f 74 4b 4c 71 6a 42 63 66 43 45 30 73 4e 76 53 42 65 2b 61 51 48 7a 42 0a 73 0d 34 68 4e 79 6c 74 57 35 36 74 37 51 59 38 47 61 7a 69 73 59 5a 69 6b 7a 4a 70 43 59 64 44 63 37 58 79 77 32 45 32 6d 30 4d 7a 33 32 2b 56 63 51 36 74 69 59 67 37 37 44 72 75 42 73 74 4e 78 76 4d 6b 6a 4c 64 42 41 36 0d 59 70 0a 77 4e 42 6b 36 48 50 55 50 77 76 66 47 65 4e 47 4f 50 62 4f 69 69 56 2b 4c 78 32 73 58 35 74 4f 68 53 7a 6d 70 46 61 48 31 6b 41 43 41 68 31 51 30 44 0a 31 45 62 0d 62 47 69 6f 41 4a 41 66 65 74 6c 6c 63 36 56 62 58 4a 4f 42 39 54 48 53 65 4b 71 41 7a 63 4d 30 47 66 6c 36 74 6d 64 67 55 34 4a 62 71 36 4d 57 48 76 50 31 6b 56 78 5a 2f 54 72 76 6f 32 38 67 70 49 72 54 56 65 0d 7a 0a 43 64 37 31 78 50 54 31 69 66 50 50 77 67 62 46 35 75 56 52 6e 2b 2b 56 4f 5a 65 71 6d 53 73 76 41 38 39 56 6b 79 44 35 51 38 56 52 32 39 70 5a 33 6c 32 63 71 62 0d 45 7a 67 6b 6f 54 57 70 72 56 54 35 61 65 75 0a 6e 39 57 37 2b 46 66 54 6d 6a 42 74 30 42 46 37 44 48 4a 58 4b 6b 55 6b 76 37 62 67 6d 7a 4a 62 46 42 2b 64 41 67 7a 43 59 32 50 4a 4b 74 6a 5a 39 63 45 4c 0a 37 0d 68 72 4f 6c 31 38 4a 70 53 69 31 55 36 75 4a 65 65 37 74 32 79 6c 4c 67 6b 63 77 4c 76 71 53 41 46 50 78 6c 2f 52 2b 52 36 67 47 64 35 54 6b 2b 6d 74 4a 69 54 6c 74 2f 33 35 62 49 70 41 50 62 59 54 67 77 59 62 6a 77 0d 46 44 0a 58 2f 49 4c 4b 2b 69 44 68 77 68 71 68 73 71 73 62 35 45 52 4d 7a 54 36 46 42 7a 2b 41 67 2b 79 50 74 77 79 52 50 4b 38 72 59 76 6e 56 37 36 43 43 57 0a 65 70 56 0d 33 32 65 4e 61 46 6a 61 6b 53 44 6c 54 61 49 4f 52 74 77 37 37 79 6f 64 6a 2d 2d 2d 2d 2d 0d 3d 0a 51 3d 41 49 54 52 56 20 4e 50 45 44 2d 2d 2d 2d 2d 45 20 59 45 4b
```

public.pem
```yaml
2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 71 6d 54 59 68 59 54 37 2b 4e 42 7a 5a 44 72 73 66 4b 44 34 0d 0a 34 4b 2b 39 72 74 4c 63 5a 4c 54 2b 56 61 57 48 59 76 6e 38 42 70 39 58 2f 66 67 37 54 6d 4b 35 6c 35 44 36 4d 73 46 38 39 72 5a 38 74 61 45 47 46 4a 50 79 2b 6b 78 2b 71 55 71 4f 4f 39 35 47 0d 0a 51 68 4d 32 53 58 41 77 6e 30 44 31 54 4a 4b 64 61 53 5a 75 6e 47 30 36 70 63 51 33 62 2b 70 62 35 47 44 59 59 70 34 33 50 37 61 67 55 73 67 48 53 43 77 32 4f 46 43 74 55 2f 4d 73 35 33 45 77 0d 0a 69 32 6a 35 31 64 45 76 2b 38 4b 62 75 71 49 70 32 49 4f 47 7a 4c 79 33 4d 7a 78 34 72 31 54 6a 54 49 6d 31 38 44 6e 70 56 56 65 6f 79 38 73 4e 74 57 62 56 64 6e 43 43 74 49 59 36 4c 6e 50 50 0d 0a 73 6d 61 4f 4a 31 2b 6a 57 72 57 67 76 39 44 6e 64 70 5a 49 65 44 4f 75 6f 7a 64 31 62 4b 6c 74 4c 42 65 49 4b 32 6b 66 46 6e 6f 78 6f 6d 54 67 57 2b 53 41 53 4c 34 72 6e 2f 6f 6a 71 4e 63 30 0d 0a 36 43 5a 35 4c 2b 4b 6e 44 43 42 79 62 68 47 33 73 67 54 69 6d 7a 77 30 51 4d 72 53 35 47 33 35 6b 46 76 32 6c 33 4d 37 2f 38 57 48 4f 69 58 57 70 53 53 5a 4b 6d 4b 71 31 54 73 62 65 76 2b 72 0d 0a 6c 77 49 44 41 51 41 42 0d 0a 2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d
```


Thường thì ta thấy:
```yaml
-----BEGIN PRIVATE KEY-----
2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d
```

Và trong file private này:
```yaml
IENBG----- TKAEIPV R
-M-
-Y-E-
49 45 4e 42 47 2d 2d 2d 2d 2d 20 54 4b 41 45 49 50 56 20 52 0a 2d 4d 2d 0d 2d 59 2d 45 2d
```

Ta lấy 10 byte đầu:

```yaml
2d 2d 2d 2d 2d 42 45 47 49 4e
49 45 4e 42 47 2d 2d 2d 2d 2d
```

Từ này ta thấy được thứ tự:
```yaml
0 1 2 3 4 5 6 7 8 9
8 6 9 5 7 ? ? ? ? ?
```

Lấy 10 byte tiếp theo
```yaml
20 50 52 49 56 41 54 45 20 4b
20 54 4b 41 45 49 50 56 20 52
```

Từ đó ta lấy được tiếp thứ tự:
```yaml
0 1 2 3 4 5 6 7 8 9
8 6 9 5 7 3 1 4 0 2    
```

Giờ có full thứ tự rồi, giờ recover lại thôi nha.


```python
private = bytes.fromhex(("49 45 4e 42 47 2d 2d 2d 2d 2d 20 54 4b 41 45 49 50 56 20 52 0a 2d 4d 2d 0d 2d 59 2d 45 2d 44 42 41 49 41 76 49 41 49 45 47 6b 39 68 69 6b 42 71 4e 67 41 46 53 45 41 41 30 51 77 42 69 67 41 67 53 59 42 77 43 4b 51 42 43 49 41 41 45 6f 67 41 34 50 30 68 76 69 5a 46 71 4e 38 75 6f 4f 78 0d 4e 0a 48 6b 74 75 78 32 30 72 6a 37 50 67 69 59 2b 70 64 35 74 56 6b 50 44 39 74 66 2b 6e 77 31 66 47 79 50 77 6b 6f 6d 59 58 4f 72 51 31 59 79 6f 74 7a 6e 58 32 70 48 0d 54 36 4c 6b 36 55 2f 43 6b 45 33 5a 34 53 37 0a 6f 50 66 56 43 51 63 5a 44 7a 4a 63 6d 62 4a 36 31 6b 70 4d 70 6c 76 76 64 36 78 71 44 54 6c 2f 6a 74 6e 63 68 59 69 6b 4e 44 49 59 64 4c 79 42 41 71 53 79 0a 7a 0d 38 31 55 54 34 4b 56 50 30 61 6e 43 63 4c 6e 54 69 36 6e 75 6f 77 2f 70 53 37 7a 4c 50 76 63 62 67 4d 59 34 62 4d 58 4e 69 56 69 4f 48 76 4c 36 79 56 6a 6c 4f 56 77 65 49 32 4b 56 63 5a 32 74 77 31 38 75 2b 6f 63 68 0d 6a 30 0a 61 36 74 58 4e 34 5a 6e 79 6f 6b 32 68 64 6c 30 43 4f 61 2f 73 33 71 4e 56 36 4d 6a 34 36 52 72 38 67 61 46 30 34 57 73 62 4f 35 5a 42 47 65 69 57 6a 0a 66 2b 75 0d 76 42 69 49 49 6e 6f 6b 54 4a 31 4f 7a 69 6f 75 48 45 49 4a 63 34 4d 76 71 44 62 52 4b 50 42 65 4f 62 79 51 66 57 62 6d 4c 79 6b 41 74 59 2f 63 76 78 63 61 7a 2f 58 71 4a 59 4a 6b 61 4a 6c 36 64 36 78 2f 4f 74 0d 72 0a 71 56 41 42 45 4d 41 41 75 67 36 58 67 55 43 41 38 45 67 41 43 67 57 4b 69 47 2b 55 71 77 4c 53 47 74 79 49 72 61 65 6a 6f 33 78 6b 56 73 44 37 71 65 73 4d 2b 2f 0d 52 36 4d 2b 77 6a 6d 45 77 49 35 6e 47 5a 61 0a 74 64 77 5a 39 37 59 46 70 6b 33 2b 6b 72 4f 38 6b 45 6d 4f 2f 52 6e 63 47 6f 54 53 6f 53 63 33 4f 51 75 53 42 6c 67 65 42 64 42 5a 37 33 57 6e 48 75 31 58 0a 42 0d 75 74 51 6f 78 42 33 52 59 74 6a 71 2b 69 4e 72 42 41 49 52 6e 6a 36 78 4a 56 73 6f 49 31 6a 34 57 61 30 42 70 6d 4e 68 78 7a 70 46 2f 34 78 44 42 2b 71 57 59 6b 71 2f 61 39 47 48 37 57 69 4d 70 4c 32 68 43 51 52 55 0d 63 38 0a 56 2f 38 4f 45 30 4c 39 74 50 68 43 45 4e 74 49 44 31 46 43 43 6b 73 76 57 58 52 39 30 59 68 45 78 51 74 4e 45 39 44 62 55 4a 4b 79 4b 67 38 51 71 6c 0a 71 76 34 0d 59 4b 6c 61 33 73 4b 41 50 67 6a 62 34 32 61 41 4b 59 39 4a 78 48 39 4a 74 74 6b 73 30 59 58 44 70 6b 34 75 45 5a 6a 44 54 4b 4f 57 30 4a 31 78 31 51 68 53 42 50 63 7a 47 2b 52 39 68 71 5a 69 75 65 55 45 54 34 0d 65 0a 67 6f 2b 51 39 37 33 71 50 6a 47 58 58 49 46 71 4d 6a 4b 49 64 48 43 54 58 4a 2b 46 30 4b 45 2f 42 51 67 35 4b 32 5a 33 6e 55 42 74 64 2b 6a 6d 44 63 51 46 53 63 0d 2f 6a 66 77 62 55 4c 46 64 4b 6f 30 51 4d 38 0a 33 55 64 6c 34 42 49 56 45 52 34 7a 46 55 68 4c 4e 52 6a 79 50 46 52 41 68 44 53 7a 63 76 75 66 4d 2b 37 41 55 63 7a 52 4e 39 50 70 4d 2f 4d 42 63 45 41 63 0a 58 0d 4b 79 4b 50 6a 58 42 45 68 4b 49 71 61 6d 43 53 73 42 61 2f 69 55 4e 52 6a 4e 38 42 43 78 75 6f 4e 6b 62 6c 2b 67 66 6c 58 45 73 39 6f 75 33 4b 46 63 44 70 6d 35 38 62 4b 51 6d 31 57 68 6a 38 6e 71 48 4e 56 67 64 4c 0d 74 36 0a 6d 49 49 32 67 6e 6a 7a 48 37 77 70 4b 67 67 58 32 63 61 68 45 4a 68 77 6e 44 67 63 42 51 46 49 63 37 55 72 65 69 69 71 32 4b 78 7a 36 70 66 6e 34 45 0a 79 68 31 0d 36 54 43 74 67 69 4c 53 42 4b 71 55 74 43 6f 6e 36 52 34 74 5a 45 49 65 5a 2f 37 59 59 35 42 45 78 67 5a 62 68 50 4d 50 77 2b 76 71 6e 37 45 57 47 61 48 58 52 73 37 30 72 68 64 34 59 56 39 79 63 69 4e 4e 54 54 0d 4b 0a 31 73 54 6e 6c 34 30 75 77 65 72 66 5a 69 70 2f 38 75 64 76 69 47 30 51 42 64 44 30 78 69 36 53 2b 76 4a 70 49 58 36 72 4c 58 70 7a 69 53 31 56 6f 4b 44 55 39 4e 0d 75 76 4a 6f 39 64 52 64 72 58 45 78 53 75 72 0a 50 33 41 72 78 59 67 4b 42 51 42 50 6e 6b 65 51 74 6e 56 79 70 74 63 62 47 75 31 6a 6f 74 4b 4c 71 6a 42 63 66 43 45 30 73 4e 76 53 42 65 2b 61 51 48 7a 42 0a 73 0d 34 68 4e 79 6c 74 57 35 36 74 37 51 59 38 47 61 7a 69 73 59 5a 69 6b 7a 4a 70 43 59 64 44 63 37 58 79 77 32 45 32 6d 30 4d 7a 33 32 2b 56 63 51 36 74 69 59 67 37 37 44 72 75 42 73 74 4e 78 76 4d 6b 6a 4c 64 42 41 36 0d 59 70 0a 77 4e 42 6b 36 48 50 55 50 77 76 66 47 65 4e 47 4f 50 62 4f 69 69 56 2b 4c 78 32 73 58 35 74 4f 68 53 7a 6d 70 46 61 48 31 6b 41 43 41 68 31 51 30 44 0a 31 45 62 0d 62 47 69 6f 41 4a 41 66 65 74 6c 6c 63 36 56 62 58 4a 4f 42 39 54 48 53 65 4b 71 41 7a 63 4d 30 47 66 6c 36 74 6d 64 67 55 34 4a 62 71 36 4d 57 48 76 50 31 6b 56 78 5a 2f 54 72 76 6f 32 38 67 70 49 72 54 56 65 0d 7a 0a 43 64 37 31 78 50 54 31 69 66 50 50 77 67 62 46 35 75 56 52 6e 2b 2b 56 4f 5a 65 71 6d 53 73 76 41 38 39 56 6b 79 44 35 51 38 56 52 32 39 70 5a 33 6c 32 63 71 62 0d 45 7a 67 6b 6f 54 57 70 72 56 54 35 61 65 75 0a 6e 39 57 37 2b 46 66 54 6d 6a 42 74 30 42 46 37 44 48 4a 58 4b 6b 55 6b 76 37 62 67 6d 7a 4a 62 46 42 2b 64 41 67 7a 43 59 32 50 4a 4b 74 6a 5a 39 63 45 4c 0a 37 0d 68 72 4f 6c 31 38 4a 70 53 69 31 55 36 75 4a 65 65 37 74 32 79 6c 4c 67 6b 63 77 4c 76 71 53 41 46 50 78 6c 2f 52 2b 52 36 67 47 64 35 54 6b 2b 6d 74 4a 69 54 6c 74 2f 33 35 62 49 70 41 50 62 59 54 67 77 59 62 6a 77 0d 46 44 0a 58 2f 49 4c 4b 2b 69 44 68 77 68 71 68 73 71 73 62 35 45 52 4d 7a 54 36 46 42 7a 2b 41 67 2b 79 50 74 77 79 52 50 4b 38 72 59 76 6e 56 37 36 43 43 57 0a 65 70 56 0d 33 32 65 4e 61 46 6a 61 6b 53 44 6c 54 61 49 4f 52 74 77 37 37 79 6f 64 6a 2d 2d 2d 2d 2d 0d 3d 0a 51 3d 41 49 54 52 56 20 4e 50 45 44 2d 2d 2d 2d 2d 45 20 59 45 4b").replace(" ",""))

lst = [8, 6, 9, 5, 7, 3, 1, 4, 0, 2]

real_private = ""
for i in range(len(private)//10):
    byte_10 = private[10*i:10*i+10]
    print(byte_10)
    for j in lst:
        real_private += (chr(byte_10[j]))
print(real_private)
```

```yaml
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCqZNiFhPv40HNk
Oux8oPjgr72u0txktP5VpYdi+fwGn1f9+DtOYrmXkPoywXz2tny1oQYUk/L6TH6p
So473kZCEzZJcDCfQPVMkp1pJm6cbTqlxDdv6lvkYNhinjc/tqBSyAdILDY4UK1T
8yzncTCLaPnV0S/7wpu6oinYg4bMvLczPHivVONMibXwOelVV6jLyw21ZtV2cIK0
hjouc8+yZo4nX6NataC/0Od2lkh4M66jN3VsqW0sF4graR8WejGiZOBb5IBIviuf
+iOo1zToJnkv4qcMIHJuEbeyBOKbPDRAytLkbfmQW/aXczv/xYc6JdalJJkqYqrV
Oxt6/6uXAgMBAAECggEAAU8gCLqSUwGK+Wioe3ajItrGysqM7eskDxVj+mMwR/6+
ZtGa5wnEIkF3Yp9w7dZOE/kmOk8+rSScToGnoRcelBBguOS3Qun1WH7B3dZxQBto
uXBN+rqitRj3YJ6VjxRAnBI0WB4a1ojsI/p4zFhmxpNqY/Wk+DqxBpiLWMH97aG8
UcQhR2CtLP09O/EV8FDCI1NCthE0RYX9vkWCsDEbN9QEthxq8lgQyJKUKaK3Yl4q
v2baj4PKgsAJHtx99KJAYkD4Xp0kYtsWK0TOjEDuZPSchB11QJxiquhZRG9z+geo
TU4eEGPXqj7Q3+9dKHjIqIMXFE0/FKJT+CXnZU235QKBgQDFmc+tjBdUwLfb/cjS
M3Q8od0FKRV4IE4dBUlyRPNjhFLzUvzuSchRDFARcNUz7MAf+EBAMcMP/9pjKXyP
KcXCaSqmKEIBhjNNUR/BisabNlokxBu8CosuE9lgX+f8mbp5cKD3Fnjqh81QWKm6
LtgNdHVHj7nz2IgmIa2hXcgpgwKBgQDcwJnEhieqri7IUFc4fEpnzK62xtTg6C1y
hCUoqtBLKiSeEZZI46tnRgEZBxY75/Yq+nwvMhPbPsX7HRGEa7WyVcY9dr40h1Ks
TNTiNrwfue4n0TlidGuv/i8Zp6xS0idQD0BL6XXrpvI+JDoUVKSz1pidoRJ9uNv9
uPSrErxdXQKBgBxAY3rynptVenQPktjK1oGcutb0CsfEBqcLjHaz+QBveNSlNthy
4BsGYaQ8t57W6JkpizYiZzswX27yDYcCd+3Vz202MEm7gDY7tQic6MxkNvsutrBp
6YBLAjdPPwHUkN6wBbOOGPefNvGX25xs+iLiVapHmFSOzth01DhQCkA1AoGAbib1
E6lVlceAtJfSTe9HOXBbJf0lMGzqcKAb4qUJdtg6mV1xPkHMv6Wg2po8r/vZTCzd
VreITPiP1fP1T7xnV+uRFg5wbsmvqSZVe+OQD8y5V8kA923cZl9RpV2TkWgoEbzq
enauTr5pVjTBfm+WF97XHKDJF07tBzgJbmvU7kkCgYAz+FdbBcZEj9KPt2J1O8rl
hL7J6eUuip1JSkLclg27yetxFlAPqLSwv5GTgdRR6/+tT/ilt+JkmYPTAbI5p3bD
wFbwjgYhiw+DL/KXIEbRs5sqqhhAzgB+6zFMTKR8yPtyw+PC6W7CnYVrvN2a3eVe
palIDTkjSFadyj7owR7OtQ==
-----END PRIVATE KEY-----
```
```yaml
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqmTYhYT7+NBzZDrsfKD4
4K+9rtLcZLT+VaWHYvn8Bp9X/fg7TmK5l5D6MsF89rZ8taEGFJPy+kx+qUqOO95G
QhM2SXAwn0D1TJKdaSZunG06pcQ3b+pb5GDYYp43P7agUsgHSCw2OFCtU/Ms53Ew
i2j51dEv+8KbuqIp2IOGzLy3Mzx4r1TjTIm18DnpVVeoy8sNtWbVdnCCtIY6LnPP
smaOJ1+jWrWgv9DndpZIeDOuozd1bKltLBeIK2kfFnoxomTgW+SASL4rn/ojqNc0
6CZ5L+KnDCBybhG3sgTimzw0QMrS5G35kFv2l3M7/8WHOiXWpSSZKmKq1Tsbev+r
lwIDAQAB
-----END PUBLIC KEY-----
```

Giờ có hết rồi tìm lại flag thôi.

**Flag: gigem{jumbl3d_r54_pr1v473_k3y_z93kd74lx}**