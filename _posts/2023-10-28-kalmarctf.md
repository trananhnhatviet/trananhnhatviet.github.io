---
title: Kalmar CTF 2024 - Writeups
date: 2024-03-25 12:00:00
categories: [CTF]
tags: [cryptography,KalmarCTF]
image: /assets/image/meme.jpg
math: true
---
## Cracking Casino
Source code như sau

**Pedersen_commitments.py**

```python

from Crypto.Util.number import getStrongPrime
from Crypto.Random.random import randint

## Implementation of Pedersen Commitment Scheme
## Computationally binding, information theoreticly hiding

# Generate public key for Pedersen Commitments
def gen():
    q = getStrongPrime(1024)
    
    g = randint(1,q-1)
    s = randint(1,q-1)
    h = pow(g,s,q)

    return q,g,h

# Create Pedersen Commitment to message x
def commit(pk, m):
    q, g, h = pk
    r = randint(1,q-1)

    comm = pow(g,m,q) * pow(h,r,q)
    comm %= q

    return comm,r

# Verify Pedersen Commitment to message x, with randomness r
def verify(param, c, r, x):
    q, g, h = param
    if not (x > 1 and x < q):
        return False
    return c == (pow(g,x,q) * pow(h,r,q)) % q

```

**casino.py**
```python
#!/usr/bin/python3 
from Pedersen_commitments import gen, commit, verify


# I want to host a trustworthy online casino! 
# To implement blackjack and craps in a trustworthy way i need verifiable dice and cards!
# I've used information theoretic commitments to prevent players from cheating.
# Can you audit these functionalities for me ?

from random import randint
# Verifiable Dice roll
def roll_dice(pk):
    roll = randint(1,6)
    comm, r = commit(pk,roll)
    return comm, roll, r

# verifies a dice roll
def check_dice(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res

# verifiable random card:
def draw_card(pk):
    idx = randint(0,51)
    # clubs spades diamonds hearts
    suits = "CSDH"
    values = "234567890JQKA"
    value = values[idx%13]
    suit = suits[idx//13]
    card = value + suit
    comm, r = commit(pk, int(card.encode().hex(),16))
    return comm, card, r

# take a card (as two chars, fx 4S = 4 of spades) and verifies it was the committed card
def check_card(pk, comm, guess, r):
    res = verify(pk, comm, r, int(guess.encode().hex(),16))
    return res


# Debug testing values for larger values
def debug_test(pk):
    dbg = randint(0,2**32-2)
    comm, r = commit(pk,dbg)
    return comm, dbg, r

# verify debug values
def check_dbg(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res


def audit():
    print("Welcome to my (beta test) Casino!")
    q,g,h = gen()
    pk = q,g,h
    print(f'public key for Pedersen Commitment Scheme is:\nq = {q}\ng = {g}\nh = {h}')
    chosen = input("what would you like to play?\n[D]ice\n[C]ards")
    
    if chosen.lower() == "d":
        game = roll_dice
        verif = check_dice
    elif chosen.lower() == "c":
        game = draw_card
        verif = check_card
    else:
        game = debug_test
        verif = check_dbg

    correct = 0
    # If you can guess the committed values more than i'd expect, then 
    for _ in range(1337):
        if correct == 100:
            print("Oh wow, you broke my casino??!? Thanks so much for finding this before launch so i don't lose all my money to cheaters!")
            with open("flag.txt","r") as f:
                flag = f.read()
            print(f"here's that flag you wanted, you earned it! {flag}")
            exit()

        comm, v, r = game(pk)
        print(f'Commitment: {comm}')
        g = input(f'Are you able to guess the value? [Y]es/[N]o')
        if g.lower() == "n":
            print(f'commited value was {v}')
            print(f'randomness used was {r}')
            print(f'verifies = {verif(pk,comm,v,r)}')
        elif g.lower() == "y":
            guess = input(f'whats your guess?')
            if verif(pk, comm, guess, r):
                correct += 1
                print("Oh wow! well done!")
            else:
                print("That's not right... Why are you wasting my time if you haven't broken anything?")
                exit()

    print(f'Guess my system is secure then! Lets go ahead with the launch!')
    exit()

if __name__ == "__main__":
    audit()

```


```python
from pwn import *
from tqdm import trange
from randcrack import RandCrack

io = remote("chal-kalmarc.tf", 9)
io.sendline(b"a")

rc = RandCrack()

for i in trange(624):
	io.sendline(b"n")
	io.recvuntil(b"commited value was ")
	res = int(io.recvline())
	rc.submit(res)


for i in range(100):
	io.sendline(b"y")
	ans = rc.predict_randrange(0, 2**32 - 2)
	io.sendline(str(ans).encode())

io.interactive()
# Kalmar{First_Crypto_Down!}
```



Phân tích source code

Ta thấy rằng, hàm ``gen()`` sẽ sinh ra output gồm 3 số là $$q$$, $$g$$ và $$h$$
```python
def gen():
    q = getStrongPrime(1024)
    
    g = randint(1,q-1)
    s = randint(1,q-1)
    h = pow(g,s,q)

    return q,g,h
```


Sau đó, hàm sẽ lấy 1 số $$dbg$$ random trong $$[0, 2^{32} - 2]$ $sau đó $$commit(q,g,h,dbg)$$
```python
def debug_test(pk):
    dbg = randint(0,2**32-2)
    comm, r = commit(pk,dbg)
    return comm, dbg, r
    
def commit(pk, m):
    q, g, h = pk
    r = randint(1,q-1)

    comm = pow(g,m,q) * pow(h,r,q)
    comm %= q

    return comm,r
```

$$comm = (g^{dbg} \pmod{q} . h^{r} \pmod{q}) \pmod{q}$$


Và giờ ta phải nhập $guess$ để sao cho 

$$comm = (g^{guess} \pmod{q} . h^{r} \pmod{q}) \pmod{q}$$


```python
def check_dbg(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res


def verify(param, c, r, x):
    q, g, h = param
    if not (x > 1 and x < q):
        return False
    return c == (pow(g,x,q) * pow(h,r,q)) % q
```

Ta thấy rằng, $$dbg \in [0, 2^{32} - 2]$$, ngoài ra, ta có thể được thử 1337 lần và được biết giá trị của $$dbg$$ khi không đoán. Vì $$dbg$$ là số 32 bit, việc đoán lại seed rất dễ dàng. Ta sẽ sử dụng ``RANDCRACK`` để hoàn thành thử thách này
```python
from pwn import *
from tqdm import trange
from randcrack import RandCrack

io = remote("casino-2.chal-kalmarc.tf", 13337)
io.sendline(b"a")

rc = RandCrack()

for i in trange(624):
	io.sendline(b"n")
	io.recvuntil(b"commited value was ")
	res = int(io.recvline())
	rc.submit(res)


for i in range(100):
	io.sendline(b"y")
	ans = rc.predict_randrange(0, 2**32 - 2)
	io.sendline(str(ans).encode())

io.interactive()
```

**Flag: Kalmar{First_Crypto_Down!}**


## Re-Cracking Casino

```python
#!/usr/bin/python3 
from Pedersen_commitments import gen, commit, verify


# I want to host a trustworthy online casino! 
# To implement blackjack and craps in a trustworthy way i need verifiable dice and cards!
# I've used information theoretic commitments to prevent players from cheating.
# Can you audit these functionalities for me ?

# Thanks for the feedback, I'll use secure randomness then!
from Crypto.Random.random import randint
# Verifiable Dice roll
def roll_dice(pk):
    roll = randint(1,6)
    comm, r = commit(pk,roll)
    return comm, roll, r

# verifies a dice roll
def check_dice(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res

# verifiable random card:
def draw_card(pk):
    idx = randint(0,51)
    # clubs spades diamonds hearts
    suits = "CSDH"
    values = "234567890JQKA"
    value = values[idx%13]
    suit = suits[idx//13]
    card = value + suit
    comm, r = commit(pk, int(card.encode().hex(),16))
    return comm, card, r

# take a card (as two chars, fx 4S = 4 of spades) and verifies it was the committed card
def check_card(pk, comm, guess, r):
    res = verify(pk, comm, r, int(guess.encode().hex(),16))
    return res


# Debug testing values for larger values
def debug_test(pk):
    dbg = randint(0,2**32-2)
    comm, r = commit(pk,dbg)
    return comm, dbg, r

# verify debug values
def check_dbg(pk,comm,guess,r):
    res = verify(pk,comm, r, int(guess))
    return res


def audit():
    print("Welcome to my (Launch day!) Casino!")
    q,g,h = gen()
    pk = q,g,h
    print(f'public key for Pedersen Commitment Scheme is:\nq = {q}\ng = {g}\nh = {h}')
    chosen = input("what would you like to play?\n[D]ice\n[C]ards")
    
    if chosen.lower() == "d":
        game = roll_dice
        verif = check_dice
    elif chosen.lower() == "c":
        game = draw_card
        verif = check_card
    else:
        game = debug_test
        verif = check_dbg

    correct = 0
    
    # Should be secure now :)
    for _ in range(256):
        if correct == 250:
            print("Oh wow, you broke my casino again??!? That's impossible!")
            with open("flag.txt","r") as f:
                flag = f.read()
            print(f"here's that flag you wanted, you earned it! {flag}")
            exit()

        comm, v, r = game(pk)
        print(f'Commitment: {comm}')
        g = input(f'Are you able to guess the value? [Y]es/[N]o')
        if g.lower() == "n":
            print(f'commited value was {v}')
            print(f'randomness used was {r}')
            print(f'verifies = {verif(pk,comm,v,r)}')
        elif g.lower() == "y":
            guess = input(f'whats your guess?')
            if verif(pk, comm, guess, r):
                correct += 1
                print(correct)
                print("Oh wow! well done!")
            else:
                print("That's not right... Why are you wasting my time if you haven't broken anything?")
                exit()

    print(f'Guess my system is secure then! Lets go ahead with the launch!')
    exit()

if __name__ == "__main__":
    audit()

```

Chall này vẫn như cũ nhưng mà giảm số vòng xuống còn 256, và không thể dùng được randcrack.

Ta thấy rằng: $$comm = g^x * h^r \pmod{q} = g^{x + rs} \pmod{q}$$

Và ví dụ $$gcd(q-1,s) = p$$ với $$p$$ là một số nguyên tố, ta sẽ có được rằng
$$comm^{\frac{q-1}{p}} \pmod{q}= g^{(x+rs).\frac{q-1}{p}} \pmod{q}$$

$$\hspace{7.2cm}=g^{x.\frac{q-1}{p}} \pmod{q}.g^{rt(q-1)} \pmod{q}$$

$$\hspace{4cm}=g^{x.\frac{q-1}{p}} \pmod{q}.1$$


Và để check coi $$gcd(q-1,s) != 1$$ thì ta sẽ 

$$h^{\frac{q-1}{p}} \pmod{q} = g^{s.\frac{q-1}{p}} \pmod{q}$$

Nếu giá trị này bằng 1 thì tức $$gcd(q-1,s) != 1$$

Giờ ta sẽ chơi dice, rồi sẽ bruteforce giá trị từ 1 tới 6, nếu trùng với giá trị của comm thì ta sẽ gửi tới server thôi.

Mình cũng có test thử và được kết quả như sau
![image](https://hackmd.io/_uploads/rJkgjAaCa.png)

Thế nhưng, bài này có 1 bug hơi to, nếu mình chơi Dice thì sẽ chọn từ 1 tới 6, thế nhưng ở hàm **verify** thì lại như thế này
```python
def verify(param, c, r, x):
    q, g, h = param
    if not (x > 1 and x < q):
        return False
    return c == (pow(g,x,q) * pow(h,r,q)) % q
```

Vì thế, mỗi khi dice lăn vào 1 thì sẽ bị False, thế nên mình sửa thành $x > 0$ để làm bài này.

```python
from pwn import *
from Crypto.Random.random import randint
from Crypto.Util.number import sieve_base

while True:
    try:
        io = process(["python3", "casino.py"])
        # io = remote("casino-2.chal-kalmarc.tf", 13337)
        io.recvline()
        io.recvline()
        q = int(io.recvline().decode()[3:])
        g = int(io.recvline().decode()[3:])
        h = int(io.recvline().decode()[3:])
        io.recvuntil(b"[C]ards")
        io.send(b"D\n")
        divs = 1
        for p in sieve_base:
            if (q - 1) % p == 0 and p > 6:
                divs *= p
        d = (q - 1) // divs
        hd = pow(h, d, q)
        assert hd == 1
        gd = pow(g, d, q)
        assert gd != 1
        print("OK")
        break
    except:
        io.close()

for _ in range(256):
    io.recvuntil(b'Commitment:')
    comm = int((io.recvuntil(b'\n',drop=True)).decode())
    print(comm)
    commd = pow(comm, d, q)
    for i in range(1,7):
        if pow(gd, i, q) == commd:
            dice = i
    io.sendlineafter(b"[Y]es/[N]o", b"Y")
    io.sendlineafter(b"whats your guess?", str(dice).encode())
    io.recvuntil(b"\n")
io.interactive()    
```

**Flag: Kalmar{Why_call_it_strong_if_its_so_weak…}**