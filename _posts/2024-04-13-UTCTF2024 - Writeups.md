---
title: UTCTF2024 - Writeups
date: 2024-04-13 19-23-28
categories: [CTF]
tags: [cryptography,UTCTF]
image: /assets/image/logo.png
math: true
---

# UTCTF2024

## RSA-256
**Flag: utflag{just_send_plaintext}**

## Beginner: Anti-dcode

```python
with open('LoooongCaesarCipher.txt','r') as file:
    data = file.read()
    
for key in range(1,26):
    encrypted_text = ""
    for char in data:
        if char.isalpha():
                shifted = ord('a') + (ord(char) - ord('a') - key) % 26
                encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    if "utflag{" in encrypted_text:
        with open("out","w") as file:
            file.write(encrypted_text)
```
**Flag: utflag{rip_dcode}**

## Bits and Pieces
```python
from Crypto.Util.number import *


n1 = 16895844090302140592659203092326754397916615877156418083775983326567262857434286784352755691231372524046947817027609871339779052340298851455825343914565349651333283551138205456284824077873043013595313773956794816682958706482754685120090750397747015038669047713101397337825418638859770626618854997324831793483659910322937454178396049671348919161991562332828398316094938835561259917841140366936226953293604869404280861112141284704018480497443189808649594222983536682286615023646284397886256209485789545675225329069539408667982428192470430204799653602931007107335558965120815430420898506688511671241705574335613090682013
e1 = 65537
c1 = 7818321254750334008379589501292325137682074322887683915464861106561934924365660251934320703022566522347141167914364318838415147127470950035180892461318743733126352087505518644388733527228841614726465965063829798897019439281915857574681062185664885100301873341937972872093168047018772766147350521571412432577721606426701002748739547026207569446359265024200993747841661884692928926039185964274224841237045619928248330951699007619244530879692563852129885323775823816451787955743942968401187507702618237082254283484203161006940664144806744142758756632646039371103714891470816121641325719797534020540250766889785919814382 
n2 = 22160567763948492895090996477047180485455524932702696697570991168736807463988465318899280678030104758714228331712868417831523511943197686617200545714707332594532611440360591874484774459472586464202240208125663048882939144024375040954148333792401257005790372881106262295967972148685076689432551379850079201234407868804450612865472429316169948404048708078383285810578598637431494164050174843806035033795105585543061957794162099125273596995686952118842090801867908842775373362066408634559153339824637727686109642585264413233583449179272399592842009933883647300090091041520319428330663770540635256486617825262149407200317
e2 = 65537
c2 = 19690520754051173647211685164072637555800784045910293368304706863370317909953687036313142136905145035923461684882237012444470624603324950525342723531350867347220681870482876998144413576696234307889695564386378507641438147676387327512816972488162619290220067572175960616418052216207456516160477378246666363877325851823689429475469383672825775159901117234555363911938490115559955086071530659273866145507400856136591391884526718884267990093630051614232280554396776513566245029154917966361698708629039129727327128483243363394841238956869151344974086425362274696045998136718784402364220587942046822063205137520791363319144 
n3 = 30411521910612406343993844830038303042143033746292579505901870953143975096282414718336718528037226099433670922614061664943892535514165683437199134278311973454116349060301041910849566746140890727885805721657086881479617492719586633881232556353366139554061188176830768575643015098049227964483233358203790768451798571704097416317067159175992894745746804122229684121275771877235870287805477152050742436672871552080666302532175003523693101768152753770024596485981429603734379784791055870925138803002395176578318147445903935688821423158926063921552282638439035914577171715576836189246536239295484699682522744627111615899081
e3 = 65537
c3 = 17407076170882273876432597038388758264230617761068651657734759714156681119134231664293550430901872572856333330745780794113236587515588367725879684954488698153571665447141528395185542787913364717776209909588729447283115651585815847333568874548696816813748100515388820080812467785181990042664564706242879424162602753729028187519433639583471983065246575409341038859576101783940398158000236250734758549527625716150775997198493235465480875148169558815498752869321570202908633179473348243670372581519248414555681834596365572626822309814663046580083035403339576751500705695598043247593357230327746709126221695232509039271637

p1 = 129984014749130366259742130443330376923069118727641845190136006048911945242427603092160936004682857611235008521722596025476170673607376869837675885556290582081941522328978811710862857253777650447221864279732376499043513950683086803379743964370215090077032772967632331576620201195241241611325672953583711295127
q1 = 129984014749130366259742130443330376923069118727641845190136006048911945242427603092160936004682857611235008521722596025476170673607376869837675885556290582081941522328978811710862857253777650447221864279732376499043513950683086803379743964370215090077032772967632331576620201195241241611325672953583711299819

q2 = 175136386393724074897068211302311758514344898633187862983126380556807924872210372704023620020763131468811275018725481764101835410780850364387004844957680252860643364609959757601263568806626614487575229052115194838589297358422557307359118854093864998895206960681533165623745478696564104830629591040860031236467
q3 = 175136386393724074897068211302311758514344898633187862983126380556807924872210372704023620020763131468811275018725481764101835410780850364387004844957680252860643364609959757601263568806626614487575229052115194838589297358422557307359118854093864998895206960681533165623745478696564104830629591040860031236467

p2 = n2//q2
p3 = n3//q3

d1 = inverse(e1,(p1-1)*(q1-1))
d2 = inverse(e2,(p2-1)*(q2-1))
d3 = inverse(e3,(p3-1)*(q3-1))

flag = long_to_bytes(pow(c1,d1,n1)) + long_to_bytes(pow(c2,d2,n2)) + long_to_bytes(pow(c3,d3,n3))
print(flag)
```
**Flag: utflag{oh_no_it_didnt_work_</3_i_guess_i_can_just_use_standard_libraries_in_the_future}**



## numbers go brrr

```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time

seed = int(time.time() * 1000) % (10 ** 6)
def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def encrypt(message):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    print(pad(message, AES.block_size))
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext.hex()

print("Thanks for using our encryption service! To get the encrypted flag, type 1. To encrypt a message, type 2.")
while True:
    print("What would you like to do (1 - get encrypted flag, 2 - encrypt a message)?")
    user_input = int(input())
    if(user_input == 1):
        break

    print("What is your message?")
    message = input()
    print("Here is your encrypted message:", encrypt(message.encode()))


flag = open('./src/flag.txt', 'r').read()
print("Here is the encrypted flag:", encrypt(flag.encode()))
```

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
from pwn import*

enc_mess = b'\x18o\xe0\x9d\xab\xbb\xddK\x7f[7\x84/\x1d\x01!'
enc_flag = b'\xb5\x8aE?6\x1c\x04N\xc8\xf8\x94\x17\xa4\xaaU\xdc\x0f\x08\xa5\x88\x8c\xf74\x9f\xe2\xaaI\xd6\xd0\x84T\x1e\x96\x80\t\xa0\xa3M6x\x82\xdf\xf5\x1c\xb7\xf4+!'

for i in range(993219,995495):
    new_seed = i
    key = b''
    for _ in range(8):
        ran_num = int(str(new_seed * new_seed).zfill(12)[3:9])
        key += (ran_num % (2 ** 16)).to_bytes(2, 'big')
        new_seed = ran_num
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(enc_mess)
    if b"aa" in plaintext:
        key = b''
        for _ in range(8):
            ran_num = int(str(new_seed * new_seed).zfill(12)[3:9])
            key += (ran_num % (2 ** 16)).to_bytes(2, 'big')
            new_seed = ran_num
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(enc_flag)
        print(plaintext)

```

**utflag{deep_seated_and_recurring_self-doubts}**

## numbers go brrr 2
```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import random

seed = random.randint(0, 10 ** 6)
def get_random_number():
    global seed 
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def encrypt(message):
    key = b''
    for i in range(8):
        key += (get_random_number() % (2 ** 16)).to_bytes(2, 'big')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return key.hex(), ciphertext.hex()


print("Thanks for using our encryption service! To get the start guessing, type 1. To encrypt a message, type 2.")
print("You will need to guess the key (you get 250 guesses for one key). You will do this 3 times!")

for i in range(3):
    seed = random.randint(0, 10 ** 6)
    print("Find the key " + str(i + 1) + " of 3!")
    key = encrypt(b"random text to initalize key")[0]
    while True:
        print("What would you like to do (1 - guess the key, 2 - encrypt a message)?")
        user_input = int(input())
        if(user_input == 1):
            break

        print("What is your message?")
        message = input()
        key, ciphertext = encrypt(message.encode())
        print("Here is your encrypted message:", ciphertext)
    print("You have 250 guesses to find the key!")
    
    found = False
    for j in range(250):
        print("What is your guess (in hex)?")
        guess = str(input()).lower()
        if guess == key:
            print("You found the key!")
            found = True
            break
        else:
            print("That is not the key!")

    if not found:
        print("You did not find the key!")
        exit(0)


flag = open('/src/flag.txt', 'r').read();
print("Here is the flag:", flag)


```

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import time
from pwn import*

# io = remote("betta.utctf.live",2435)
io = process(["python3","main.py"])


for _ in range(3):
    io.recvuntil(b'What would you like to do (1 - guess the key, 2 - encrypt a message)?\n')
    io.sendline(b'2')
    io.recvuntil(b'What is your message?\n')
    io.sendline(b'abcdefabcdef')
    io.recvuntil(b'Here is your encrypted message: ')
    enc_mess = io.recvuntil(b'\n',drop=True).decode()
    enc_mess = bytes.fromhex(enc_mess)

    for i in range(0,10**6):
        new_seed = i
        key0 = b''
        for _ in range(8):
            ran_num = int(str(new_seed * new_seed).zfill(12)[3:9])
            key0 += (ran_num % (2 ** 16)).to_bytes(2, 'big')
            new_seed = ran_num
        key1 = b''
        for _ in range(8):
            ran_num = int(str(new_seed * new_seed).zfill(12)[3:9])
            key1 += (ran_num % (2 ** 16)).to_bytes(2, 'big')
            new_seed = ran_num
        cipher = AES.new(key1, AES.MODE_ECB)
        plaintext = cipher.decrypt(enc_mess)
        if b"abcdefabcdef" in plaintext:
            print(key1.hex())
            break
    io.recvuntil(b'What would you like to do (1 - guess the key, 2 - encrypt a message)?\n')
    io.sendline(b'1')
    io.recvuntil(b'What is your guess (in hex)?\n')
    io.sendline(key1.hex().encode())
io.interactive()
```

## Cryptordle

```python
#!/usr/bin/env python3
import random

wordlist = open('filtered_words.txt', 'r').read().split('\n')

lst = []
for word in wordlist:
    if len(word) == 4:
        continue
    if len(word) == 5:
        for letter in word:
            assert letter in 'abcdefghijklmnopqrstuvwxyz'
        lst.append(word)
for word in lst:
    assert len(word) == 5
    for letter in word:
        assert letter in 'abcdefghijklmnopqrstuvwxyz'
        
        
for attempt in range(3):
    answer = random.choice(lst)
    num_guesses = 0
    while True:
        num_guesses += 1

        print("What's your guess?")
        guess = input().lower()

        assert len(guess) == 5
        for letter in guess:
            assert letter in 'abcdefghijklmnopqrstuvwxyz'

        if guess == answer:
            break

        response = 1
        for x in range(5):
            a = ord(guess[x]) - ord('a')
            b = ord(answer[x]) - ord('a')
            response = (response * (a-b)) % 31
        print(response)
    if num_guesses > 6:
        print("Sorry, you took more than 6 tries. No flag for you :(")
        exit()
    else:
        print("Good job! Onward...")

if num_guesses <= 6:
    print('Nice! You got it :) Have a flag:')
    flag = open('/src/flag.txt', 'r').read()
    print(flag)
else:
    print("Sorry, you took more than 6 tries. No flag for you :(")
```

```python
from pwn import*

io = process(["python3","main.py"])
for i in range(3):
    lst = []
    io.recvuntil(b"What's your guess?\n")
    io.sendline(b'abcde')
    lst.append(int(io.recvuntil(b'\n',drop=True).decode()))
    io.recvuntil(b"What's your guess?\n")
    io.sendline(b'fghij')
    lst.append(int(io.recvuntil(b'\n',drop=True).decode()))
    io.recvuntil(b"What's your guess?\n")
    io.sendline(b'klmno')
    lst.append(int(io.recvuntil(b'\n',drop=True).decode()))
    io.recvuntil(b"What's your guess?\n")
    io.sendline(b'pqrst')
    lst.append(int(io.recvuntil(b'\n',drop=True).decode()))
    io.recvuntil(b"What's your guess?\n")
    io.sendline(b'vwxyz')
    lst.append(int(io.recvuntil(b'\n',drop=True).decode()))
    lst_anser = []
    wordlist = open('filtered_words.txt', 'r').read().split('\n')
    for answer in wordlist:
        if len(answer) == 4:
            pass
        else:
            if len(answer) == 5:
                guesses = ["abcde", "fghij", "klmno", "pqrst", "vwxyz"]
                responses = []
                for guess in guesses:
                    response = 1
                    for x in range(5):
                        a = ord(guess[x]) - ord('a')
                        b = ord(answer[x]) - ord('a')
                        response = (response * (a - b)) % 31
                    responses.append(response)
                if responses == lst:
                    lst_anser.append(answer)
    io.recvuntil(b'\n')
    if len(lst) == 0:
        io.close()
    io.sendline(lst_anser[0].encode())
io.interactive()
```

**Flag: utflag{sometimes_pure_guessing_is_the_strat}**

## simple signature

![image](https://hackmd-prod-images.s3-ap-northeast-1.amazonaws.com/uploads/upload_55bcf9fa9f706f55179c49431b42e934.png?AWSAccessKeyId=AKIA3XSAAW6AWSKNINWO&Expires=1713011331&Signature=rxMDmu8AUWZiH3OaPO9ekgllW2g%3D)

**Flag: utflag{a1m05t_t3xtb00k_3x3rc153}**