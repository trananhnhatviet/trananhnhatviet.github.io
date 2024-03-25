---
title: Bi0s CTF 2024 Challengename - Writeups
date: 2024-03-26 00-40-56
categories: [CTF]
tags: [cryptography,HTB]
image: /assets/image/bi0s.png
math: true
---

## LALALA

Source code của chall như sau:

```python
from random import randint
from re import search

flag = "bi0sctf{ %s }" % f"{randint(2**39, 2**40):x}"

p = random_prime(2**1024)
unknowns = [randint(0, 2**32) for _ in range(10)]
unknowns = [f + i - (i%1000)  for i, f in zip(unknowns, search("{(.*)}", flag).group(1).encode())]

output = []
for _ in range(100):
    aa = [randint(0, 2**1024) for _ in range(1000)]
    bb = [randint(0, 9) for _ in range(1000)]
    cc = [randint(0, 9) for _ in range(1000)]
    output.append(aa)
    output.append(bb)
    output.append(cc)
    output.append(sum([a + unknowns[b]^2 * unknowns[c]^3 for a, b, c in zip(aa, bb, cc)]) % p)

print(f"{p = }")
print(f"{output = }")
```

Ta thu được rất nhiều giá trị output, tận nhìu nhìu MB lận.

Phân tích bài này, ta thấy được rằng $$Unknown$$ gồm có 10 giá trị, ngoài ra còn có 100 vòng for bao gồm:

- Vòng for 0:
    Gồm 100 vòng for

  - $$aa_0 + unknown_{b_0}^{2}.unknown_{c_0}^{3} \pmod{p}$$

    ...

  - $$aa_{99} + unknown_{b_{99}}^{2}.unknown_{c_{99}}^{3} \pmod{p}$$

...

- Vòng for 99:
    Gồm 100 vòng for

  - $$aa_0 + unknown_{b_0}^{2}.unknown_{c_0}^{3} \pmod{p}$$

    ...

  - $$aa_{99} + unknown_{b_{99}}^{2}.unknown_{c_{99}}^{3} \pmod{p}$$

Ta phân tích vòng for 0, ta thấy rằng $b,c \in {[0,9]}$, thế nên vòng for đầu tiên sẽ bằng:

$$\text{hệ số}.unknown_{b_0}^{2}.unknown_{c_0}^{3} + \text{hệ số}.unknown_{b_0}^{2}.unknown_{c_1}^{3} + ... + \text{hệ số}.unknown_{b_1}^{2}.unknown_{c_0}^{3} + ... +\text{hệ số}.unknown_{b_9}^{2}.unknown_{c_9}^{3} + sum(aa) = result_0$$

Tương tự như thế, 100 vòng for ta sẽ có ma trận như sau:


<math xmlns="http://www.w3.org/1998/Math/MathML" display="block">
  <mrow data-mjx-texclass="INNER">
    <mo data-mjx-texclass="OPEN">[</mo>
    <mtable columnspacing="1em" rowspacing="4pt">
      <mtr>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <msub>
            <mi>f</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>0</mn>
          </msub>
        </mtd>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <msub>
            <mi>f</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>1</mn>
          </msub>
        </mtd>
        <mtd>
          <mo>.</mo>
          <mo>.</mo>
          <mo>.</mo>
        </mtd>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <msub>
            <mi>f</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>9</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>9</mn>
          </msub>
        </mtd>
      </mtr>
      <mtr>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <msub>
            <mi>f</mi>
            <mn>1</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>0</mn>
          </msub>
        </mtd>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <msub>
            <mi>f</mi>
            <mn>1</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>1</mn>
          </msub>
        </mtd>
        <mtd>
          <mo>.</mo>
          <mo>.</mo>
          <mo>.</mo>
        </mtd>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <msub>
            <mi>f</mi>
            <mn>1</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>9</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>9</mn>
          </msub>
        </mtd>
      </mtr>
      <mtr>
        <mtd>
          <mrow data-mjx-texclass="ORD">
            <mo>&#x22EE;</mo>
          </mrow>
        </mtd>
        <mtd>
          <mrow data-mjx-texclass="ORD">
            <mo>&#x22EE;</mo>
          </mrow>
        </mtd>
      </mtr>
      <mtr>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <msub>
            <mi>f</mi>
            <mrow data-mjx-texclass="ORD">
              <mn>99</mn>
            </mrow>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>0</mn>
          </msub>
        </mtd>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <mi>f</mi>
          <mrow data-mjx-texclass="ORD">
            <mn>99</mn>
          </mrow>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>0</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>1</mn>
          </msub>
        </mtd>
        <mtd>
          <mo>.</mo>
          <mo>.</mo>
          <mo>.</mo>
        </mtd>
        <mtd>
          <mi>c</mi>
          <mi>o</mi>
          <mi>e</mi>
          <mi>f</mi>
          <mi>f</mi>
          <mrow data-mjx-texclass="ORD">
            <mn>99</mn>
          </mrow>
          <mo>.</mo>
          <msub>
            <mi>b</mi>
            <mn>9</mn>
          </msub>
          <mo>.</mo>
          <msub>
            <mi>c</mi>
            <mn>9</mn>
          </msub>
        </mtd>
      </mtr>
    </mtable>
    <mo data-mjx-texclass="CLOSE">]</mo>
  </mrow>
  <mo>=</mo>
  <mrow data-mjx-texclass="INNER">
    <mo data-mjx-texclass="OPEN">[</mo>
    <mtable columnspacing="1em" rowspacing="4pt">
      <mtr>
        <mtd>
          <mi>r</mi>
          <mi>e</mi>
          <mi>s</mi>
          <mi>u</mi>
          <mi>l</mi>
          <msub>
            <mi>t</mi>
            <mn>0</mn>
          </msub>
          <mo>&#x2212;</mo>
          <mi>s</mi>
          <mi>u</mi>
          <mi>m</mi>
          <mo stretchy="false">(</mo>
          <mi>a</mi>
          <msub>
            <mi>a</mi>
            <mn>0</mn>
          </msub>
          <mo stretchy="false">)</mo>
        </mtd>
      </mtr>
      <mtr>
        <mtd>
          <mi>r</mi>
          <mi>e</mi>
          <mi>s</mi>
          <mi>u</mi>
          <mi>l</mi>
          <msub>
            <mi>t</mi>
            <mn>1</mn>
          </msub>
          <mo>&#x2212;</mo>
          <mi>s</mi>
          <mi>u</mi>
          <mi>m</mi>
          <mo stretchy="false">(</mo>
          <mi>a</mi>
          <msub>
            <mi>a</mi>
            <mn>1</mn>
          </msub>
          <mo stretchy="false">)</mo>
        </mtd>
      </mtr>
      <mtr>
        <mtd>
          <mrow data-mjx-texclass="ORD">
            <mo>&#x22EE;</mo>
          </mrow>
        </mtd>
      </mtr>
      <mtr>
        <mtd>
          <mi>r</mi>
          <mi>e</mi>
          <mi>s</mi>
          <mi>u</mi>
          <mi>l</mi>
          <msub>
            <mi>t</mi>
            <mn>9</mn>
          </msub>
          <mn>9</mn>
          <mo>&#x2212;</mo>
          <mi>s</mi>
          <mi>u</mi>
          <mi>m</mi>
          <mo stretchy="false">(</mo>
          <mi>a</mi>
          <msub>
            <mi>a</mi>
            <mn>9</mn>
          </msub>
          <mn>9</mn>
          <mo stretchy="false">)</mo>
        </mtd>
      </mtr>
    </mtable>
    <mo data-mjx-texclass="CLOSE">]</mo>
  </mrow>
</math>

Sau đó ta chỉ cần dùng hàm ``solve_right`` của sage là có thể tìm được 100 nghiệm từ $$unknown_{0}^{2}.unknown_{0}^{3}$$ tới $$unknown_{9}^{2}.unknown_{9}^{3}$$

Ta sẽ thu được 10 giá trị là $$unknown_{i}^5$$ với $$i \in {[0,9]}$$. Ta chỉ cần căn bậc 5 là thu được 10 giá trị $$unknown$$ nha.

Ta chỉ cần %1000 là sẽ thu được flag nha.

Hơi rắc rối tí nhưng mà bạn đọc code rùi sẽ hiểu nha.

```python
from out import*
from gmpy2 import iroot

Ma = []
Re = []

for i in range(0,len(output),4):
    row = [[0 for i in range(10)] for j in range(10)]
    aa = output[i]
    bb = output[i+1]
    cc = output[i+2]
    result = output[i+3]
    sum = 0
    for a, b, c in zip(aa,bb,cc):
        sum = (sum + a) % p
        row[b][c] +=1
    real_row = []
    for elements in row:
        for element in elements:
            real_row.append(element)
    Ma.append(real_row)
    Re.append(result - sum)

Mat = Matrix(GF(p), Ma)
Res = vector(GF(p), Re)
X = Mat^-1 *Res
# X = Mat.solve_right(Res)

data = []
lst = []
for i in range(100):
    lst.append(X[i])
    if len(lst) == 10:
        data.append(lst)
        lst = []

unknown = []
for i in range(10):
    unknown.append(int(str(iroot(int(data[i][i]),5)[0]).replace("mpz(","").replace(")","")))
print(unknown)

flag = ""
for i in unknown:
    flag += chr(i%1000)
    print(i%1000)
print("bi0sctf{" + flag + "}")
```

**Flag: bi0sctf{8d522ae1a7}**