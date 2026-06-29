# Serial Experiment Lain themed reverse engineering challenge - The Wired

<div align="center">
  
<img width="4096" height="1500" alt="image" src="https://github.com/user-attachments/assets/bd0851a0-ce4b-4cae-8510-8983455cdf60" />

</div>

## Challenge Info

* Name: The Wired
* OS: Linux
* Architecture: x86-64

## Goal

Authenticate into The Wired by providing the correct password.

---

<details>
  <summary>View Write-up</summary>

## The Wired Writeup 

## Initial Analysis

The binary is stripped:

```bash
thewired: ... stripped
```

Examining the binary with `readelf -SW` reveals several unusual custom sections:

```bash
.no_matter_where_you_go_everyone_is_connected
.im_real
.why_are_you_crying_lain
```

Running the binary without any arguments prints:

```bash
$ ./thewired
[-] The Wired is just a higher field of reality
```

The program also writes an image named `lain_is_here.png` to the current directory.

Running the binary with an argument triggers password validation:

```bash
$ ./thewired hi
[-] Incorrect Password
```

## Password Validation

Within Ghidra's decompiler (with edited variable names), the password check was identified as:

```c
password = strcmp(*(char **)(argv + 8), (char *)password_buf);
```

This indicates that the user-supplied argument is compared against a string stored in `password_buf`, which is 36 bytes long (including the null terminator):

```c
byte password_buf[36];
```

The program then checks whether `password` equals `0` (i.e., whether `strcmp()` returned a match). If the comparison succeeds, it performs an XOR operation on two memory regions before printing the authentication message:

```c
i = 0;
if (password == 0) {
    do {
        decrypted_msg[i] =
            (&key)[i % 12] ^
            (&DAT_00104060)[i];
        i = i + 1;
    } while (i != 173);

    decrypted_msg[0xac] = 0;
    printf("%s", decrypted_msg);
    goto EOF;
}
```

`&DAT_0012f758` appears to contain the XOR key because it is referenced in three separate decryption routines:

1. `password_buf[i] = (&DAT_0012f758)[i % 12] ^ (&DAT_00104120)[i];`
2. `decrypted_msg[i] = (&DAT_0012f758)[i % 12] ^ (&DAT_0012f6f0)[i];`
3. `decrypted_msg[i] = (&DAT_0012f758)[i % 12] ^ (&DAT_0012f720)[i];`

From this, we can hypothesize that the program stores several strings in encrypted form and decrypts them at runtime using a repeating 12-byte XOR key. This likely includes the password buffer as well as the various status messages displayed during execution.

The `password_buf[i]` is held in `&DAT_00104120` memory location:

```
index  address     value (hex)  char
0      0x00104120  0x59         Y
1      0x00104121  0x02         .
2      0x00104122  0x31         1
3      0x00104123  0x14         .
4      0x00104124  0x42         B
5      0x00104125  0x1A         .
6      0x00104126  0x3A         :
7      0x00104127  0x1E         .
8      0x00104128  0x1C         .
9      0x00104129  0x1F         .
10     0x0010412A  0x0A         .
11     0x0010412B  0x31         1
12     0x0010412C  0x5D         ]
13     0x0010412D  0x02         .
14     0x0010412E  0x1C         .
15     0x0010412F  0x1C         .
16     0x00104130  0x4F         O
17     0x00104131  0x1A         .
18     0x00104132  0x3A         :
19     0x00104133  0x17         .
20     0x00104134  0x0B         .
21     0x00104135  0x19         .
22     0x00104136  0x0A         .
23     0x00104137  0x1C         .
24     0x00104138  0x47         G
25     0x00104139  0x0A         .
26     0x0010413A  0x0B         .
27     0x0010413B  0x1B         .
28     0x0010413C  0x5A         Z
29     0x0010413D  0x05         .
30     0x0010413E  0x3A         :
31     0x0010413F  0x1E         .
32     0x00104140  0x12         .
33     0x00104141  0x00         .
34     0x00104142  0x01         .
35     0x00104143  0x6E         n
```

Encrypted password:

```c
0x59, 0x02, 0x31, 0x14, 0x42, 0x1A, 0x3A, 0x1E,
0x1C, 0x1F, 0x0A, 0x31, 0x5D, 0x02, 0x1C, 0x1C,
0x4F, 0x1A, 0x3A, 0x17, 0x0B, 0x19, 0x0A, 0x1C,
0x47, 0x0A, 0x0B, 0x1B, 0x5A, 0x05, 0x3A, 0x1E,
0x12, 0x00, 0x01, 0x6E
```

## Key Validation

Within the .text section holds 4 data segments, one of them being the same data segment for the key (`DAT_0012f758`):

```c
  _DAT_0012f758 = DAT_0012f6ca;
  _DAT_0012f75c = DAT_0012f6ce;
  _DAT_0012f75e = DAT_0012f6c4;
  _DAT_0012f762 = DAT_0012f6c8;
```

Further analyzing the data segments within the disassembler, it is shown to also have 12 bytes meaning that this is the key (probably built during runtime):

```
                     DAT_0012f6c4                                   
0012f6c4 65 72 73 69     undefined4 69737265h
                    DAT_0012f6c8                                   
0012f6c8 6f 6e           undefined2 6E6Fh
                    DAT_0012f6ca                                   
0012f6ca 2e 67 6e 75     undefined4 756E672Eh
                    DAT_0012f6ce                                   
0012f6ce 2e 76           undefined2 762Eh
```

Decryption Key:

```c
0x2e, 0x67, 0x6e, 0x75, 0x2e, 0x76,
0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e
```

## Decryption

Bash script:

```bash
#!/usr/bin/env bash
python3 <<'PY'
data = bytes([
    0x59, 0x02, 0x31, 0x14, 0x42, 0x1A, 0x3A, 0x1E,
    0x1C, 0x1F, 0x0A, 0x31, 0x5D, 0x02, 0x1C, 0x1C,
    0x4F, 0x1A, 0x3A, 0x17, 0x0B, 0x19, 0x0A, 0x1C,
    0x47, 0x0A, 0x0B, 0x1B, 0x5A, 0x05, 0x3A, 0x1E,
    0x12, 0x00, 0x01, 0x6E
])

key = bytes([
    0x2e, 0x67, 0x6e, 0x75, 0x2e, 0x76,
    0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e
])

out = bytearray(len(data))

for i in range(len(data)):
    out[i] = data[i] ^ key[i % len(key)]

print("BYTES:", list(out))

print("ASCII:", out.decode(errors="replace"))
PY
```

Output:

```bash
$ ./script.sh 
BYTES: [119, 101, 95, 97, 108, 108, 95, 108, 111, 118, 101, 95, 115, 101, 114, 105, 97, 108, 95, 101, 120, 112, 101, 114, 105, 109, 101, 110, 116, 115, 95, 108, 97, 105, 110, 0]
ASCII: we_all_love_serial_experiments_lain
```

## Anti-debugging Technique

Also, within .text section there are indications of an anti-debugging technique implementation that detects any placement of INT 3 (0xCC) within `FUN_00101380` (i.e. authentication logic function).

```c
  do {
    if (FUN_00101380[*plVar1] == (code)0xcc) {
      ...
      do {
        ...
      }
```

## Solution

**we_all_love_serial_experiments_lain**

```bash
$ ./thewired we_all_love_serial_experiments_lain
================================
          THE WIRED             
================================

ACCESS GRANTED

Welcome to The Wired.

Everyone is connected.

[ONLINE]
```

## Future Improvements

The binary has several weaknesses in how it attempts to protect its logic. The key is stored in a way that’s effectively recoverable as plain text, which makes it easy to extract and use for decrypting the data. On top of that, even though there is an anti-debugging check in place, it doesn’t really prevent static analysis, since everything can still be fully reconstructed just by inspecting the binary.

</details>
