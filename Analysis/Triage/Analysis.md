
---

## Identification

```
Filename - wannacry.exe
File size - 0x3723293 
MD5 - 3983f0ebeec88b8005724a203ae27180
SHA1 - 9f34d48eae30b6da0a5c5297a873f989a49e10e8
SHA256 - ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9
```


## System info

```
File type - exe
Architecture - x86
Subsystem - Windows GUI
Compiler - Microsoft Visual C/C++ (12.00.9782) [C++]
linker - Microsoft Linker (6.00.8047)
Sections Count - 4
Time Date Stamp - Saturday, 20.11.2010 09:03:08 UTC
```

## Optional header

```
Size of Code - 0x9000
Size of Initialized Data - 0x383000
Size of Uninitialized Data - 0x0
Base of Code - 0x1000
Entry Point - 0x9A16
Image Base - 0x400000
Section/File Alignment - 0x1000/0x1000
Size of Image - 0x66b000

Data directory:
Export Directory - empty
Exception Directory - empty
TLS Directory - empty
.NET header - empty
```

## Sections

![](Sections%20info.png)

```Entropy
.headers - 0.72670
.text - 6.13459
.data - 6.10032
.rdata - 3.50362
.rsrc - 7.99523
.overlay - 4.65108
```

## Suspicious

```Suspicious_die
(Heur) Malware: Anomalous build info [May be infected, be careful!]  
(Heur) Packer: Generic [Section #3 (".rsrc") compressed + PE in resources + High entropy]  
Resource: PE32 [Alignment = 0x000320a4, Size = 0x0035a000]  
  
Archive: Zip (2.0) [encrypted, 55.8%, 36 files]  

Overlay: Binary [Alignment = 0x0038d000, Size = 0x1d]
```

## Another suspicious artifacts

1. Unusually large virtual size of **.data**.
```
.data:
RawSize    = 0x27000
VirtualSize = 0x30489C

SectionAlignment = 0x1000
FileAlignment    = 0x1000
```
`.data` has an unusually large virtual size compared with its raw size.

2. Size of rsrc is very big - 0x0035a000.

3. Analysis with HxD show two pe blobs in **.data section**.
   **First pe blob**:
   ![](First%20pe%20blob.png)
   ! Eventual size ~ 0x4000.
   
   **Second pe blob**:
   ![](Second%20pe%20blob.png)
   ! It is unpossible to measure size, as it gets confused with other data.
   
   
## Initial hypotheses

```
1. This sample could be a dropper based on:
   - Existence some blob in .rsrc.
   - Existence two pe blob in .data.
   - existence archive in sample.    

2. The large difference between .data RawSize and VirtualSize may indicate a significant runtime data area, large uninitialized data region, or memory used for dynamically generated/extracted content. This requires further investigation during static/reverse analysis.
   
3. Sample dont have a tls mechanism - so we can start analysis from entry point.
```
## Conslusions

```
1. Sample is executable.
2. Writing on c\c++.
3. 32-bit Windows GUI program.
4. Have few emdended blobs.
5. We can analysing starting with entry point (stripped tls).
```
