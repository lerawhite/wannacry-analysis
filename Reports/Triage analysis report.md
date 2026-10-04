
---
## 1. Identification

|Attribute|Value|
|---|---|
|Filename|`wannacry.exe`|
|File Size|`0x3723293`|
|MD5|`3983f0ebeec88b8005724a203ae27180`|
|SHA1|`9f34d48eae30b6da0a5c5297a873f989a49e10e8`|
|SHA256|`ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9`|

## 2. File Identification

|Attribute|Value|
|---|---|
|File Type|PE executable|
|Architecture|x86 / PE32|
|Subsystem|Windows GUI|
|Compiler|Microsoft Visual C/C++ 12.00.9782|
|Linker|Microsoft Linker 6.00.8047|
|Sections|4|
|Timestamp|20 November 2010, 09:03:08 UTC|

The sample is a 32-bit Windows GUI executable compiled with Microsoft Visual C/C++.

The PE timestamp is inconsistent with the malware's known 2017 activity and should therefore not be treated as a reliable indicator of compilation time.

## 3. Optional Header

|Attribute|Value|
|---|---|
|Size of Code|`0x9000`|
|Size of Initialized Data|`0x383000`|
|Size of Uninitialized Data|`0x0`|
|Base of Code|`0x1000`|
|Entry Point|`0x9A16`|
|Image Base|`0x400000`|
|Section/File Alignment|`0x1000 / 0x1000`|
|Size of Image|`0x66B000`|

The export, exception, TLS, and .NET directories are empty.

The absence of a TLS directory means no TLS callback-based execution path was identified during triage. Static and dynamic analysis can therefore begin from the PE entry point without accounting for a TLS callback executing before it.

## 4. Section Characteristics

|Section|Entropy|
|---|--:|
|`.headers`|0.72670|
|`.text`|6.13459|
|`.data`|6.10032|
|`.rdata`|3.50362|
|`.rsrc`|7.99523|
|Overlay|4.65108|

The `.rsrc` section has particularly high entropy, while both `.text` and `.data` also contain relatively high-entropy data.

The `.rsrc` section is unusually large and contains embedded executable content, making it a primary area of interest for subsequent static analysis.

## 5. Suspicious Characteristics

### Generic packing / compression indicators

Detection by DIE identified:

- Generic malware / anomalous build information.
    
- Generic packer characteristics associated with compressed resources and embedded PE content.
    
- A PE32 resource with size `0x35A000`.
    
- An encrypted ZIP archive containing 36 files.
    
- A 29-byte binary overlay.
    

These characteristics indicate that the executable contains substantial embedded or compressed content rather than consisting solely of its primary executable code.

### Unusually large `.data` virtual size

The `.data` section has a significant difference between its raw and virtual sizes:

```text
Raw Size:     0x27000
Virtual Size: 0x30489C
```

With a section alignment of `0x1000`, the large virtual size suggests that a considerable amount of memory is reserved for runtime data beyond the data physically stored in the file.

This characteristic warranted further investigation during reverse engineering.

### Embedded PE content

Hex-level inspection identified multiple PE-like structures inside the sample's `.data` section.

At least two PE blobs were identified:

- First PE blob: approximately `0x4000` bytes.
    
- Second PE blob: larger embedded structure whose exact boundary could not be reliably determined from the raw data alone.
    

The sample therefore contains multiple embedded executable structures in addition to the main PE image.

## 6. Initial Hypotheses

Based on triage, the following hypotheses were established for subsequent analysis:

1. **The sample may operate as a dropper or payload container.**
    
    - Large embedded PE resources.
        
    - Multiple PE-like structures in `.data`.
        
    - Embedded encrypted archive.
        
2. **The large `.data` virtual size may represent a substantial runtime data area.**
    
    - The difference between raw and virtual size suggests additional memory space used during execution.
        
    - Further reverse engineering was required to determine its actual purpose.
        
3. **Embedded resources may contain executable payloads or supporting components.**
    
    - The large `.rsrc` section and PE32 resource warranted resource extraction and analysis.
        
4. **No TLS-based execution mechanism was identified.**
    
    - Analysis could therefore begin directly from the PE entry point.
        

## 7. Triage Conclusions

The initial triage established that the sample is:

- A 32-bit Windows GUI executable.
    
- Compiled with Microsoft Visual C/C++.
    
- A PE executable containing multiple embedded data and executable structures.
    
- Characterised by a large `.rsrc` section with high entropy.
    
- Characterised by an unusually large `.data` virtual size.
    
- Associated with an encrypted ZIP archive and a small overlay.
    
- Free of a TLS directory, allowing the entry point to serve as the initial reverse-engineering focus.
    

The observed characteristics strongly justified deeper static and dynamic analysis of the entry point, resources, embedded PE structures, and runtime payload extraction mechanisms.