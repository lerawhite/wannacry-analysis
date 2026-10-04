
---
## 1. Scope

This stage of the investigation focused on the static examination of three primary sources of evidence:

- imported modules and functions;
    
- extracted strings;
    
- PE resources and embedded content.
    

The objective was not to reconstruct individual execution paths at the instruction level, but to identify the sample's potential capabilities, establish relationships between different static artifacts, and develop behavioral hypotheses for subsequent deep reverse engineering.

The complete raw outputs are preserved in:

```text
Dumps/Static/
├── Raw_Imports&Functions(DIE)
├── Raw_strings_(DIE).txt
└── Resourses(DIE).md
```

---

# 2. Imported Modules and Functions

The sample imports functionality from the following system modules:

```text
KERNEL32.dll
ADVAPI32.dll
WS2_32.dll
MSVCP60.dll
iphlpapi.dll
WININET.dll
MSVCRT.dll
```

The imported APIs indicate several distinct capability groups.

### File and Resource Handling

`KERNEL32.dll` provides APIs for file access and resource management, including:

```text
CreateFileA
ReadFile
GetFileSize
MoveFileExA
FindResourceA
LoadResource
LockResource
SizeofResource
```

This combination is significant because the resource section contains an embedded PE component. The imports therefore provide a plausible API-level mechanism for accessing embedded data and subsequently interacting with files on disk.

At the static stage, this establishes a **candidate resource-extraction and file-deployment path**, but does not by itself establish how the APIs are connected during execution.

### Dynamic API Resolution

The presence of:

```text
GetModuleHandleA
GetModuleHandleW
GetProcAddress
```

indicates that the sample is capable of resolving exported functions dynamically at runtime.

This is particularly relevant because some networking functionality expected from `WS2_32.dll` was not represented as conventional imports by the PE analysis tools. Dynamic resolution is therefore one possible explanation for the discrepancy, although parser limitations or non-standard import representation cannot be excluded at this stage.

### Threading and Synchronization

The imported synchronization primitives include:

```text
InitializeCriticalSection
EnterCriticalSection
LeaveCriticalSection
InterlockedIncrement
InterlockedDecrement
```

along with execution-management functions such as:

```text
GetCurrentThread
GetCurrentThreadId
WaitForSingleObject
Sleep
TerminateThread
ExitProcess
```

This combination indicates that the sample contains infrastructure for concurrent execution and shared-state management.

The imports alone do not identify the exact worker architecture, but they provide an early indication that multithreaded execution should be investigated during reverse engineering.

### Memory Management

The sample imports:

```text
LocalAlloc
LocalFree
GlobalAlloc
GlobalFree
```

indicating dynamic memory allocation and deallocation.

Given the presence of embedded PE data, these APIs represent a plausible mechanism for constructing runtime buffers and processing embedded content. Their exact role remained a hypothesis until confirmed through function-level analysis.

### Timing

The following APIs were also identified:

```text
QueryPerformanceFrequency
QueryPerformanceCounter
GetTickCount
```

These provide access to both high-resolution and system-uptime timing sources.

At the static stage, they indicate timing-related functionality. Possible uses include delays, timeout handling, scheduling, execution measurement, or timing-dependent logic. Their presence alone is insufficient to classify them as anti-analysis behavior, so this remained a hypothesis for deep analysis.

---

# 3. Windows Service Functionality

`ADVAPI32.dll` contains a particularly significant group of service-management APIs:

```text
OpenSCManagerA
CreateServiceA
OpenServiceA
ChangeServiceConfig2A
StartServiceA
CloseServiceHandle
```

The sample also imports the APIs required for operating as a service process:

```text
StartServiceCtrlDispatcherA
RegisterServiceCtrlHandlerA
SetServiceStatus
```

Together, these imports establish that the sample contains the API-level capabilities required for both sides of the Windows Service architecture:

```text
Service installation / configuration
        │
        ├── OpenSCManagerA
        ├── CreateServiceA
        ├── ChangeServiceConfig2A
        └── StartServiceA
                  │
                  ▼
             Service process
                  │
        ├── StartServiceCtrlDispatcherA
        ├── RegisterServiceCtrlHandlerA
        └── SetServiceStatus
```

This provides strong static evidence for a **service-based execution path** and makes service-based persistence a primary hypothesis for subsequent reverse engineering.

---

# 4. Cryptographic and Randomness-Related APIs

The sample imports:

```text
CryptAcquireContextA
CryptGenRandom
```

These APIs provide access to a Windows Cryptographic Service Provider and cryptographically secure random-data generation.

The static evidence establishes that cryptographic provider functionality is available to the sample, but the purpose of generated random data cannot be determined from imports alone.

Possible uses include cryptographic operations, randomized behavior, network target generation, or other internal state. Therefore, the exact role was left for function-level analysis.

---

# 5. Network-Related Imports

## 5.1 WinINet

The following WinINet APIs were identified:

```text
InternetOpenA
InternetOpenUrlA
InternetCloseHandle
```

This establishes the capability to initiate Internet communication through the WinINet API.

The presence of these APIs is particularly relevant because the sample also contains a network-related domain in its static string set.

However, imports alone do not establish:

- the exact destination;
    
- request parameters;
    
- protocol details;
    
- the purpose of the request;
    
- whether the communication is related to the kill-switch mechanism.
    

These relationships require execution-flow analysis.

## 5.2 Winsock

`WS2_32.dll` is present among the imported modules, but the expected networking functions were not displayed by PE-bear as conventional imports.

This discrepancy may result from:

- dynamic API resolution;
    
- non-standard import representation;
    
- PE parser limitations;
    
- modified or reconstructed import structures.
    

Because the sample also imports `GetModuleHandleA/W` and `GetProcAddress`, dynamic Winsock API resolution became a relevant hypothesis for deep reverse engineering.

## 5.3 Network Adapter Enumeration

`iphlpapi.dll` provides:

```text
GetAdaptersInfo
GetPerAdapterInfo
```

These APIs allow enumeration of local network adapters and retrieval of their configuration.

Their presence indicates that the sample can obtain information about the local network environment, including adapter and IP configuration.

This provides static support for a **network-environment discovery capability** and motivated further investigation of local-network target generation.

---

# 6. Resource Analysis

The `.rsrc` section contains a PE-formatted blob beginning at approximately:

```text
0x0035A000
```

The extracted data begins with the `MZ` signature and can itself be identified as a PE.

Further inspection showed that the embedded PE contains a ZIP archive.

The archive contains multiple WannaCry-related components, including:

```text
msg
b.wnry
s.wnry
taskse.exe
taskdl.exe
```

The archive metadata is readable, while the archived file contents are marked as encrypted.

The extracted embedded PE has the following SHA-256:

```text
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
```

The resulting structure can be represented as:

```text
Main PE
└── .rsrc
    └── Embedded PE
        └── ZIP archive
            ├── taskse.exe
            ├── taskdl.exe
            ├── *.wnry
            └── msg/m_*.wnry
```

This is one of the most significant findings of the static stage because it establishes that the main executable contains additional executable and supporting content rather than functioning as a single standalone PE.

---

# 7. String Analysis

The raw string extraction produced a large and heterogeneous dataset.

The primary reason is the presence of multiple PE images and an embedded archive. Consequently, strings originating from different executable components are mixed together.

For this reason, the raw string dump was retained as evidence but was not treated as a direct representation of the main executable's complete functionality.

Instead, strings were manually filtered according to their behavioral relevance and correlated with imports and resource structures.

The analysis concentrated on:

- network indicators;
    
- service names;
    
- executable names;
    
- command-line strings;
    
- filesystem paths;
    
- embedded PE signatures;
    
- archive-related strings;
    
- cryptographic references;
    
- ransomware-specific identifiers;
    
- targeted file extensions.
    

---

# 8. Embedded PE and Archive Indicators

Several strings provide independent support for the resource analysis.

PE-related strings include:

```text
!This program cannot be run in DOS mode.
.text
.rdata
.data
.rsrc
.reloc
```

These strings are consistent with the presence of embedded PE structures.

The resource content also contains references to:

```text
inflate 1.1.3 Copyright 1995-1998 Mark Adler
unzip 0.15 Copyright 1998 Gilles Vollant
```

These references are consistent with zlib/DEFLATE decompression and ZIP processing.

Together with the resource structure, they support the following model:

```text
Main PE
   │
   └── .rsrc
        │
        └── Embedded PE
             │
             └── ZIP archive
                  │
                  ├── executable components
                  ├── .wnry files
                  └── language resources
```

This relationship is stronger than treating the individual strings as isolated indicators because both the resource structure and string content independently point toward the same embedded-archive architecture.

---

# 9. WannaCry-Specific Indicators

Several strings directly identify the embedded content as WannaCry-related:

```text
WanaCrypt0r
WANACRY!
WNcry@2ol7
```

These indicators correlate with the embedded PE and archive structure.

Their presence provides additional evidence that the resource data contains components belonging to the analyzed WannaCry sample rather than unrelated compressed or embedded content.

---

# 10. Filesystem and Execution Indicators

Several strings provide preliminary evidence of filesystem manipulation and process execution.

Notable examples include:

```text
cmd.exe /c "%s"
icacls . /grant Everyone:F /T /C /Q
attrib +h .
tasksche.exe
TaskStart
```

Additional path-related strings include:

```text
%s\%s
%s\Intel
%s\ProgramData
C:\%s\%s
WINDOWS
```

The presence of:

```text
icacls . /grant Everyone:F /T /C /Q
```

indicates a potential capability to modify filesystem permissions.

The string:

```text
attrib +h .
```

indicates a potential mechanism for setting the hidden attribute.

The presence of `cmd.exe /c "%s"` provides evidence that command-line execution through `cmd.exe` may be used.

These observations identify candidate execution and filesystem-manipulation paths but do not establish that every command is executed during the analyzed run.

---

# 11. Service and Process Indicators

The following strings are particularly relevant when correlated with the service-related imports:

```text
mssecsvc.exe
tasksche.exe
TaskStart
```

The combination of:

```text
CreateServiceA
StartServiceA
StartServiceCtrlDispatcherA
RegisterServiceCtrlHandlerA
SetServiceStatus
```

with service-related strings provides converging evidence for a Windows service execution component.

The exact service configuration, execution path and relationship between the identified filenames were deferred to deep reverse engineering.

---

# 12. Targeted File Extensions

The resource content contains a large collection of document, database, source-code, backup, virtual-machine and media file extensions, including:

```text
.lay6
.sqlite3
.sqlitedb
.accdb
.java
.class
.mpeg
.djvu
.tiff
.jpeg
.backup
.vmdk
.sldm
.sldx
.onetoc2
.vsdx
.potm
.potx
.ppam
.ppsx
.ppsm
.pptm
.pptx
.xltm
.xltx
.xlsb
.xlsm
.xlsx
.dotx
.dotm
.docm
.docb
.docx
```

This collection is consistent with the expected file-targeting behavior of WannaCry ransomware.

However, the extension list alone does not demonstrate that every listed extension is actively processed during execution. At this stage it is treated as static evidence of the intended file-targeting scope.

Execution-level confirmation requires tracing the corresponding file-processing logic during deep reverse engineering.

---

# 13. Preliminary Behavioral Model

Correlation of imports, strings and resources produced the following preliminary model:

```text
                         Main PE
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
          ▼                 ▼                  ▼
      Services          Networking         Resources
          │                 │                  │
          │                 │                  ▼
          │                 │             Embedded PE
          │                 │                  │
          │                 │                  ▼
          │                 │             ZIP archive
          │                 │                  │
          │                 │          ┌───────┼───────┐
          │                 │          │       │       │
          │                 │        *.wnry  tasks*   msg
          │                 │
          │                 ├── WinINet
          │                 ├── Winsock
          │                 └── adapter enumeration
          │
          ├── Service installation
          ├── Service configuration
          └── Service execution
```

The static evidence therefore suggests several major behavioral areas:

1. **Service-based execution and persistence**
    
2. **Embedded payload/resource extraction**
    
3. **Filesystem and process manipulation**
    
4. **Network communication**
    
5. **Local network environment discovery**
    
6. **Multithreaded execution and shared-state management**
    
7. **Cryptographic/randomness-related functionality**
    
8. **Ransomware-oriented file targeting**
    

These capabilities are not independent observations. Several are supported by multiple evidence sources.

For example:

```text
Service APIs
      +
service-related strings
      ↓
Service execution hypothesis
```

and:

```text
Resource PE
      +
ZIP-related strings
      +
embedded WannaCry identifiers
      ↓
Embedded payload/archive hypothesis
```

and:

```text
iphlpapi APIs
      +
Winsock presence
      +
network-related WinINet APIs
      ↓
Network-aware behavior hypothesis
```

---

# 14. Static Analysis Limitations

Static analysis established capabilities and behavioral hypotheses, but it did not establish the complete execution flow.

In particular, the following remained unresolved at the end of this stage:

- which imported APIs are connected to each other during execution;
    
- the exact control-flow path from the Entry Point;
    
- the exact purpose of the generated random data;
    
- the relationship between dynamic Winsock resolution and network functions;
    
- the exact mechanism used to process embedded PE components;
    
- the runtime role of individual `.wnry` files;
    
- which file extensions are actively processed;
    
- the exact use of timing APIs;
    
- the complete relationship between network discovery and SMB propagation;
    
- whether all identified command-line strings are executed during the analyzed run.
    

These questions were therefore transferred to the Deep Reverse Analysis stage.

---

# 15. Conclusion

The static analysis established that the sample is not limited to a single ransomware execution path. Its imported APIs, embedded resources and extracted strings indicate a combination of **service management, resource and file handling, network communication, local network discovery, multithreaded execution, dynamic API resolution and ransomware-related file processing**.

The most significant static finding is the presence of an **embedded PE containing a ZIP archive with additional WannaCry components**, supported independently by both the resource structure and strings referencing ZIP/DEFLATE processing.

The second major finding is the convergence of service-related imports and service-specific strings, providing strong evidence for a dedicated Windows service execution path.

Network-related imports and `iphlpapi` functions additionally indicate that the sample is aware of its network environment and is capable of network communication and adapter enumeration.

The string analysis further identified WannaCry-specific markers, filesystem and command-line artifacts, and an extensive set of targeted file extensions. These findings provide supporting evidence for ransomware functionality but were not treated as proof of runtime execution without corresponding behavioral evidence.

The resulting static behavioral model is therefore:

```text
Embedded Payload
       │
       ├── Resource / Archive Processing
       │
       └── Additional PE Components

Windows Service
       │
       └── Service-based Execution / Persistence

Network Awareness
       │
       ├── Adapter Enumeration
       ├── Internet Communication
       └── Winsock-related Functionality

Execution Infrastructure
       │
       ├── Dynamic API Resolution
       ├── Dynamic Memory
       ├── Thread Synchronization
       └── Timing

Ransomware Indicators
       │
       ├── Targeted File Extensions
       ├── Filesystem Commands
       └── WannaCry-specific Identifiers
```

At the end of the static stage, these findings formed the **initial behavioral model and investigation hypotheses** used to guide the subsequent Deep Reverse Analysis.

The static evidence established _what the sample appears capable of doing_. The next stage was required to determine _how these capabilities are connected during execution_ and which of the identified hypotheses can be confirmed through code and runtime evidence.