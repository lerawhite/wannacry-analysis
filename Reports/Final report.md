
---

```
Final Report
│
├── 1. Sample Overview
├── 2. Analysis Methodology
├── 3. Initial Triage
├── 4. Static Analysis
├── 5. Execution Architecture
├── 6. Persistence
├── 7. Service Execution
├── 8. Network Target Discovery
├── 9. SMB Propagation
├── 10. DOUBLEPULSAR-related Stage
├── 11. Payload Staging and Transfer
├── 12. IOC Summary
├── 13. Behavioral Summary
├── 14. Analysis limitations/notes
└── 15. Conclusion
```


---

## 1. Sample Overview

### 1.1 Sample

**Malware:** WannaCry  
**Architecture:** PE32 / x86  
**SHA-256:**

```text
ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9
```

The analyzed sample is a Windows executable containing multiple embedded PE regions and a network propagation component based on SMB.

The reverse-engineering work focused on the executable's execution architecture, service installation, payload staging, network target discovery, SMB communication, DOUBLEPULSAR-related processing, and network payload transfer.

The ransomware encryption engine itself was not fully reverse engineered in this project. The analysis instead follows the sample through the execution and propagation architecture that could be reconstructed from the available static and dynamic evidence.

### 1.2 Main Functional Components

The analyzed sample contains the following major components:

```text
Execution control
├── Kill switch
├── Argument-based execution mode
└── Service execution

Persistence / deployment
├── Service creation
├── Failure recovery
├── Embedded resource extraction
└── Payload process creation

Network propagation
├── Local network enumeration
├── Random IPv4 target generation
├── TCP/445 reachability
├── SMB protocol processing
├── DOUBLEPULSAR-related stage
└── Payload transfer

Payload handling
├── Embedded PE data
├── Running executable copy
├── In-memory staging
├── XOR transformation
└── Chunked network transmission
```

---

# 2. Analysis Methodology

The analysis was performed using a combination of static and dynamic reverse-engineering techniques.

### Static analysis

The PE structure, sections, resources, strings, imports, embedded PE regions, and relevant code paths were examined using:

- Detect It Easy;
    
- PE-bear;
    
- HxD;
    
- Ghidra.
    

### Dynamic analysis

Runtime behaviour was examined in an isolated Windows 10 22H2 virtual machine using:

- x64dbg/x32dbg;
    
- Procmon;
    
- Process Hacker;
    
- Wireshark/Npcap;
    
- controlled network targets.
    

### Reverse-engineering approach

The analysis proceeded from architecture to individual functions:

```text
entry point
    ↓
execution mode
    ↓
service execution
    ↓
network initialisation
    ↓
worker architecture
    ↓
target discovery
    ↓
TCP/445 gate
    ↓
SMB processing
    ↓
payload transfer
```

Function relationships were reconstructed using:

- call relationships;
    
- API behaviour;
    
- register and memory state;
    
- packet structures;
    
- response-dependent control flow;
    
- cross-function data flow.
    

Dynamic evidence was preferred where available. When the remote target did not reproduce a later stage, the corresponding behaviour was explicitly classified as statically reconstructed rather than dynamically verified.

---

# 3. Initial Triage

The sample is a 32-bit Windows PE executable containing embedded PE data and resources.

The resource section contains several PE-related objects, including:

```text
msg
b.wnry
s.wnry
tasksche.exe
taskdl.exe
```

The binary also contains strings associated with WannaCry execution and deployment, including:

```text
WanaCrypt0r
WANACRY!
mssecsvc2.0
Microsoft Security Center (2.0)
wannacry -m security
```

The embedded data and high-entropy regions indicated that the resource section required deeper examination.

The sample also contains an overlay and embedded executable material that was subsequently traced into runtime memory.

---

# 4. Static Analysis

Static analysis established the basic structure of the sample before dynamic execution.

Important findings included:

- PE32 executable;
    
- multiple embedded PE regions;
    
- resource-contained executable data;
    
- service-related strings;
    
- network-related imports and strings;
    
- embedded payload material;
    
- kill-switch domain;
    
- SMB-related protocol data;
    
- code paths responsible for network propagation.
    

The static analysis also identified the two large payload buffers later reconstructed dynamically by `0x00407A20`.

The most important static finding was that the sample contains executable data that is subsequently copied into memory rather than merely stored as unused resources.

---

# 5. Execution Architecture

The reconstructed execution architecture is:

```text
                         Entry Point
                              │
                              ▼
                        Kill Switch
                              │
                  ┌───────────┴───────────┐
                  │                       │
               success                 failure
                  │                       │
                 exit                     ▼
                                  Argument analysis
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                    argc < 2                      argc >= 2
                         │                             │
                         ▼                             ▼
                  persistence /                service execution
                  payload deployment                  │
                                                       ▼
                                               network subsystem
                                                       │
                                                       ▼
                                              propagation workers
                                                       │
                                    ┌──────────────────┴──────────────────┐
                                    │                                     │
                              local discovery                      random discovery
                                    │                                     │
                                    └──────────────────┬──────────────────┘
                                                       ▼
                                                TCP/445 gate
                                                       │
                                                       ▼
                                               SMB propagation
                                                       │
                                                       ▼
                                          payload transfer stage
```

The architecture separates target discovery from target processing.

This allows multiple discovery mechanisms to feed the same propagation engine.

---

# 6. Persistence

The no-argument execution path creates the Windows service:

```text
Service:
mssecsvc2.0

Display name:
Microsoft Security Center (2.0)

Start type:
SERVICE_AUTO_START

Command:
<executable path> -m security
```

The service is created using `CreateServiceA()` and subsequently started with `StartServiceA()`.

The failure-action configuration uses:

```text
SC_ACTION_RESTART
```

with a 60-second delay.

The configured command string is:

```text
wannacry -m security
```

The relevant persistence architecture is:

```text
Initial execution
      │
      ▼
CreateServiceA
      │
      ▼
mssecsvc2.0
      │
      ▼
SERVICE_AUTO_START
      │
      ▼
StartServiceA
      │
      ▼
ServiceMain
```

The service therefore provides an execution mechanism independent of the initial process invocation.

---

# 7. Service Execution

The service entry point is:

```text
0x00408000
```

The service is registered through:

```text
StartServiceCtrlDispatcherA
```

using:

```text
mssecsvc2.0
```

as the service name.

`ServiceMain`:

1. registers the service control handler;
    
2. initializes the service status;
    
3. transitions the service to `RUNNING`;
    
4. invokes the network propagation subsystem.
    

The core relationship is:

```text
Windows Service Manager
          │
          ▼
StartServiceCtrlDispatcherA
          │
          ▼
0x00408000
          │
          ▼
0x00407BD0
          │
          ▼
Propagation subsystem
```

A service failure-action configuration additionally requests automatic restart after a 60-second delay.

---

# 8. Network Target Discovery

The propagation module has two independent target-selection mechanisms.

```text
                 Target Discovery
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
   Local network                Random IPv4
   enumeration                 generation
          │                         │
          └────────────┬────────────┘
                       ▼
                Target processing
```

## 8.1 Local network enumeration

`0x00409160` enumerates network interfaces through:

```text
GetAdaptersInfo()
GetPerAdapterInfo()
```

It derives network and broadcast information from the adapter configuration and generates usable host addresses.

The resulting targets are validated, filtered, sorted, and deduplicated.

`0x00407720` distributes these targets to per-target workers.

The process is:

```text
adapter information
       ↓
IPv4 network parameters
       ↓
host-range generation
       ↓
validation / RFC1918 filtering
       ↓
deduplication
       ↓
target workers
```

## 8.2 Random IPv4 generation

`0x00407840` provides a complementary discovery mechanism.

It generates candidate IPv4 addresses independently from local interface configuration.

Randomness is obtained through:

```text
0x00407660
    │
    ├── CryptGenRandom()
    │
    └── rand() fallback
```

Generated addresses are filtered before use.

The function then performs a TCP/445 reachability check.

```text
Random IPv4
     │
     ▼
inet_addr()
     │
     ▼
TCP/445
     │
     ├── fail → discard
     │
     └── success
             │
             ▼
        propagation worker
```

This provides a broader target-selection path in addition to local-network enumeration.

---

# 9. SMB Propagation

The propagation architecture converges on:

```text
0x00407540
```

The complete per-target path is:

```text
Target IP
    │
    ▼
0x00407480
TCP/445 gate
    │
    ▼
0x00407540
    │
    ├── 0x00401980
    │      SMB qualification
    │
    ├── 0x00401B70
    │      SMB Transaction2 stage
    │
    ├── 0x00401370
    │      table-driven protocol processing
    │
    └── 0x004072A0
           payload transfer
```

## 9.1 TCP/445 gate

`0x00407480` creates a TCP socket, configures non-blocking operation, attempts a connection to port 445, evaluates the result through `select()`, and closes the socket.

This provides the first target qualification layer before SMB processing.

## 9.2 SMB negotiation

`0x00401980` establishes an SMB1 communication sequence.

The observed sequence is:

```text
TCP/445
   ↓
SMB_COM_NEGOTIATE
   ↓
SMB_COM_SESSION_SETUP_ANDX
   ↓
STATUS_ACCESS_DENIED
   ↓
IPC$ Tree Connect
   ↓
SMB_COM_TREE_CONNECT_ANDX
```

The function constructs:

```text
\\<target>\IPC$
```

and uses response-derived session information when preparing subsequent protocol data.

## 9.3 Transaction2 stage

`0x00401B70` establishes another SMB connection and prepares:

```text
SMB_COM_TRANSACTION2
```

after the SMB negotiation, Session Setup, and IPC$ stages.

The transaction contains response-dependent fields.

The controlled execution did not reach a complete valid Transaction2 exchange because the preceding target interaction terminated at the SMB connection boundary.

Therefore this stage is classified as statically reconstructed.

## 9.4 Table-driven protocol engine

`0x00401370` implements a descriptor-driven network processing engine.

The global table:

```text
0x00431480
```

contains entries controlling operations such as:

```text
connect
send
recv
close
```

The function also maintains SMB-related state associated with:

```text
treeid
userid
```

This provides the underlying protocol-processing infrastructure for the surrounding SMB path.

---

# 10. DOUBLEPULSAR-related Stage

The strongest evidence for the DOUBLEPULSAR relationship is the routine:

```text
0x00406ED0
```

It implements the known DOUBLEPULSAR XOR-key derivation algorithm.

The function transforms an input DWORD using byte rearrangement, shifts, arithmetic, and XOR with twice the original value.

Conceptually:

```text
input DWORD
     │
     ├── byte rearrangement
     ├── shifts
     ├── masking
     ├── 2 × input
     └── XOR
          │
          ▼
     derived key
```

The algorithm matches the published DOUBLEPULSAR derivation used in SMB tooling.

The surrounding architecture further connects this value to subsequent payload-processing functions.

The resulting interpretation is:

```text
SMB response-derived value
          │
          ▼
     0x00406ED0
          │
          ▼
 DOUBLEPULSAR-related
      key derivation
          │
          ▼
 subsequent network/
 payload processing
```

The analysis does not claim that the sample contains a complete local copy of the remote DOUBLEPULSAR implant. The evidence instead establishes a DOUBLEPULSAR-related protocol stage within the SMB propagation component.

---

# 11. Payload Staging and Transfer

This stage provides the strongest data-flow relationship between embedded executable material and network propagation.

## 11.1 Initial payload staging

`0x00407A20` creates:

```text
0x70F864 → Buffer 1
0x70F868 → Buffer 2
```

Each buffer contains embedded PE material together with a copy of the running executable.

Conceptually:

```text
Embedded PE
     │
     ▼
0x00407A20
     │
     ├──────────────┐
     ▼              ▼
 Buffer 1        Buffer 2
     │              │
     └──────┬───────┘
            ▼
       later selection
```

## 11.2 Payload selection

`0x00406F50` selects one of the two buffers according to its mode.

It then:

1. allocates a new working region;
    
2. copies staged payload data;
    
3. initializes transfer state;
    
4. transforms the data;
    
5. constructs transfer packets.
    

The data flow is:

```text
0x70F864 / 0x70F868
        │
        ▼
   0x00406F50
        │
        ▼
 allocated transfer context
        │
        ▼
   0x00406F00
        │
        ▼
 transformed data
        │
        ▼
 packet construction
```

## 11.3 Repeating XOR transformation

`0x00406F00` performs an in-place repeating four-byte XOR transformation:

```c
for (i = 0; i < length; i++)
    buffer[i] ^= key[i & 3];
```

The observed implementation should therefore be described as a repeating XOR transformation rather than as a cryptographic primitive.

## 11.4 Chunked transfer

The prepared data is transmitted in approximately `0x1000`-byte chunks.

The packet transmission path is:

```text
payload chunk
     │
     ▼
XOR transformation
     │
     ▼
packet construction
     │
     ▼
send(..., 0x1052)
     │
     ▼
recv(..., 0x1000)
     │
     ▼
response == 'R'
     │
     ├── no → stop
     │
     └── yes
          │
          ▼
      next chunk
```

After all full chunks, a final variable-length block is transmitted.

## 11.5 Complete payload data flow

The most important reconstructed relationship is:

```text
Embedded PE regions
        │
        ▼
   0x00407A20
        │
        ▼
  0x70F864 / 0x70F868
        │
        ▼
   0x00406F50
        │
        ▼
 transfer working buffer
        │
        ▼
   0x00406F00
        │
        ▼
 transformed payload
        │
        ▼
 SMB/network packet
        │
        ▼
      send()
        │
        ▼
 remote target
```

This demonstrates that the embedded executable data is functionally connected to the network propagation stage.

The exact remote-side execution of the transmitted data was not reproduced in the controlled environment.

---

# 12. IOC Summary

## 12.1 Network IOC

```text
www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com
```

**Type:** Domain / URL  
**Role:** Kill switch

## 12.2 Service IOC

```text
mssecsvc2.0
```

**Type:** Windows Service  
**Role:** Persistence / service execution

## 12.3 Service display name

```text
Microsoft Security Center (2.0)
```

**Type:** Service metadata  
**Role:** Service identification

## 12.4 Service command

```text
wannacry -m security
```

**Type:** Process/service command  
**Role:** Service execution and failure recovery

## 12.5 Dropped executable

```text
C:\WINDOWS\tasksche.exe
```

**Type:** File  
**Role:** Extracted executable

## 12.6 Renamed executable

```text
C:\WINDOWS\qeriuwjhrf
```

**Type:** File  
**Role:** Subsequent file destination

## 12.7 Process command line

```text
tasksche.exe /i
```

**Type:** Process execution  
**Role:** Extracted payload execution

## 12.8 Sample hash

```text
SHA-256:
ed492db95034ca288dd52df88e3ce3ec7b146ffd854a394ac187f0553ef966d9
```

**Type:** File hash  
**Role:** Sample identification

### Protocol evidence that is not treated as IOC

The following are behavioural/protocol evidence rather than classic IOC values:

```text
TCP/445
IPC$
SMB command codes
SMB status codes
treeid
userid
'Q' response marker
'R' response marker
0x1052 transfer size
0x1000 chunk size
```

Dynamic lab addresses and VM-specific MAC addresses are also excluded from the IOC set.

---

# 13. Behavioral Summary

The analyzed sample exhibits the following behavioural chain:

```text
1. Initial execution
       ↓
2. Kill-switch check
       ↓
3. Execution-mode selection
       ↓
4. Service installation / execution
       ↓
5. Network subsystem initialization
       ↓
6. Payload staging in memory
       ↓
7. Target discovery
       ↓
8. TCP/445 qualification
       ↓
9. SMB negotiation and state handling
       ↓
10. Transaction / DOUBLEPULSAR-related stage
       ↓
11. Payload selection
       ↓
12. Payload transformation
       ↓
13. Chunked network transmission
```

The propagation subsystem uses two complementary discovery mechanisms:

```text
local network enumeration
          +
random IPv4 generation
          ↓
      target set
```

The target-processing architecture is concurrent:

```text
multiple targets
      │
      ├── worker
      ├── worker
      ├── worker
      ├── ...
      └── worker
```

The payload architecture is staged:

```text
embedded data
      ↓
global memory buffers
      ↓
transfer context
      ↓
transformation
      ↓
network packets
```

The overall behaviour can therefore be characterised as a multi-stage propagation architecture combining local and randomized target discovery with SMB-based processing and staged executable-data transfer.

---

# 14. Analysis Limitations / Notes

### 14.1 Remote-side execution

The controlled environment did not reproduce the complete remote-side execution chain.

Therefore the report does not claim that the observed local transfer routine alone proves successful remote code execution.

### 14.2 SMB Transaction2

The `SMB_COM_TRANSACTION2` stage was identified statically, but the complete exchange was not dynamically reproduced because the controlled target terminated the preceding communication.

### 14.3 DOUBLEPULSAR

The DOUBLEPULSAR XOR-key derivation is an exact algorithmic match, providing strong evidence for the relationship.

However, the complete remote DOUBLEPULSAR implementation and its full protocol state machine were outside the scope of this project.

### 14.4 Payload interpretation

The local sample clearly selects previously staged executable data, transforms it, constructs network packets, and transmits it.

The exact interpretation and execution of every transmitted field by the remote target could not be established solely from the local binary.

### 14.5 Ransomware encryption engine

The project primarily focused on execution architecture and network propagation.

The complete ransomware encryption/decryption workflow was not reconstructed at function level and is therefore not presented as a fully analysed component of this report.

### 14.6 Dynamic environment

Network observations were performed against controlled laboratory systems.

Observed laboratory IP addresses, MAC addresses, VM-specific paths, and debugger modifications are not considered malware IOCs.

---

# 15. Conclusion

The reverse-engineering analysis reconstructs WannaCry's propagation architecture as a layered system rather than a single exploit routine.

The sample first controls execution through a kill switch and argument-dependent execution mode. It establishes persistence through the `mssecsvc2.0` Windows service and prepares executable data in memory.

The propagation subsystem then uses two complementary target-discovery mechanisms: local interface/subnet enumeration and randomized IPv4 generation. Candidate targets are first filtered through a TCP/445 connectivity check before entering the SMB processing path.

The SMB component performs negotiation, Session Setup, IPC$ tree connection, transaction processing, and table-driven protocol operations. Within the same network component, `0x00406ED0` implements the known DOUBLEPULSAR XOR-key derivation algorithm, providing direct algorithmic evidence for a DOUBLEPULSAR-related stage.

The most significant data-flow finding is the relationship between the embedded PE data and the later propagation stage:

```text
embedded PE data
      ↓
0x00407A20
      ↓
0x70F864 / 0x70F868
      ↓
0x00406F50
      ↓
transfer buffer
      ↓
0x00406F00
      ↓
packet construction
      ↓
SMB/network transmission
```

This establishes that the embedded executable material is not merely present in the binary as static data. It is incorporated into a later network-transfer path.

The complete remote-side exploitation and execution sequence could not be reproduced in the controlled environment. Nevertheless, the combination of dynamic observations and static reconstruction is sufficient to establish the principal architecture:

```text
Execution
   ↓
Persistence
   ↓
Network initialisation
   ↓
Target discovery
   ↓
TCP/445 qualification
   ↓
SMB propagation
   ↓
DOUBLEPULSAR-related processing
   ↓
Payload staging
   ↓
Chunked network transfer
```

The resulting model provides a coherent explanation of how the analysed WannaCry sample moves from local execution and persistence into multi-target SMB propagation and staged payload delivery.