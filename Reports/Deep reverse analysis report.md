
---

## 1. Scope

This report presents the deep reverse-engineering results for the analyzed WannaCry sample, with emphasis on execution flow, service execution, network target discovery, SMB propagation, the DOUBLEPULSAR-related stage, and payload transfer.

The analysis combines:

- x64dbg dynamic execution;
    
- Ghidra static reconstruction;
    
- API-level observation;
    
- packet-level inspection;
    
- control-flow reconstruction;
    
- memory and data-flow tracing.
    

The main objective was to reconstruct how the malware moves from initial execution to network propagation and how the embedded executable data is connected to the later SMB transfer stage.

The analysis does not attempt to fully reconstruct the remote-side implementation of `ETERNALBLUE/DOUBLEPULSAR` or the complete ransomware encryption engine.

---

# 2. High-Level Execution Architecture

The analyzed sample can be divided into five major functional layers:

```text
                    WannaCry
                       │
                       ▼
              Initial execution
                       │
                       ▼
                 Kill switch
                       │
              ┌────────┴────────┐
              │                 │
           success           failure
              │                 │
             exit                ▼
                         Execution mode
                         determination
                               │
                 ┌─────────────┴─────────────┐
                 │                           │
            no arguments                 arguments
                 │                           │
                 ▼                           ▼
          persistence /             service-oriented
          payload deployment          execution
                                             │
                                             ▼
                                      network subsystem
                                             │
                                             ▼
                                    target discovery
                                             │
                              ┌──────────────┴──────────────┐
                              │                             │
                       local network                  random IPv4
                       enumeration                    generation
                              │                             │
                              └──────────────┬──────────────┘
                                             ▼
                                      TCP/445 gate
                                             │
                                             ▼
                                    SMB propagation path
                                             │
                          ┌──────────────────┼──────────────────┐
                          │                  │                  │
                    SMB qualification   transaction       protocol engine
                          │                  │                  │
                          └──────────────────┼──────────────────┘
                                             ▼
                                  DOUBLEPULSAR-related
                                      processing
                                             │
                                             ▼
                                  staged payload transfer
                                             │
                                             ▼
                                      remote target
```

The architecture is therefore not a single linear routine. It consists of independent execution and target-selection components that converge on a common per-target propagation worker.

---

# 3. Initial Execution

The entry-point logic first performs the kill-switch check.

The relevant path attempts to access:

```text
www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com
```

The result determines whether execution continues.

```text
Kill-switch check
       │
       ├── successful connection
       │        │
       │        ▼
       │       exit
       │
       └── failed connection
                │
                ▼
          continue execution
```

The kill switch is therefore an execution gate rather than a conventional command-and-control channel.

After the check, execution mode is determined from the process arguments.

The analyzed architecture separates:

```text
argc < 2
    │
    └── installation / persistence / payload deployment

argc >= 2
    │
    └── service-oriented execution
```

---

# 4. Persistence and Payload Deployment

The no-argument path creates the service infrastructure and deploys the ransomware-related executable components.

The persistence stage creates the service:

```text
Service name:
mssecsvc2.0

Display name:
Microsoft Security Center (2.0)

Start type:
SERVICE_AUTO_START

Command:
<executable path> -m security
```

The service is subsequently started.

The failure-action configuration also contains:

```text
wannacry -m security
```

with a restart action and a 60-second delay.

The sample additionally extracts an embedded executable resource and writes it to:

```text
C:\WINDOWS\tasksche.exe
```

The extracted file is then involved in the following path:

```text
embedded resource
      │
      ▼
FindResourceA / LoadResource
      │
      ▼
WriteFile
      │
      ▼
C:\WINDOWS\tasksche.exe
      │
      ▼
CreateProcessA
      │
      ▼
tasksche.exe /i
      │
      ▼
MoveFileExA
      │
      ▼
C:\WINDOWS\qeriuwjhrf
```

This establishes the relationship between the embedded resource, the dropped executable, and the subsequent execution stage.

---

# 5. Service Execution

The service entry point is:

```text
0x00408000
```

The service is registered through:

```text
StartServiceCtrlDispatcherA
```

with:

```text
Service name:
mssecsvc2.0

ServiceMain:
0x00408000
```

`ServiceMain` registers a control handler and maintains a `SERVICE_STATUS` structure.

The execution state progresses from:

```text
START_PENDING
      ↓
RUNNING
```

The service then invokes:

```text
0x00407BD0
```

which starts the network propagation subsystem.

The overall relationship is:

```text
Windows Service
      │
      ▼
0x00408000 ServiceMain
      │
      ▼
0x00407BD0
      │
      ▼
Network propagation
```

The service remains alive for an extended period after the propagation subsystem is started.

---

# 6. Network Subsystem Initialization

The network subsystem is initialized through `0x00407B90`.

The function first invokes:

```text
WSAStartup(MAKEWORD(2,2))
```

Failure prevents the subsequent worker subsystem from being initialized.

On success, the function continues into:

```text
0x00407620
0x00407A20
```

The first prepares the cryptographic provider and synchronization state.

The second prepares the in-memory payload buffers used later during propagation.

The initialization relationship is:

```text
0x00407B90
    │
    ├── WSAStartup()
    │
    ├── 0x00407620
    │      ├── CryptAcquireContextA
    │      └── InitializeCriticalSection
    │
    └── 0x00407A20
           ├── embedded PE #1
           ├── embedded PE #2
           └── running executable
```

---

# 7. Payload Preparation in Memory

`0x00407A20` creates two global buffers:

```text
0x70F864
0x70F868
```

The buffers are populated with embedded PE material and a copy of the running executable.

Conceptually:

```text
Buffer 1
┌───────────────────────────────┐
│ Embedded PE #1                │
├───────────────────────────────┤
│ Executable size               │
├───────────────────────────────┤
│ Running executable            │
└───────────────────────────────┘

Buffer 2
┌───────────────────────────────┐
│ Embedded PE #2                │
├───────────────────────────────┤
│ Executable size               │
├───────────────────────────────┤
│ Running executable            │
└───────────────────────────────┘
```

These buffers are not isolated embedded resources.

Later analysis of `0x00406F50` demonstrates that the propagation subsystem explicitly selects these buffers as the source of data for network transmission.

This creates the following verified local data flow:

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
transfer buffer
       │
       ▼
0x00406F00
       │
       ▼
network packets
```

This is one of the most significant findings of the reverse analysis.

---

# 8. Propagation Worker Architecture

`0x00407BD0` is the main propagation dispatcher.

It starts:

- one local-network worker;
    
- up to 128 randomized-target worker launch attempts.
    

The structure is:

```text
                 0x00407BD0
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
     0x00407720               0x00407840
          │                       │
          │                       │
 local network targets       random IPv4 targets
          │                       │
          └───────────┬───────────┘
                      ▼
                 0x00407540
                      │
                      ▼
              per-target processing
```

Thread handles are closed after creation, allowing the worker threads to continue independently.

A shared counter at:

```text
0x0070F86C
```

is used for worker-count synchronisation.

The design therefore supports concurrent processing of multiple targets rather than serial target handling.

---

# 9. Local Network Target Discovery

`0x00407720` obtains a target list from `0x00409160`.

`0x00409160` uses:

```text
GetAdaptersInfo()
GetPerAdapterInfo()
inet_addr()
```

to reconstruct local IPv4 network information.

The analysis showed the following operations:

```text
local adapter information
        │
        ▼
IPv4 address + subnet mask
        │
        ▼
network / broadcast calculation
        │
        ▼
usable host generation
        │
        ▼
range validation
        │
        ▼
RFC1918 filtering
        │
        ▼
sorting / deduplication
        │
        ▼
target array
```

The target array is then distributed through worker threads.

Each target is passed to:

```text
0x004076B0
```

which performs the per-target gatekeeping and worker management.

---

# 10. Randomized IPv4 Target Discovery

The second discovery path is implemented by:

```text
0x00407840
```

This routine independently generates IPv4 addresses.

Randomness is obtained through `0x00407660`, which uses:

```text
CryptGenRandom()
```

when the initialized CryptoAPI provider is available, with `rand()` as a fallback.

The generated address is filtered before being used.

The first octet excludes:

```text
127
224–255
```

The address is then converted using:

```text
inet_addr()
```

and tested through the TCP/445 connectivity gate.

The flow is:

```text
runtime randomness
       │
       ▼
random IPv4 generation
       │
       ▼
address filtering
       │
       ▼
inet_addr()
       │
       ▼
0x00407480
       │
       ▼
TCP/445 reachability
       │
       ├── failure → discard
       │
       └── success
               │
               ▼
        0x00407540
```

This complements local subnet enumeration:

```text
0x00407720
    → local network enumeration

0x00407840
    → randomized IPv4 generation
```

Both paths converge on the same propagation engine.

---

# 11. TCP/445 Connectivity Gate

`0x00407480` performs the initial network reachability test.

The routine creates a TCP socket:

```text
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
```

configures it for non-blocking operation:

```text
ioctlsocket(FIONBIO)
```

and attempts:

```text
connect(target, 445)
```

The connection state is then evaluated through:

```text
select()
```

followed by:

```text
closesocket()
```

The architectural role is:

```text
candidate target
      │
      ▼
TCP/445 connectivity
      │
      ├── not reachable → stop
      │
      └── reachable
             │
             ▼
       SMB processing
```

This gate prevents the more expensive SMB processing path from being entered for targets that do not pass the initial TCP connectivity stage.

---

# 12. Per-Target Propagation Worker

`0x004076B0` is the per-target supervisor.

It receives a target IPv4 address and first invokes:

```text
0x00407480
```

Only a successful connectivity result causes creation of the secondary worker:

```text
0x00407540
```

The worker is monitored for up to ten minutes.

The resulting structure is:

```text
target IP
   │
   ▼
0x004076B0
   │
   ▼
0x00407480
   │
   ├── fail → cleanup
   │
   └── success
          │
          ▼
     0x00407540
          │
          ▼
      SMB stages
```

This creates a layered propagation model:

1. target discovery;
    
2. TCP reachability;
    
3. per-target worker;
    
4. SMB processing.
    

---

# 13. SMB Propagation

`0x00407540` represents the main per-target propagation stage.

Its execution can be reconstructed as:

```text
Target
  │
  ▼
TCP/445 gate
  │
  ▼
0x00401980
  │
  ├── SMB negotiation
  ├── Session Setup
  ├── IPC$ Tree Connect
  └── protocol qualification
  │
  ▼
0x00401B70
  │
  └── SMB Transaction2 stage
  │
  ▼
0x00401370
  │
  └── table-driven SMB/network processing
  │
  ▼
0x004072A0
  │
  └── staged payload transfer
```

Not every stage was dynamically completed in the controlled environment. Where the target terminated or reset the SMB connection, later behaviour was reconstructed statically from the local binary.

---

# 14. SMB Protocol Qualification — `0x00401980`

`0x00401980` performs the initial SMB1 protocol interaction.

The observed sequence is:

```text
TCP connection to 445
        │
        ▼
SMB_COM_NEGOTIATE (0x72)
        │
        ▼
SMB_COM_SESSION_SETUP_ANDX (0x73)
        │
        ▼
STATUS_ACCESS_DENIED
        │
        ▼
IPC$ Tree Connect
        │
        ▼
SMB_COM_TREE_CONNECT_ANDX (0x75)
        │
        ▼
connection reset
```

The function constructs:

```text
\\<target>\IPC$
```

and incorporates response-derived SMB session state into the following request.

The important finding is that the function implements a stateful SMB sequence rather than sending an isolated SMB packet.

The later transaction stage was present in the static packet templates but was not fully reproduced dynamically in the controlled execution.

---

# 15. SMB Transaction2 Stage — `0x00401B70`

`0x00401B70` establishes another SMB connection and repeats the initial SMB negotiation/session sequence.

The static reconstruction then identifies:

```text
SMB_COM_TRANSACTION2 (0x32)
```

following the IPC$ Tree Connect stage.

Selected fields of the transaction request are populated from the preceding receive buffer.

The logical sequence is:

```text
NEGOTIATE
    │
    ▼
SESSION_SETUP
    │
    ▼
IPC$ TREE_CONNECT
    │
    ▼
TRANSACTION2
    │
    ▼
response-dependent processing
```

Because the controlled target did not provide the expected response at the preceding stage, the complete transaction exchange was not dynamically observed.

Therefore the report treats this as a **statically reconstructed SMB transaction stage**, rather than claiming a fully reproduced remote exploit.

---

# 16. Table-Driven Network Processing — `0x00401370`

`0x00401370` implements a table-driven network/protocol engine.

A global descriptor table at:

```text
0x00431480
```

contains entries with a fixed stride of:

```text
0x2728
```

The first field determines the operation type.

Observed operations include:

```text
Type 2 → socket + connect
Type 3 → closesocket
Type 0 → data preparation + send
Type 1 → recv + response-state extraction
```

The routine also processes state associated with:

```text
treeid
userid
```

This makes the function a protocol-processing engine rather than an individual network operation.

Its relationship with the surrounding propagation architecture is:

```text
SMB state
   │
   ▼
descriptor table
   │
   ├── connect
   ├── send
   ├── recv
   └── close
```

The complete descriptor-driven protocol was outside the scope of the analysis.

---

# 17. DOUBLEPULSAR-related Stage

The strongest direct evidence for the DOUBLEPULSAR relationship is `0x00406ED0`.

The function accepts a DWORD and calculates:

```c
uint32_t x =
    (((s & 0x0000FF00) | (s << 16)) << 8) |
    (((s >> 16) | (s & 0x00FF0000)) >> 8);

return (2 * s) ^ x;
```

This is the known DOUBLEPULSAR XOR-key derivation algorithm. The same algorithm is documented in public DOUBLEPULSAR research and tooling.

This is stronger evidence than simply observing SMB traffic: the local sample contains the same specific algorithmic transformation used by DOUBLEPULSAR.

The architecture can therefore be represented as:

```text
SMB response
      │
      ▼
response-derived DWORD
      │
      ▼
0x00406ED0
      │
      ▼
DOUBLEPULSAR-compatible XOR key
      │
      ▼
subsequent payload-processing path
```

The analysis does not claim that `0x00401370` itself is the complete DOUBLEPULSAR implementation. Instead, the evidence establishes that the analyzed SMB propagation component contains a DOUBLEPULSAR-related protocol stage.

---

# 18. Payload Preparation — `0x00406F50`

`0x00406F50` is the main bridge between the prepared payload buffers and the network transfer.

It selects:

```text
[0x70F864]
```

or:

```text
[0x70F868]
```

depending on its mode argument.

These are the buffers previously constructed by `0x00407A20`.

The selected data is copied into a newly allocated working buffer.

The resulting flow is:

```text
0x70F864 / 0x70F868
       │
       ▼
GlobalAlloc()
       │
       ▼
transfer context
       │
       ▼
0x00406F00
       │
       ▼
packet construction
```

This establishes direct data-flow continuity between the embedded executable material identified during initialization and the later propagation stage.

---

# 19. Repeating XOR Transformation — `0x00406F00`

The transformation routine applies:

```c
for (i = 0; i < length; i++)
    buffer[i] ^= key[i & 3];
```

The key is therefore repeated every four bytes:

```text
K0 K1 K2 K3 K0 K1 K2 K3 ...
```

The function is best classified as a repeating XOR transformation.

The observed code does not by itself establish whether the operation represents encoding or decoding because XOR is symmetric.

Its architectural role is clear:

```text
prepared payload
      │
      ▼
0x00406F00
      │
      ▼
transformed transfer data
      │
      ▼
network packet
```

---

# 20. Chunked Payload Transfer

The payload transfer stage divides the prepared data into `0x1000`-byte chunks.

For each chunk:

```text
prepare data
     │
     ▼
0x00406F00
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
     ├── no → terminate transfer
     │
     └── yes
           │
           ▼
       next 0x1000 bytes
```

After the full chunks are transmitted, a final variable-length block is generated for the remaining data.

This is an acknowledgement-driven staged transfer mechanism.

The exact remote-side interpretation of the transmitted payload cannot be established solely from the local sample.

---

# 21. Complete Propagation Data Flow

The complete reconstructed network path is:

```text
                 TARGET DISCOVERY
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
   Local subnet              Random IPv4
   enumeration               generation
          │                         │
          └────────────┬────────────┘
                       ▼
                0x004076B0
                       │
                       ▼
                0x00407480
                 TCP/445 gate
                       │
                       ▼
                0x00407540
                       │
          ┌────────────┼─────────────┐
          │            │             │
          ▼            ▼             ▼
      0x00401980   0x00401B70   0x00401370
          │            │             │
          │            └──────┬──────┘
          │                   │
          └───────────────────┘
                       │
                       ▼
              DOUBLEPULSAR-related
                  processing
                       │
                       ▼
                 0x004072A0
                       │
                       ▼
                 0x00406F50
                       │
                       ▼
             staged payload buffer
                       │
                       ▼
                 0x00406F00
                       │
                       ▼
                chunk construction
                       │
                       ▼
                    send()
                       │
                       ▼
                 remote target
```

---

# 22. Functional Interpretation

The reverse-engineered propagation architecture can be divided into four layers.

### Layer 1 — Target discovery

```text
local adapter enumeration
+
random IPv4 generation
```

### Layer 2 — Target qualification

```text
TCP/445 connectivity
```

### Layer 3 — SMB propagation

```text
SMB negotiation
Session Setup
IPC$ Tree Connect
Transaction2
protocol/state processing
```

### Layer 4 — Payload transfer

```text
embedded PE/self-image
        ↓
staged buffers
        ↓
transfer context
        ↓
XOR transformation
        ↓
chunked SMB transfer
```

This layered architecture explains why the sample contains multiple independent network functions rather than a single monolithic propagation routine.

---

# 23. What Was Dynamically Confirmed

The following behaviour was directly observed or strongly established through runtime execution:

- kill-switch network access;
    
- service execution;
    
- Winsock initialization;
    
- local adapter/network enumeration;
    
- TCP/445 connectivity checks;
    
- SMB negotiation and session establishment;
    
- IPC$ tree connection attempts;
    
- response-dependent SMB processing;
    
- network worker creation;
    
- target-processing timeouts;
    
- payload-buffer creation;
    
- selection of staged payload buffers;
    
- construction of transfer contexts;
    
- network transmission routines.
    

The following stages were reconstructed primarily through static analysis because the controlled target did not reproduce the complete remote-side behaviour:

- complete SMB Transaction2 exchange;
    
- full DOUBLEPULSAR remote-side interaction;
    
- final remote payload execution;
    
- exact semantics of the remote target after payload transmission.
    

---

# 24. Final Architecture

The resulting model of the analyzed sample is:

```text
                    ENTRY POINT
                        │
                        ▼
                   KILL SWITCH
                        │
                 ┌──────┴──────┐
                 │             │
              success       failure
                 │             │
                exit           ▼
                         MODE SELECTION
                              │
                 ┌────────────┴────────────┐
                 │                         │
          persistence /              service execution
          payload deployment                │
                                            ▼
                                     NETWORK INIT
                                            │
                              ┌─────────────┴─────────────┐
                              │                           │
                        local discovery             random discovery
                              │                           │
                              └─────────────┬─────────────┘
                                            ▼
                                      TCP/445 gate
                                            │
                                            ▼
                                    SMB propagation
                                            │
                                            ▼
                              DOUBLEPULSAR-related stage
                                            │
                                            ▼
                                   payload preparation
                                            │
                                            ▼
                                  chunked network transfer
```

The central architectural finding is the continuity between the initial payload construction and the later propagation stage:

```text
embedded PE data
      ↓
0x00407A20
      ↓
0x70F864 / 0x70F868
      ↓
0x00406F50
      ↓
0x00406F00
      ↓
SMB/network packet construction
      ↓
remote transmission
```

This provides a coherent local explanation of how the analyzed WannaCry sample combines execution, persistence, target discovery, SMB propagation, DOUBLEPULSAR-related protocol processing, and payload transfer.