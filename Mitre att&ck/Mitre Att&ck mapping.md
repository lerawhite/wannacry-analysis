
---
## 1. Overview

This mapping describes the MITRE ATT&CK techniques associated with **WannaCry (S0366)** and relates them to the behavior identified during the analysis of the examined sample.

The mapping distinguishes between:

- **Confirmed in this analysis** — directly supported by static and/or dynamic analysis of the examined sample.
    
- **Documented by MITRE / not fully reproduced** — officially associated with WannaCry, but outside the directly verified scope of this analysis.
    

The distinction is important because ATT&CK represents the broader publicly documented capabilities of WannaCry, while this project focuses primarily on its execution, persistence, network discovery, SMB propagation, and payload-transfer architecture.

---

## 2. Enterprise ATT&CK Mapping

| Tactic              | Technique                                                        | ID        | Status in this Analysis                                  |
| ------------------- | ---------------------------------------------------------------- | --------- | -------------------------------------------------------- |
| Persistence         | Create or Modify System Process: Windows Service                 | T1543.003 | **Confirmed**                                            |
| Impact              | Data Encrypted for Impact                                        | T1486     | Documented by MITRE; not deeply reversed in this project |
| Command and Control | Encrypted Channel: Asymmetric Cryptography                       | T1573.002 | Documented by MITRE; not reproduced in this project      |
| Lateral Movement    | Exploitation of Remote Services                                  | T1210     | **Confirmed / strongly supported**                       |
| Discovery           | File and Directory Discovery                                     | T1083     | Documented by MITRE; not deeply reversed in this project |
| Defense Evasion     | File and Directory Permissions Modification: Windows Permissions | T1222.001 | **Confirmed**                                            |
| Defense Evasion     | Hide Artifacts: Hidden Files and Directories                     | T1564.001 | **Confirmed**                                            |
| Impact              | Inhibit System Recovery                                          | T1490     | Documented by MITRE; not deeply reversed in this project |
| Lateral Movement    | Lateral Tool Transfer                                            | T1570     | **Supported by propagation architecture**                |
| Discovery           | Peripheral Device Discovery                                      | T1120     | Documented by MITRE; not reproduced in this project      |
| Command and Control | Proxy: Multi-hop Proxy                                           | T1090.003 | Documented by MITRE; not reproduced in this project      |
| Lateral Movement    | Remote Services: RDP Hijacking                                   | T1563.002 | Documented by MITRE; not reproduced in this project      |
| Discovery           | Remote System Discovery                                          | T1018     | **Confirmed**                                            |
| Impact              | Service Stop                                                     | T1489     | Documented by MITRE; not deeply reversed in this project |
| Discovery           | System Network Configuration Discovery                           | T1016     | **Confirmed**                                            |
| Execution           | Windows Management Instrumentation                               | T1047     | Documented by MITRE; not reproduced in this project      |

> **Note:** The table contains 17 rows because several techniques belong to different ATT&CK tactics. MITRE's current WannaCry software page associates these techniques with S0366.

---

# 3. Technique Details

## T1543.003 — Create or Modify System Process: Windows Service

**Tactic:** Persistence

**Status:** Confirmed

WannaCry creates the Windows service `mssecsvc2.0` with the display name `Microsoft Security Center (2.0)`.

The analyzed sample uses:

```text
CreateServiceA
    ↓
mssecsvc2.0
    ↓
Microsoft Security Center (2.0)
    ↓
<malware path> -m security
    ↓
StartServiceA
```

The service is configured for automatic startup and provides the service-based execution path implemented by `ServiceMain`.

This behavior directly corresponds to T1543.003.

---

## T1486 — Data Encrypted for Impact

**Tactic:** Impact

**Status:** Documented by MITRE; outside the primary reverse-engineering scope of this project

WannaCry is documented as encrypting targeted user files using its ransomware functionality.

The current project focuses on the executable's propagation and execution architecture rather than performing a complete reverse engineering of the ransomware encryption subsystem.

MITRE associates WannaCry with T1486.

---

## T1573.002 — Encrypted Channel: Asymmetric Cryptography

**Tactic:** Command and Control

**Status:** Documented by MITRE; not reproduced in this project

MITRE documents WannaCry's use of Tor and cryptographic communication mechanisms.

This functionality was not the focus of the examined network-propagation path and was not independently reproduced during the laboratory analysis.

---

## T1210 — Exploitation of Remote Services

**Tactic:** Lateral Movement

**Status:** Confirmed / strongly supported

The analyzed sample contains an SMB-based propagation chain targeting TCP port 445.

The architecture includes:

```text
Local / Random Target Discovery
          ↓
TCP/445 Reachability Check
          ↓
SMB Negotiation
          ↓
Session Setup
          ↓
IPC$ Tree Connection
          ↓
SMB Transaction Processing
          ↓
DOUBLEPULSAR-related Processing
          ↓
Payload Transfer
```

The sample contains SMB1 protocol structures and a propagation workflow associated with exploitation of vulnerable SMB services.

MITRE explicitly maps WannaCry's SMBv1 exploitation to T1210.

---

## T1083 — File and Directory Discovery

**Tactic:** Discovery

**Status:** Documented by MITRE; not deeply reversed in this project

MITRE documents WannaCry searching for user files by extension before encryption.

This functionality belongs to the ransomware impact component and was not the primary subject of the current reverse-engineering workflow.

---

## T1222.001 — File and Directory Permissions Modification: Windows Permissions

**Tactic:** Defense Evasion

**Status:** Confirmed statically

The sample contains commands associated with modification of file attributes and permissions, including:

```text
attrib +h
icacls . /grant Everyone:F /T /C /Q
```

These operations make selected files hidden and modify their access permissions.

MITRE explicitly maps these WannaCry behaviors to T1222.001.

---

## T1564.001 — Hide Artifacts: Hidden Files and Directories

**Tactic:** Defense Evasion

**Status:** Confirmed statically

The sample contains the command:

```text
attrib +h
```

This operation is used to mark files as hidden.

The behavior corresponds to T1564.001.

---

## T1490 — Inhibit System Recovery

**Tactic:** Impact

**Status:** Documented by MITRE; not deeply reversed in this project

MITRE documents WannaCry's use of Windows utilities including `vssadmin`, `wbadmin`, `bcdedit`, and `wmic` to interfere with operating-system recovery mechanisms.

This component was outside the main propagation-focused reverse-engineering scope.

---

## T1570 — Lateral Tool Transfer

**Tactic:** Lateral Movement

**Status:** Supported by the analyzed propagation architecture

The analyzed sample constructs and stages executable data for network transmission.

The relevant data flow is:

```text
Embedded PE / Self-image
        ↓
Runtime staging buffers
        ↓
Payload preparation
        ↓
XOR transformation
        ↓
SMB-based packet construction
        ↓
Network transmission
```

The analysis therefore establishes executable payload transfer as part of the propagation architecture.

MITRE also maps WannaCry's SMB-based copying of itself to remote systems to T1570.

---

## T1120 — Peripheral Device Discovery

**Tactic:** Discovery

**Status:** Documented by MITRE; not reproduced in this project

MITRE documents a WannaCry thread that searches for newly attached drives and processes files on those devices.

This behavior was outside the scope of the current propagation-focused analysis.

---

## T1090.003 — Proxy: Multi-hop Proxy

**Tactic:** Command and Control

**Status:** Documented by MITRE; not reproduced in this project

MITRE associates WannaCry with Tor-based communications and maps this behavior to the Multi-hop Proxy sub-technique.

No Tor-based communication was reconstructed in the analyzed SMB propagation path.

---

## T1563.002 — Remote Service Session Hijacking: RDP Hijacking

**Tactic:** Credential Access / Lateral Movement

**Status:** Documented by MITRE; not reproduced in this project

MITRE documents WannaCry's enumeration of active Remote Desktop sessions and execution attempts within those sessions.

This functionality was not part of the analyzed execution path.

---

## T1018 — Remote System Discovery

**Tactic:** Discovery

**Status:** Confirmed

The sample implements two complementary target-selection mechanisms:

```text
Local network discovery
        +
Random IPv4 generation
        ↓
Candidate target
        ↓
TCP/445 reachability
```

The local-network path enumerates adapter configuration, calculates network and broadcast boundaries, generates usable host addresses, filters private address ranges, and normalizes the resulting target set.

The randomized path generates IPv4 addresses and subjects them to the same TCP/445 propagation gate.

This behavior corresponds to remote-system discovery. MITRE explicitly maps WannaCry's local network scanning to T1018.

---

## T1489 — Service Stop

**Tactic:** Impact

**Status:** Documented by MITRE; not deeply reversed in this project

MITRE documents WannaCry attempting to stop processes associated with services such as Exchange, Microsoft SQL Server, and MySQL before encryption.

This functionality was outside the main scope of the current reverse-engineering analysis.

---

## T1016 — System Network Configuration Discovery

**Tactic:** Discovery

**Status:** Confirmed

The sample calls `GetAdaptersInfo` and related networking APIs to enumerate local adapter configuration.

The resulting information is used to derive:

- local IPv4 addresses;
    
- subnet information;
    
- network boundaries;
    
- broadcast addresses;
    
- usable host ranges.
    

The collected addresses are then passed into the propagation worker architecture.

This directly corresponds to T1016.

---

## T1047 — Windows Management Instrumentation

**Tactic:** Execution

**Status:** Documented by MITRE; not reproduced in this project

MITRE documents WannaCry using `wmic` as part of its recovery-inhibition functionality.

The WMI-related functionality was not independently reproduced during the current analysis.

---

# 4. Analysis-Specific ATT&CK Coverage

The strongest ATT&CK coverage established by this project is concentrated in the following chain:

```text
T1016
System Network Configuration Discovery
        ↓
T1018
Remote System Discovery
        ↓
T1210
Exploitation of Remote Services
        ↓
T1570
Lateral Tool Transfer
        ↓
Payload Transfer / Propagation
```

Persistence is represented separately:

```text
T1543.003
Windows Service
        ↓
mssecsvc2.0
        ↓
ServiceMain
        ↓
Network propagation subsystem
```

The project also provides direct evidence for:

```text
T1222.001  → Windows permission modification
T1564.001  → Hidden files
```

The ransomware-specific impact and additional discovery/C2 techniques documented by MITRE are intentionally marked as outside the directly reproduced scope rather than being presented as dynamically verified behavior.

# 5. ATT&CK Interpretation

The analyzed sample demonstrates that WannaCry is not a single-purpose ransomware component. Its architecture combines:

1. **Persistence** through a Windows service.
    
2. **Network configuration discovery**.
    
3. **Remote-system discovery**.
    
4. **SMB-based remote-service exploitation**.
    
5. **Network propagation and payload transfer**.
    
6. **Executable payload staging and transformation**.
    
7. **Defense-evasion operations** through file hiding and permission modification.
    
8. **Ransomware impact functionality** documented separately by ATT&CK.
    

The most distinctive part of the analyzed sample is the propagation chain, where network discovery, SMB protocol processing, DOUBLEPULSAR-related key derivation, and staged executable transfer form a continuous execution architecture.

The ATT&CK mapping should therefore be interpreted as a combination of **capabilities documented for WannaCry as a malware family** and **behaviors directly established during this sample-specific reverse-engineering project**.