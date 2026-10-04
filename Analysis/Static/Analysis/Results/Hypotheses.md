
---

| ID  | Hypothesis                      | Static Evidence                     | Confidence | Deep RE Objective                                        |
| --- | ------------------------------- | ----------------------------------- | ---------- | -------------------------------------------------------- |
| H1  | Embedded PE/resource processing | PE blob in `.rsrc`, resource APIs   | High       | Identify extraction/processing path                      |
| H2  | Payload extraction/deployment   | Embedded PE + file APIs             | Medium     | Determine whether payload is written/executed            |
| H3  | Windows service execution       | Service APIs                        | High       | Reconstruct service installation/execution               |
| H4  | Kill-switch network request     | Domain string + WinINet APIs        | High       | Identify request and conditional branch                  |
| H5  | Network adapter discovery       | `GetAdaptersInfo`                   | Medium     | Determine purpose of adapter enumeration                 |
| H6  | Dynamic WS2_32 resolution       | Missing imports + `GetProcAddress`  | Medium     | Identify runtime-resolved APIs                           |
| H7  | Network propagation             | WS2_32/IPHLPAPI capabilities        | Medium     | Reconstruct network propagation logic                    |
| H8  | Cryptographic processing        | Crypto APIs + crypto strings        | Medium     | Identify purpose of crypto operations                    |
| H9  | File encryption/processing      | File APIs + crypto functionality    | Medium     | Identify file-processing pipeline                        |
| H10 | Multithreaded execution         | Thread/synchronization APIs         | High       | Identify worker threads and synchronization              |
| H11 | Timing-based logic              | QPC/GetTickCount/Sleep              | Low/Medium | Determine whether timing is operational or anti-analysis |
| H12 | Dynamic API resolution          | `GetProcAddress`/`GetModuleHandle*` | Medium     | Identify dynamically resolved APIs                       |


