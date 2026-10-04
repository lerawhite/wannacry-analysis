
---


## PATH A — Initialization / Kill-switch

```
                 Entry Point
                     ↓
               initialization
                     ↓
              network module
                     ↓
               InternetOpenA
                     ↓
             InternetOpenUrlA
                     ↓
              kill-switch URL
                     ↓
                response
                /      \
               /        \
        kill switch     continue
            ↓              ↓
        terminate       main execution
```



---

# PATH B — Resource / Payload

```
Entry Point
    ↓
resource handling
    ↓
FindResourceA
    ↓
LoadResource
    ↓
LockResource
    ↓
embedded PE
    ↓
ZIP container
    ↓
payload files
    ↓
decompression/decryption
    ↓
execution / deployment
```

---

# PATH C — Service installation (persistance)

```
Main execution
      ↓
OpenSCManagerA
      ↓
CreateServiceA
      ↓
ChangeServiceConfig2A
      ↓
StartServiceA
      ↓
service process
      ↓
StartServiceCtrlDispatcherA
      ↓
RegisterServiceCtrlHandlerA
      ↓
SetServiceStatus
```


---

# PATH D — Network discovery / propagation

```
Network module
      ↓
GetAdaptersInfo
      ↓
local interface information
      ↓
WS2_32 APIs
      ↓
network communication
      ↓
potential target discovery
      ↓
potential propagation
```



---

# PATH E — File processing / Cryptography

```
File discovery/access
      ↓
CreateFileA
      ↓
GetFileSize
      ↓
ReadFile
      ↓
cryptographic operation
      ↓
file modification
      ↓
MoveFileExA / other file operation
```



---

# PATH F — Dynamic API resolution



```
GetModuleHandleA/W
        ↓
GetProcAddress
        ↓
resolve API
        ↓
indirect call
        ↓
network / system functionality
```



# PATH G — Working with two embended pe_blob in .data

