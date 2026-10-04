`Raw Imports&Functions located in -  Dumps/Static/Raw_Imports&Functions(DIE)`

---
 
I extracted the imported modules and their functions, organized them into logical behavioral groups, and developed preliminary hypotheses about the malware's potential capabilities and behavior.

**All system modules:**
``` import_dll
|KERNEL32.dll|
|ADVAPI32.dll|
|WS2_32.dll|
|MSVCP60.dll|
|iphlpapi.dll|
|WININET.dll|
|MSVCRT.dll|
```


---

## Kernel32.dll_Analysis
### 1. File System Operations

|Function|Role|
|---|---|
|`CreateFileA`|Opens or creates a file/object|
|`ReadFile`|Reads data from a file|
|`GetFileSize`|Retrieves file size|
|`MoveFileExA`|Moves/renames a file, optionally with replacement/deferred operation|
|`CloseHandle`|Closes a file/object handle|

**Capability:**
> **File system access and file manipulation**


### 2. Resource Management

|Function|Role|
|---|---|
|`FindResourceA`|Locates a resource in the PE|
|`LoadResource`|Loads a resource into memory|
|`LockResource`|Obtains a pointer to resource data|
|`SizeofResource`|Retrieves resource size|

Logical chain:

```
FindResourceA
      ↓
SizeofResource
      ↓
LoadResource
      ↓
LockResource
      ↓
resource data
```

**Capability:**

> **Embedded resource access and extraction**



### 3. Dynamic API / Module Resolution

|Function|Role|
|---|---|
|`GetModuleHandleA`|Retrieves handle of loaded module|
|`GetModuleHandleW`|Unicode variant|
|`GetProcAddress`|Resolves address of exported function|

logics:

```
GetModuleHandle*
       ↓
GetProcAddress
       ↓
resolve API address
```

**Capability:**

> **Dynamic module/function resolution**.


- runtime API resolution;
- reduced/static imports;
- optional functionality;
- compatibility logic;
- indirect API invocation.


### 4. Process / Thread Termination & Synchronization


There are several different functions here, but I would group them under a broader category of **Execution / Thread Management**.

|Function|Role|
|---|---|
|`GetCurrentThread`|Retrieves pseudo-handle of current thread|
|`GetCurrentThreadId`|Retrieves current thread ID|
|`TerminateThread`|Terminates a thread|
|`ExitProcess`|Terminates current process|
|`WaitForSingleObject`|Waits for an object/thread/process|
|`Sleep`|Suspends execution|
|`GetStartupInfoA`|Retrieves process startup information|

I would further divide this category into two subgroups.

#### Thread / process control

```
GetCurrentThread
GetCurrentThreadId
TerminateThread
ExitProcess
```

#### Execution timing / synchronization

```
WaitForSingleObject
Sleep
```


I would highlight `GetStartupInfoA` separately as:

> **Process initialization / startup information**

Because its behavioral role is different.

### 5. Synchronization / Thread Safety

This deserves a separate block because it contains a complete set of **critical section primitives**:

|Function|Role|
|---|---|
|`InitializeCriticalSection`|Initializes critical section|
|`EnterCriticalSection`|Acquires critical section|
|`LeaveCriticalSection`|Releases critical section|
|`InterlockedIncrement`|Atomic increment|
|`InterlockedDecrement`|Atomic decrement|

**Capability:**

> **Thread synchronization and shared-state management**

A particularly interesting combination is:

```
InitializeCriticalSection
        ↓
EnterCriticalSection
        ↓
shared operation
        ↓
LeaveCriticalSection
```

and:

```
InterlockedIncrement
InterlockedDecrement
```

May indicate about:

- reference counters;
- shared state;
- multithreaded execution;
- synchronization of worker threads.


### 6. Memory Allocation / Deallocation

|Function|Role|
|---|---|
|`LocalAlloc`|Allocates local heap memory|
|`LocalFree`|Frees local memory|
|`GlobalAlloc`|Allocates global heap memory|
|`GlobalFree`|Frees global memory|

**Capability:**

> **Dynamic memory management**

This can be visualized as:

```
GlobalAlloc / LocalAlloc
        ↓
memory buffer
        ↓
processing
        ↓
GlobalFree / LocalFree
```


For Wannacry it is potencially interested like:

- resource processing;
- embedded data;
- buffers;
- cryptographic operations;
- dynamically constructed data.

But now it is only hypothesis.


### 7. Timing / Performance Measurement

|Function|Role|
|---|---|
|`QueryPerformanceFrequency`|Retrieves high-resolution performance counter frequency|
|`QueryPerformanceCounter`|Retrieves high-resolution counter value|
|`GetTickCount`|Retrieves system uptime in milliseconds|

**Capability:**

> **Timing and execution measurement**

I would **definitely highlight this block separately**, as it may be of particular interest from a malware-analysis perspective.

Such functions may be used for:

- performance measurement;
- timeout logic;
- delays;
- synchronization;
- execution profiling;
- potentially timing-based anti-analysis.

But now:

> **Potential timing / anti-analysis capability**



### 9. Complete DLL Overview


|Logical Block|APIs|Potential Capability|
|---|---|---|
|**File System**|`CreateFileA`, `ReadFile`, `GetFileSize`, `MoveFileExA`, `CloseHandle`|File access and manipulation|
|**Resource Management**|`FindResourceA`, `LoadResource`, `LockResource`, `SizeofResource`|Embedded resource access|
|**Dynamic API Resolution**|`GetModuleHandleA/W`, `GetProcAddress`|Runtime module/function resolution|
|**Thread / Process Control**|`GetCurrentThread`, `GetCurrentThreadId`, `TerminateThread`, `ExitProcess`, `WaitForSingleObject`, `Sleep`|Thread/process control and execution management|
|**Synchronization**|`InitializeCriticalSection`, `EnterCriticalSection`, `LeaveCriticalSection`, `InterlockedIncrement/Decrement`|Thread synchronization/shared state|
|**Memory Management**|`LocalAlloc`, `LocalFree`, `GlobalAlloc`, `GlobalFree`|Dynamic memory allocation|
|**Module Identification**|`GetModuleFileNameA`|Module/executable path discovery|
|**Timing**|`QueryPerformanceFrequency`, `QueryPerformanceCounter`, `GetTickCount`|Timing and execution measurement|
|**Process Initialization**|`GetStartupInfoA`|Process startup information|

---

Conclusion:

> **Kernel32 imports indicate several functional capabilities, including file manipulation, embedded resource access, dynamic API resolution, dynamic memory management, thread synchronization, process/thread control and timing operations. The combination of resource-management and file-system APIs is particularly relevant given the presence of an embedded PE payload in `.rsrc`. These findings provide several candidate execution paths for further investigation during deep reverse engineering.**



---

## Advapi32.dll_analysis

### 1. Windows Service Management

#### Service Installation / Configuration

| Function                | Description                                                              |
| ----------------------- | ------------------------------------------------------------------------ |
| `OpenSCManagerA`        | **Opens a connection to the Service Control Manager.**                   |
| `CreateServiceA`        | **Creates and registers a new Windows service.**                         |
| `OpenServiceA`          | **Opens an existing Windows service.**                                   |
| `ChangeServiceConfig2A` | **Modifies additional configuration parameters of an existing service.** |
| `StartServiceA`         | **Starts a registered Windows service.**                                 |
| `CloseServiceHandle`    | **Closes a handle to a service or Service Control Manager object.**      |
|                         |                                                                          |

#### Static inference

> **These APIs indicate the capability to interact with the Windows Service Control Manager, including service creation, configuration, opening and execution.**

A particularly interesting combination is:

```
OpenSCManagerA
      ↓
CreateServiceA
      ↓
ChangeServiceConfig2A
      ↓
StartServiceA
```


> **The combination of `CreateServiceA`, `ChangeServiceConfig2A` and `StartServiceA` strongly suggests service-based execution and potentially service-based persistence.**




### 2. Service Process / SCM Communication

|Function|Description|
|---|---|
|`StartServiceCtrlDispatcherA`|**Connects the process to the Service Control Manager and starts the service control dispatcher.**|
|`RegisterServiceCtrlHandlerA`|**Registers a control handler responsible for processing service control requests.**|
|`SetServiceStatus`|**Reports the current service status to the Service Control Manager.**|

#### Static inference

> **These APIs indicate that the sample contains functionality for operating as a Windows service process and communicating its execution state to the Service Control Manager.**

Logical:

```
StartServiceCtrlDispatcherA
            ↓
RegisterServiceCtrlHandlerA
            ↓
service execution
            ↓
SetServiceStatus
```



> **The presence of `StartServiceCtrlDispatcherA`, `RegisterServiceCtrlHandlerA` and `SetServiceStatus` suggests that the sample may contain a dedicated service execution path.**



### 3. Cryptographic Functionality

|Function|Description|
|---|---|
|`CryptAcquireContextA`|**Acquires a handle to a cryptographic service provider.**|
|`CryptGenRandom`|**Generates cryptographically secure random data.**|

#### Static inference

> **These APIs indicate the presence of cryptographic functionality involving a Cryptographic Service Provider and generation of cryptographically secure random data.**

Potencially chain:

```
CryptAcquireContextA
        ↓
CryptGenRandom
        ↓
random data
```


> **The purpose of the generated random data cannot be determined from the imports alone and requires further reverse engineering.**



---

## WININET.DLL

### 1. Network Communication

|Function|Description|
|---|---|
|`InternetOpenA`|**Initializes a WinINet session and establishes the context for subsequent Internet operations.**|
|`InternetOpenUrlA`|**Opens a specified URL and initiates a request to the remote resource.**|
|`InternetCloseHandle`|**Closes a WinINet handle and releases associated resources.**|

#### Logical subsequence

```
InternetOpenA
      ↓
InternetOpenUrlA
      ↓
remote resource / response
      ↓
InternetCloseHandle
```

#### Static inference

> **These imports indicate HTTP/Internet communication capabilities through the Windows WinINet API.**


> **The presence of WinINet APIs is consistent with the previously identified network-related indicators and suggests that the sample may perform outbound Internet requests.**

But:

> **The imports alone do not determine the destination, protocol details, request parameters or purpose of the communication.**



---

## WS2_32.DLL — Import Anomaly

> **The sample appears to reference multiple WS2_32 networking functions, while these functions are not displayed by PE-bear as conventional imports.**



> **This discrepancy may be caused by dynamic API resolution, non-standard import representation, parser limitations, or modification of the PE import structures.**



> **The presence of `GetModuleHandleA/W` and `GetProcAddress` provides a potential mechanism for resolving networking APIs dynamically at runtime. This hypothesis should be investigated during deep reverse engineering.**


---


## IPHLPAPI.DLL


```
GetAdaptersInfo
GetPerAdaptersInfo
```

---

### `GetAdaptersInfo`

|                     |                                                                                |
| ------------------- | ------------------------------------------------------------------------------ |
| `GetAdaptersInfo`   | Enumerates network adapters and retrieves their configuration information.     |
| `GetPerAdapterInfo` | Retrieves additional configuration information for a specific network adapter. |

#### Static inference

> **The presence of `GetAdaptersInfo` indicates that the sample can enumerate local network adapter information.**


It can be used for:

- obtaining local network configuration;
- identifying network interfaces;
- determining IP addresses;
- collecting adapter information;
- network environment awareness.