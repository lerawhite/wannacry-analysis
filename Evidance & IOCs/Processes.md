
---

## Function 0x00408090

>`mssecsvc2.0`

- **Type:** Windows Service
- **Evidence:** `OpenServiceA` opens the `mssecsvc2.0` service through the local Service Control Manager. The same service name is then provided to `StartServiceCtrlDispatcherA` through `lpServiceName`.
- **Role:** Service-oriented execution / persistence
- **Importance:** Identifies the Windows service used by the sample to enter the service execution path.

> `ServiceMain - 0x00408000`

- **Type:** Process execution / Service entry point
- **Evidence:** `StartServiceCtrlDispatcherA` receives a `SERVICE_TABLE_ENTRYA` containing `lpServiceName = "mssecsvc2.0"` and `lpServiceProc = 0x00408000`.
- **Role:** Service execution
- **Importance:** Establishes the relationship between the `mssecsvc2.0` service and the malware's `ServiceMain` routine.


---

## Function 0x00407CE0

> `tasksche.exe /i`

- **Type:** Process command line
- **Evidence:** The runtime stack immediately before `CreateProcessA` contains the command line `C:\WINDOWS\tasksche.exe /i`.
- **Role:** Payload execution
- **Importance:** Identifies the command line used to execute the resource-extracted PE (**.rsrc**) as a separate process.

> `Additional evidance&IOCs`
#### Embedded PE Resource Extraction

- **Evidence:** The sample locates resource `0x727` of type `R` using `FindResourceA`, then processes it through `LoadResource`, `LockResource`, and `SizeofResource`.
- **Behavior:** Embedded executable data is extracted from the sample's own PE image.
- **Importance:** Establishes that the resource is actively used as a payload source rather than being an unused resource.

#### PE Payload Deployment

- **Evidence:** The extracted buffer begins with the `MZ` signature and is written to `C:\WINDOWS\tasksche.exe` using `WriteFile`.
- **Behavior:** An embedded PE is materialized as a standalone executable on disk.
- **Importance:** Directly links the embedded resource to the dropped executable.

#### Payload Execution

- **Evidence:** `CreateProcessA` is invoked with `C:\WINDOWS\tasksche.exe /i` and `CREATE_NO_WINDOW`.
- **Behavior:** The resource-extracted PE is executed as a separate process without creating a console window.
- **Importance:** Confirms the complete resource-to-disk-to-process execution chain.

#### Runtime API Resolution

- **Evidence:** `GetModuleHandleW("kernel32.dll")` and `GetProcAddress` dynamically resolve `CreateProcessA`, `CreateFileA`, `WriteFile`, and `CloseHandle`.
- **Behavior:** Required execution APIs are resolved at runtime rather than being invoked exclusively through direct import references.
- **Importance:** Provides supporting evidence for the execution mechanism identified in this function.

---

## Function 0x00408000

> `Additional evidance&IOCs`

- **ServiceMain:** `0x00408000` is registered as the service entry point associated with `mssecsvc2.0`.
- **Service control handler:** `0x00407F30` is registered through `RegisterServiceCtrlHandlerA` as the control handler for `mssecsvc2.0`.
- **Service status:** The service transitions from `SERVICE_START_PENDING` (`0x02`) to `SERVICE_RUNNING` (`0x04`) and reports the new state through `SetServiceStatus`.
- **Execution transition:** After successful service initialisation, execution continues to `0x00407BD0`, establishing the connection between the Windows service context and the subsequent malware execution stage.


---

## Function 0x00407BD0

> `Additional evidance&IOCs`

- **Worker subsystem:** The function launches `0x00407720` once and subsequently creates up to 128 worker threads executing `0x00407840`.
- **High worker count:** `0x00407840` is launched 128 times with unique arguments ranging from `0` to `127`. This unusually large number of worker-launch attempts is consistent with a dedicated concurrent processing subsystem rather than ordinary application-level execution.
- **Staggered execution:** Worker-launch attempts are separated by `Sleep(2000)`, resulting in an approximately two-second interval between successive worker creations.
- **Independent execution:** Thread handles returned by `_beginthreadex` are immediately released with `CloseHandle`, while the created threads continue executing independently.
- **Execution gate:** All worker creation depends on the successful return of `0x00407B90`; if this function returns `0`, the worker subsystem is not started.
- **Network architecture:** `0x00407BD0` itself does not perform the network operations. It acts as an orchestration layer that establishes the worker subsystem from which the subsequent network execution is reached.


---

## Function 0x00407B90

> `Additional evidance&IOCs`

- **Winsock dependency:** The function initialises Winsock with `WSAStartup(MAKEWORD(2, 2), ...)` before executing the subsequent network-subsystem initialisation stages.
- **Network execution gate:** A non-zero `WSAStartup` return value causes `0x00407B90` to return `0`, which in turn prevents `0x00407BD0` from creating its worker threads.
- **Chained initialisation:** Successful Winsock initialisation enables execution of `0x00407620` and `0x00407A20`, linking Winsock setup to the subsequent cryptographic and payload/network buffer initialisation stages.
- **Worker-subsystem dependency:** The function establishes that the worker subsystem launched by `0x00407BD0` is dependent on successful network-stack initialisation rather than being started unconditionally.


---

## Function 0x00407620

> `Additional evidance&IOCs`

- **Cryptographic provider initialisation:** The function acquires a CryptoAPI provider context using `CryptAcquireContextA` with `PROV_RSA_FULL` and `CRYPT_VERIFYCONTEXT`.
- **Provider fallback:** If the default provider acquisition fails, the function retries using the explicitly specified provider `"Microsoft Base Cryptographic Provider v1.0"`.
- **Cryptographic state:** The resulting provider handle is stored at `0x0070F870`, establishing persistent cryptographic state for subsequent functions.
- **Thread synchronisation:** After provider initialisation, the function calls `InitializeCriticalSection(&0x00431418)`, providing synchronisation for subsequent access to the cryptographic state.
- **Network subsystem dependency:** This initialisation is reached from `0x00407B90` only after successful Winsock initialisation, linking the cryptographic subsystem to the broader network-worker initialisation chain.


---

## Function 0x00407A20

> `Additional evidance&IOCs`

- **Embedded PE blob #1:** `0x0040B020`, size `0x4060` bytes.
  - **Type:** Embedded PE payload
  - **Evidence:** The function copies `0x4060` bytes from the embedded image at `0x0040B020` into the first dynamically allocated buffer at `0x0070F864`.
  - **Role:** In-memory payload staging
  - **Importance:** Establishes one of the embedded PE components used by the network subsystem.

- **Embedded PE blob #2:** `0x0040F080`, size `0xC8A4` bytes.
  - **Type:** Embedded PE payload
  - **Evidence:** The function copies `0xC8A4` bytes from the embedded image at `0x0040F080` into the second dynamically allocated buffer at `0x0070F868`.
  - **Role:** In-memory payload staging
  - **Importance:** Establishes a second embedded PE component used by the network subsystem.

- **Self-image staging:** `[DWORD file_size][self executable]`
  - **Type:** Embedded executable image
  - **Evidence:** The function opens the current executable, obtains its complete file size with `GetFileSize`, stores the size immediately after PE blob #1, and reads the complete executable into the same buffer with `ReadFile`.
  - **Role:** Self-image staging
  - **Importance:** Demonstrates that the sample explicitly prepares a complete copy of its own executable for subsequent processing or network transmission.

- **Duplicated self-image region:** `[DWORD file_size][self executable]`
  - **Type:** In-memory executable copy
  - **Evidence:** The `[file_size][self executable]` region from Buffer 1 is copied to Buffer 2 without the first embedded PE blob. Buffer 2 therefore contains PE blob #2 followed by an identical copy of the executable image.
  - **Role:** Payload construction / staging
  - **Importance:** Establishes that both network payload buffers contain the same self-image while using different embedded PE prefixes.

- **Self-image size:** `0x0038D01D` bytes
  - **Type:** Executable size
  - **Evidence:** `GetFileSize` returns `0x0038D01D`, and the value is stored in both staged structures before the executable data.
  - **Role:** Payload metadata
  - **Importance:** Provides the size metadata used to delimit the staged executable image.


---

## Function 0x00407720

> `Additional evidance&IOCs`

- **IPv4 target distribution:** The function iterates through the dynamically generated IPv4 collection produced by `0x00409160` and passes each stored IPv4 value directly to a worker executing at `0x004076B0`.
- **Worker execution:** Each valid target is processed through `_beginthreadex`, with `0x004076B0` used as the thread entry point and the target IPv4 value supplied as the thread argument.
- **Concurrent target processing:** Successful worker creation causes an atomic increment of the shared counter at `0x0070F86C`, indicating that multiple target-processing workers may execute concurrently.
- **Worker-count throttling:** New worker creation is delayed while the shared counter remains greater than `10`, with `Sleep(100)` used between counter checks.
- **Inter-worker delay:** After each worker creation attempt, the dispatcher waits `50 ms` before processing the next IPv4 target.
- **Independent worker execution:** After a successful `_beginthreadex` call, the returned thread handle is closed with `CloseHandle`, while the worker continues executing independently.
- **Dynamic target collection:** The function does not use a hard-coded target count. The number of targets is derived from the boundaries of the dynamically generated IPv4 array returned by `0x00409160`.


---

## Function 0x004076B0

> `Additional evidance&IOCs`

- **Per-target worker execution**
  - **Type:** Network target processing
  - **Evidence:** The function receives an IPv4 target as its argument and passes the same value to `0x00407480` and, after successful validation, to a secondary worker executing at `0x00407540`.
  - **Role:** Per-target execution
  - **Importance:** Establishes the transition from the target-distribution layer to target-specific network processing.

- **Target-processing gate**
  - **Type:** Execution control
  - **Evidence:** The IPv4 address is first passed to `0x00407480`. A non-positive return value terminates the current worker without creating the secondary `0x00407540` worker.
  - **Role:** Target filtering / execution gating
  - **Importance:** Identifies `0x00407480` as a critical decision point controlling whether an individual target proceeds to the next network-processing stage.

- **Secondary network worker**
  - **Type:** Worker process/thread
  - **Evidence:** When `0x00407480` returns a positive value, `_beginthreadex` creates a secondary worker at `0x00407540` and passes the target IPv4 value as its argument.
  - **Role:** Target-specific network processing
  - **Importance:** Establishes the second level of the worker architecture used for individual IPv4 targets.

- **Worker execution timeout**
  - **Type:** Execution control
  - **Evidence:** The dispatcher waits up to `600000 ms` (10 minutes) for the `0x00407540` worker to terminate. A `WAIT_TIMEOUT` result causes `TerminateThread` to be called.
  - **Role:** Worker lifecycle control
  - **Importance:** Demonstrates that target-specific processing is explicitly bounded by a maximum execution interval.

- **Shared worker-count synchronisation**
  - **Type:** Thread synchronisation
  - **Evidence:** The function decrements the shared counter at `0x0070F86C` using `InterlockedDecrement` before terminating its own CRT-managed thread.
  - **Role:** Concurrency management
  - **Importance:** Completes the worker-count mechanism introduced by `0x00407720` and confirms that the counter tracks active per-target workers across concurrent execution contexts.


---

