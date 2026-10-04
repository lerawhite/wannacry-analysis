
---

## Function 0x00408140

>*`www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com`*

- **Type:** Domain / URL.
- **Evidence:** The sample attempts to establish a connection to the embedded URL. A valid connection descriptor causes execution to branch to `0x004081BC` and terminate.
- **Role:** Kill switch.
- **Importance:** This domain is the primary network IOC associated with the sample's kill-switch mechanism.


---

## Function 0x00409160

> `Additional evidance&IOCs`

- **Local IPv4 network enumeration**
  - **Type:** Network discovery / IPv4 address collection
  - **Evidence:** The function retrieves local adapter configuration through `GetAdaptersInfo`, extracts the IPv4 address and subnet mask, calculates the corresponding network and broadcast boundaries, and generates the usable host addresses within the discovered range.
  - **Role:** Local network target discovery
  - **Importance:** Demonstrates that the sample dynamically derives network targets from the host's current network configuration rather than relying exclusively on a statically embedded address list.

- **Host-address range generation**
  - **Type:** IPv4 host enumeration
  - **Evidence:** `0x00408E50` enumerates addresses between the calculated network and broadcast boundaries while excluding the network and broadcast addresses. The resulting addresses are inserted into the dynamic target array.
  - **Role:** Candidate target generation
  - **Importance:** Establishes the mechanism used to construct the candidate IPv4 target set later consumed by `0x00407720`.

- **RFC1918 private IPv4 filtering**
  - **Type:** Private IPv4 address range
  - **Evidence:** `0x00409110` converts candidate addresses with `htonl()` and checks them against the RFC1918 ranges `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
  - **Role:** Network-address filtering
  - **Importance:** Shows that private IPv4 address space is explicitly handled during the construction of the target collection.

- **Network-range validation**
  - **Type:** IPv4 range validation
  - **Evidence:** `0x004090D0` uses `htonl()` to normalise the candidate address and supplied range boundaries before determining whether the address falls within the calculated network range.
  - **Role:** Target filtering / address normalisation
  - **Importance:** Confirms that candidate addresses are constrained to the network range derived from the local adapter configuration.

- **Per-adapter address collection**
  - **Type:** Adapter-associated IPv4 discovery
  - **Evidence:** The function retrieves additional adapter information through `GetPerAdapterInfo`, converts the associated IPv4 addresses with `inet_addr()`, applies private-address and range validation, and inserts accepted values into the target array.
  - **Role:** Network target enrichment
  - **Importance:** Demonstrates that the final target collection is built from multiple sources of local adapter information rather than from a single interface address.

- **Target-set normalisation**
  - **Type:** IPv4 collection normalisation
  - **Evidence:** The resulting address array is sorted and subsequently deduplicated before being returned to `0x00407720`.
  - **Role:** Target preparation
  - **Importance:** Establishes that the dispatcher receives a normalised collection of unique IPv4 targets.


---

## Function 0x004076B0

> `Additional evidance&IOCs`

- **TCP/445 target-processing chain**
  - **Type:** Network behaviour
  - **Evidence:** Each IPv4 target distributed by `0x00407720` is passed through `0x004076B0` to `0x00407480`, which performs the TCP/445 connectivity check before the target is allowed to proceed to `0x00407540`.
  - **Role:** Network target validation
  - **Importance:** Establishes the connection between the dynamically generated IPv4 target set and the subsequent TCP/445 propagation path.


---

## Function 0x00407480

> `Additional evidance&IOCs`

- **TCP/445 reachability check**
  - **Type:** Network behaviour
  - **Evidence:** The function creates an IPv4 TCP socket with `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`, enables non-blocking mode through `ioctlsocket(FIONBIO)`, and attempts to connect to the supplied IPv4 address on TCP port `445`.
  - **Role:** Target reachability filtering
  - **Importance:** Establishes a dedicated TCP-level filtering stage between candidate target generation and the subsequent SMB processing path.

- **Non-blocking TCP connection**
  - **Type:** Network behaviour
  - **Evidence:** The socket is configured with `FIONBIO` before `connect()` is called. The resulting connection state is subsequently monitored through `select()`.
  - **Role:** Asynchronous connection handling
  - **Importance:** Demonstrates that target reachability is checked without maintaining a blocking `connect()` operation.

- **TCP connection monitoring**
  - **Type:** Network behaviour
  - **Evidence:** After initiating the non-blocking connection, the function calls `select()` and preserves its return value before closing the socket.
  - **Role:** Connection-state evaluation
  - **Importance:** The result of `select()` is returned to the caller and directly determines whether the target proceeds to the next processing stage.

- **TCP/445 propagation gate**
  - **Type:** Network execution gate
  - **Evidence:** `0x004076B0` terminates the per-target worker when `0x00407480` returns a non-positive value. A positive result allows execution to continue to `0x00407540`.
  - **Role:** Target-processing gate
  - **Importance:** Establishes `0x00407480` as the transport-level decision point between candidate target discovery and subsequent SMB-related processing.

- **SMB target-processing chain**
  - **Type:** Network behaviour
  - **Evidence:** A target passing the TCP/445 check proceeds through `0x00407540` and subsequently reaches `0x00401980`, where SMB1 protocol interaction is performed.
  - **Role:** Propagation pipeline
  - **Importance:** Demonstrates the separation between transport-level reachability testing and application-layer SMB interaction.

#### Laboratory Observation

> `192.168.124.128:445`

- **Type:** Laboratory network observation
- **Evidence:** During dynamic analysis, the controlled Windows 10 22H2 analysis VM at `192.168.124.128` successfully passed the TCP/445 reachability stage.
- **Role:** Experimental target
- **Importance:** Provides runtime confirmation that a reachable TCP/445 target proceeds from `0x00407480` into the subsequent SMB-processing path.

> **Note:** `192.168.124.128` is a laboratory address and is not treated as a malware IOC.


---

## Function 0x00407540

> `Additional evidance&IOCs`

- **Per-target SMB processing**
    
    - **Type:** Network behaviour
        
    - **Evidence:** The function receives an IPv4 target address, converts it to a string representation, and initiates the subsequent network-processing chain through `0x00401980` using TCP port `445`.
        
    - **Role:** Per-target network processing
        
    - **Importance:** Establishes the transition from the TCP/445 reachability stage into target-specific SMB-related processing.
        
- **SMB processing after TCP reachability**
    
    - **Type:** Network behaviour
        
    - **Evidence:** `0x00407540` is reached only after the target passes the TCP/445 reachability check performed by `0x00407480`. The function subsequently invokes `0x00401980` and `0x00401B70` for the same target.
        
    - **Role:** Propagation pipeline
        
    - **Importance:** Demonstrates the separation between transport-level target filtering and subsequent SMB protocol processing.
        
- **Repeated target processing**
    
    - **Type:** Network behaviour
        
    - **Evidence:** The function can invoke `0x00401370` repeatedly, with the retry loop allowing up to five processing attempts before the execution returns to the subsequent `0x00401B70` stage.
        
    - **Role:** Network processing / retry mechanism
        
    - **Importance:** Shows that failure of the intermediate processing path does not immediately terminate target handling.
        
- **Final processing gate**
    
    - **Type:** Network execution gate
        
    - **Evidence:** After the retry sequence, `0x00401B70` is invoked again. Only a successful result allows execution to continue to `0x004072A0`; an unsuccessful result terminates processing of the current target.
        
    - **Role:** Target-processing decision point
        
    - **Importance:** Establishes `0x00401B70` as a critical control-flow boundary before the subsequent network stage.
        
- **Staged network execution**
    
    - **Type:** Network architecture
        
    - **Evidence:** The function separates initial target processing through `0x00401980`, intermediate processing through `0x00401B70` and `0x00401370`, and the subsequent stage at `0x004072A0`.
        
    - **Role:** Propagation state progression
        
    - **Importance:** Demonstrates that the per-target network path is implemented as multiple sequential processing stages rather than as a single SMB operation.


---

## Function 0x00401980

> `Additional evidance&IOCs`

- **SMB1 protocol interaction**
    
    - **Type:** Network protocol behaviour
        
    - **Evidence:** The function establishes a TCP connection to port `445` and performs a sequence of SMB1 requests including `SMB_COM_NEGOTIATE`, `SMB_COM_SESSION_SETUP_ANDX`, and `SMB_COM_TREE_CONNECT_ANDX`.
        
    - **Role:** SMB protocol interaction
        
    - **Importance:** Establishes that the target-processing path proceeds beyond TCP/445 reachability into stateful SMB1 communication.
        
- **SMB_COM_NEGOTIATE**
    
    - **Type:** SMB protocol command
        
    - **Evidence:** The function transmits a `0x58`-byte SMB1 request containing command `0x72` (`SMB_COM_NEGOTIATE`) and the dialect strings `LANMAN1.0`, `LM1.2X002`, `NT LANMAN 1.0`, and `NT LM 0.12`.
        
    - **Role:** SMB dialect negotiation
        
    - **Importance:** Identifies the first application-layer SMB operation performed against the target.
        
- **SMB negotiation response**
    
    - **Type:** Network protocol evidence
        
    - **Evidence:** The target returned a `409`-byte response to `SMB_COM_NEGOTIATE`, which was accepted by the function as a valid SMB1 negotiation response.
        
    - **Role:** Protocol capability negotiation
        
    - **Importance:** Provides dynamic confirmation that the target responded to the initial SMB1 request.
        
- **SMB_COM_SESSION_SETUP_ANDX**
    
    - **Type:** SMB protocol command
        
    - **Evidence:** The function transmits a `0x67`-byte SMB1 request with command `0x73` (`SMB_COM_SESSION_SETUP_ANDX`) containing the legacy Windows identification strings `Windows 2000 2195` and `Windows 2000 5.0`.
        
    - **Role:** SMB session setup
        
    - **Importance:** Establishes the second application-layer stage of the SMB interaction.
        
- **STATUS_ACCESS_DENIED**
    
    - **Type:** SMB response status
        
    - **Evidence:** The observed `SMB_COM_SESSION_SETUP_ANDX` response contains status `0xC0000022` (`STATUS_ACCESS_DENIED`).
        
    - **Role:** Session-setup outcome
        
    - **Importance:** Confirms that the observed execution did not establish a successful authenticated SMB session.
        
- **Response-derived SMB UID**
    
    - **Type:** SMB session state
        
    - **Evidence:** The function extracts the two-byte UID field from the `SMB_COM_SESSION_SETUP_ANDX` response and passes the resulting bytes to `0x004017B0`. In the observed response, the UID was `0x0000`.
        
    - **Role:** Response-dependent packet construction
        
    - **Importance:** Establishes a direct data dependency between the Session Setup response and the subsequent Tree Connect request.
        
- **IPC$ tree connection**
    
    - **Type:** SMB protocol artifact
        
    - **Evidence:** `0x004017B0` constructs the UNC path `\\<target>\IPC$` and inserts it into the subsequent SMB request.
        
    - **Role:** SMB tree connection
        
    - **Importance:** Establishes that the SMB processing path attempts to access the target's IPC$ tree before the subsequent transaction stage.
        
- **SMB_COM_TREE_CONNECT_ANDX**
    
    - **Type:** SMB protocol command
        
    - **Evidence:** The reconstructed request contains command `0x75` (`SMB_COM_TREE_CONNECT_ANDX`), the response-derived UID, and the dynamically constructed `\\<target>\IPC$` path. The request is successfully passed to `send()`.
        
    - **Role:** SMB tree connection
        
    - **Importance:** Demonstrates the transition from SMB session setup to target tree connection.
        
- **TCP connection reset**
    
    - **Type:** Network behaviour
        
    - **Evidence:** After the Tree Connect request is transmitted successfully, `recv()` returns `SOCKET_ERROR` and `WSAGetLastError()` returns `10054` (`WSAECONNRESET`).
        
    - **Role:** Dynamic execution boundary
        
    - **Importance:** Establishes the exact point at which the controlled execution loses the SMB connection and prevents the subsequent transaction stage from being dynamically observed.
        

#### Static-Only Evidence

- **SMB_COM_TRANSACTION**
    
    - **Type:** SMB protocol command
        
    - **Evidence:** Static analysis identifies a preconstructed SMB1 request at `0x0042E4F4` containing command `0x25` (`SMB_COM_TRANSACTION`). This request was not transmitted during the observed execution.
        
    - **Role:** Subsequent SMB processing
        
    - **Importance:** Demonstrates that the function contains a later SMB transaction stage beyond the dynamically observed Tree Connect exchange.
        
- **TRANS_PEEK_NMPIPE**
    
    - **Type:** SMB transaction subtype
        
    - **Evidence:** The statically identified transaction contains `0x0023` (`TRANS_PEEK_NMPIPE`) together with a `\PIPE\` path. This stage was not reached dynamically in the controlled execution.
        
    - **Role:** Named-pipe transaction
        
    - **Importance:** Provides static evidence of a subsequent named-pipe-oriented SMB transaction within the propagation path.
        
- **Named-pipe path**
    
    - **Type:** SMB protocol artifact
        
    - **Evidence:** The statically reconstructed transaction contains the string `\PIPE\`.
        
    - **Role:** Named-pipe transaction target
        
    - **Importance:** Establishes the presence of a named-pipe stage in the subsequent SMB processing logic.
        

#### Experimental Evidence

- **UID substitution**
    
    - **Type:** Dynamic experiment
        
    - **Evidence:** The UID supplied to `0x004017B0` was manually changed from the observed `0x0000` to `0x1122`. The resulting Tree Connect request was reconstructed and transmitted successfully, but the subsequent `recv()` still returned `WSAECONNRESET (10054)`.
        
    - **Role:** Controlled hypothesis testing
        
    - **Importance:** Demonstrates that changing the observed zero UID did not alter the connection-reset outcome. The available evidence therefore does not support identifying the UID value as the direct cause of the failure.


---

## Function 0x00401B70

> `Additional evidance&IOCs`

- **SMB_COM_TRANSACTION2**
    
    - **Type:** SMB protocol command
        
    - **Evidence:** Static analysis identifies an `SMB_COM_TRANSACTION2 (0x32)` request prepared after the SMB negotiation, Session Setup, and `IPC$` Tree Connect stages.
        
    - **Role:** Subsequent SMB transaction processing
        
    - **Importance:** Establishes a later SMB transaction stage within the per-target propagation path.
        
- **IPC$ tree connection**
    
    - **Type:** SMB protocol artifact
        
    - **Evidence:** The function constructs an `SMB_COM_TREE_CONNECT_ANDX (0x75)` request containing a `\\<target>\IPC$` UNC path.
        
    - **Role:** SMB tree connection
        
    - **Importance:** Establishes the IPC$ stage preceding the subsequent transaction processing.
        
- **Response-dependent transaction state**
    
    - **Type:** SMB protocol behaviour
        
    - **Evidence:** Selected fields of the `SMB_COM_TRANSACTION2` request are populated from offsets within the preceding receive buffer before the transaction is transmitted.
        
    - **Role:** Response-dependent packet construction
        
    - **Importance:** Demonstrates that the later SMB transaction depends on state derived from the preceding exchange.
        
- **Conditional transaction exchange**
    
    - **Type:** SMB protocol behaviour
        
    - **Evidence:** The response to the transaction is checked for byte `0x51` (`'Q'`). When the condition is satisfied, additional fields are modified and another send/receive exchange is performed.
        
    - **Role:** Protocol state handling
        
    - **Importance:** Establishes a conditional multi-stage SMB transaction sequence.
        
- **Dynamic execution boundary**
    
    - **Type:** Network behaviour
        
    - **Evidence:** In the controlled execution, the receive operation following the `IPC$` Tree Connect failed, preventing the subsequent `SMB_COM_TRANSACTION2` exchange from being dynamically observed.
        
    - **Role:** Analysis boundary
        
    - **Importance:** Separates dynamically verified SMB behaviour from the statically reconstructed transaction stage.


---

## Function 0x00401370

> `Additional evidance&IOCs`

- **Table-driven network processing**
    
    - **Type:** Network behaviour
        
    - **Evidence:** Iterates over the descriptor table at `0x00431480`, dispatching connection, transmission, reception, and socket-cleanup operations according to per-entry operation types.
        
    - **Role:** Network/protocol state machine
        
    - **Importance:** Establishes a structured, state-driven network processing layer.
        
- **SMB session state handling**
    
    - **Type:** SMB protocol evidence
        
    - **Evidence:** Received data is processed for fields associated with `treeid` and `userid`.
        
    - **Role:** SMB session/tree state management
        
    - **Importance:** Links the routine to stateful SMB protocol processing.
        
- **SMB network operation set**
    
    - **Type:** Network behaviour
        
    - **Evidence:** The routine supports TCP connection establishment, data transmission, reception, and socket cleanup through `connect()`, `send()`, `recv()`, and `closesocket()`.
        
    - **Role:** Protocol communication engine
        
    - **Importance:** Demonstrates that the routine provides the underlying network operations used by the surrounding SMB propagation path.
        
- **DOUBLEPULSAR-related network stage**
    
    - **Type:** Protocol/architecture evidence
        
    - **Evidence:** The routine participates in the SMB transaction path, while the same network component contains the `DOUBLEPULSAR-compatible XOR-key` derivation at `0x00406ED0` and subsequent payload-transfer logic at `0x004072A0`.
        
    - **Role:** DOUBLEPULSAR-related network processing
        
    - **Importance:** Establishes the routine's position within the DOUBLEPULSAR-related propagation path without claiming that `0x00401370` itself implements the complete protocol.


---

## Function 0x004072A0

> `Additional evidance&IOCs`

- **SMB payload-transfer stage**
    
    - **Type:** Network behaviour
        
    - **Evidence:** After SMB session establishment and a response-dependent control exchange, the function enters a staged payload-transfer path over the established SMB connection.
        
    - **Role:** Payload delivery
        
    - **Importance:** Establishes the transition from SMB protocol processing to payload transmission.
        
- **Response-gated payload delivery**
    
    - **Type:** Protocol behaviour
        
    - **Evidence:** Payload preparation continues only after the received response contains `0x51` (`'Q'`).
        
    - **Role:** Remote-side state validation
        
    - **Importance:** Demonstrates that payload delivery is gated by a target response.
        
- **Staged payload buffer selection**
    
    - **Type:** Payload evidence
        
    - **Evidence:** `0x00406F50` selects either `0x70F864` or `0x70F868`, the buffers previously populated by `0x00407A20` with embedded PE data and a copy of the running executable.
        
    - **Role:** Payload source selection
        
    - **Importance:** Directly links the embedded PE/self-image buffers to the later network-transfer stage.
        
- **Payload data-flow to network transmission**
    
    - **Type:** Payload/network evidence
        
    - **Evidence:** Data from the selected staged buffer is copied into a transfer context, processed by `0x00406F00`, and subsequently transmitted through `send()`.
        
    - **Role:** Payload preparation and delivery
        
    - **Importance:** Establishes a direct data-flow from embedded payload material to network transmission.
        
- **Chunked payload transfer**
    
    - **Type:** Network behaviour
        
    - **Evidence:** Transfer data is generated in repeated blocks, transmitted with `send(..., 0x1052)`, followed by `recv(..., 0x1000)` and an `'R'` response check before the next chunk.
        
    - **Role:** Staged payload transmission
        
    - **Importance:** Demonstrates acknowledgement-controlled chunked transfer rather than a single bulk transmission.
        
- **Transfer acknowledgement**
    
    - **Type:** Protocol evidence
        
    - **Evidence:** The next transfer stage is reached only when the received response contains `0x51` (`'R'`).
        
    - **Role:** Chunk-transfer synchronisation
        
    - **Importance:** Establishes response-controlled progression of the payload transfer.
        
- **Embedded PE to remote-transfer linkage**
    
    - **Type:** Payload architecture evidence
        
    - **Evidence:** The buffers created by `0x00407A20` from embedded PE regions are later selected by `0x00406F50` and used as the source for data transmitted by `0x004072A0`.
        
    - **Role:** Remote propagation payload
        
    - **Importance:** Provides direct static evidence connecting the embedded PE data with the network propagation stage.


---

## Function 0x00406ED0

> `Additional evidance&IOCs`

- **DOUBLEPULSAR XOR-key derivation**
    
    - **Type:** Protocol implementation evidence
        
    - **Evidence:** The function implements the documented DOUBLEPULSAR XOR-key derivation algorithm, including byte rearrangement, shifts, and XOR with `2 × input`.
        
    - **Role:** DOUBLEPULSAR key derivation
        
    - **Importance:** Provides direct algorithmic evidence linking the surrounding SMB network component to DOUBLEPULSAR.
        
- **Derived key used in network processing**
    
    - **Type:** Protocol/data-flow evidence
        
    - **Evidence:** The value returned by `0x00406ED0` is consumed by the subsequent payload-processing path.
        
    - **Role:** Protocol-dependent value generation
        
    - **Importance:** Connects the identified `DOUBLEPULSAR key` derivation to the later SMB payload-processing stage.


---

## Function 0x00406F50

> `Additional evidance&IOCs`

- **Staged payload buffer selection**
    
    - **Type:** Payload evidence
        
    - **Evidence:** Selects either `[0x70F864]` or `[0x70F868]`, the two buffers previously populated by `0x00407A20` with embedded PE data and a copy of the running executable.
        
    - **Role:** Payload source selection
        
    - **Importance:** Directly links the previously staged executable data to the network transfer routine.
        
- **Payload transfer-context construction**
    
    - **Type:** Payload/data-flow evidence
        
    - **Evidence:** Allocates a new working buffer and copies data from the selected staged payload region into it before packet construction.
        
    - **Role:** Payload staging
        
    - **Importance:** Establishes an explicit intermediate payload-transfer context.
        
- **Repeating XOR transformation**
    
    - **Type:** Data transformation evidence
        
    - **Evidence:** Calls `0x00406F00`, which applies an in-place four-byte repeating XOR transformation to the transfer data.
        
    - **Role:** Payload data transformation
        
    - **Importance:** Establishes the transformation applied immediately before network packet construction.
        
- **Chunked payload transmission**
    
    - **Type:** Network behaviour
        
    - **Evidence:** Constructs repeated transfer blocks, sends `0x1052` bytes, receives up to `0x1000` bytes, and advances the source offset by `0x1000` after the expected `'R'` response.
        
    - **Role:** Acknowledgement-driven payload transfer
        
    - **Importance:** Demonstrates staged, chunk-based transmission of the prepared payload.
        
- **Transfer acknowledgement**
    
    - **Type:** Protocol evidence
        
    - **Evidence:** Each chunk requires the response marker `0x52` (`'R'`) before the next chunk is processed.
        
    - **Role:** Transfer synchronisation
        
    - **Importance:** Establishes remote acknowledgement as a condition for transfer progression.
        
- **Final payload block**
    
    - **Type:** Network behaviour
        
    - **Evidence:** After the full `0x1000`-byte chunks, the remaining data is transformed and transmitted as a final variable-length block.
        
    - **Role:** Payload transfer completion
        
    - **Importance:** Demonstrates handling of the remaining payload data after the fixed-size chunk sequence.


---

## Function 0x00407840

> `Additional evidance&IOCs`

- **Randomized IPv4 target generation**
    
    - **Type:** Network behaviour
        
    - **Evidence:** Generates IPv4 addresses independently of local interface enumeration and converts the resulting dotted-decimal address through `inet_addr()`.
        
    - **Role:** External target discovery
        
    - **Importance:** Establishes a second target-selection mechanism alongside local-network enumeration.
        
- **IPv4 range filtering**
    
    - **Type:** Network behaviour
        
    - **Evidence:** Rejects generated first octets equal to `127` and values from `224` onward before using the address as a propagation target.
        
    - **Role:** Target filtering
        
    - **Importance:** Excludes loopback and multicast/reserved address ranges from randomized targeting.
        
- **Randomized TCP/445 target scanning**
    
    - **Type:** Network behaviour
        
    - **Evidence:** Generated IPv4 addresses are passed to `0x00407480`, which performs the TCP/445 connectivity check.
        
    - **Role:** Target reachability discovery
        
    - **Importance:** Links randomized IPv4 generation directly to SMB propagation targeting.
        
- **Reachable-target propagation worker**
    
    - **Type:** Process/thread behaviour
        
    - **Evidence:** Targets passing the TCP/445 gate are forwarded to a new worker executing `0x00407540`.
        
    - **Role:** Propagation execution
        
    - **Importance:** Establishes the transition from randomized target discovery to the common SMB propagation path.
        
- **Per-target worker timeout**
    
    - **Type:** Process/thread behaviour
        
    - **Evidence:** The `0x00407540` worker is monitored for up to 60 minutes and terminated with `TerminateThread()` on `WAIT_TIMEOUT`.
        
    - **Role:** Worker lifecycle management
        
    - **Importance:** Establishes bounded execution for individual propagation attempts.


---
## Function 0x00407660

> `Additional evidance&IOCs`

- **Cryptographic randomness for target generation**
    
    - **Type:** Randomness/implementation evidence
        
    - **Evidence:** Selects `CryptGenRandom(..., 4)` when the global CryptoAPI provider handle at `0x0070F870` is available; otherwise falls back to `rand()`.
        
    - **Role:** Random target generation
        
    - **Importance:** Establishes that randomized IPv4 targets can be generated using a CryptoAPI-backed randomness source.
        
- **Synchronized randomness access**
    
    - **Type:** Runtime behaviour
        
    - **Evidence:** The cryptographic randomness path is executed under the critical section initialized by the network module.
        
    - **Role:** Concurrent randomness handling
        
    - **Importance:** Supports safe random-value generation across the propagation worker threads.

