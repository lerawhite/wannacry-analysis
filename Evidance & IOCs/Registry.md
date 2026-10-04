
---

## Function 0x00407C40

> `Additional evidance&IOCs`

- **Windows Service configuration stored by Service Control Manager**
    
    - **Type:** Registry-related persistence evidence
        
    - **Evidence:** The function calls `CreateServiceA` to create the `mssecsvc2.0` Windows service with `SERVICE_AUTO_START` and the malware executable as its service binary.
        
    - **Role:** Persistent service configuration
        
    - **Importance:** The service configuration is maintained by the Windows Service Control Manager and therefore results in persistent service-related configuration within the system registry.
        
- **Automatic service startup configuration**
    
    - **Type:** Registry-related persistence evidence
        
    - **Evidence:** `CreateServiceA` specifies `SERVICE_AUTO_START` for `mssecsvc2.0`.
        
    - **Role:** Automatic execution
        
    - **Importance:** Causes the service to be configured for automatic startup through the Windows Service Control Manager.
        

---

## Function 0x00407FA0

> `Additional evidance&IOCs`

- **Service failure-action configuration**
    
    - **Type:** Registry-related service configuration
        
    - **Evidence:** `ChangeServiceConfig2A` is called with `SERVICE_CONFIG_FAILURE_ACTIONS`, configuring the service to restart after failure with a 60-second delay.
        
    - **Role:** Service recovery configuration
        
    - **Importance:** Extends the persistence mechanism by configuring automatic service recovery through the Service Control Manager.
        
- **Service recovery command**
    
    - **Type:** Service configuration artifact
        
    - **Evidence:** The configured failure-action structure contains the command `wannacry -m security`.
        
    - **Role:** Service recovery
        
    - **Importance:** Associates the configured service recovery mechanism with the malware's service execution mode.
        

---

## Function 0x00408090

> `Additional evidance&IOCs`

- **Service identifier**
    
    - **Type:** Windows Service / Registry-related persistence artifact
        
    - **Evidence:** `OpenServiceA` accesses the service `mssecsvc2.0`, matching the service created during the persistence stage.
        
    - **Role:** Existing service access
        
    - **Importance:** Confirms that the malware subsequently interacts with the persistent service configuration.
        

---

## Registry Analysis Note

No direct registry API calls such as `RegCreateKeyExA`, `RegSetValueExA`, or `RegOpenKeyExA` were identified in the analyzed persistence path.

The registry relevance therefore comes from the **Windows Service Control Manager abstraction** rather than direct registry manipulation by the malware:

```text
CreateServiceA
      ↓
Service Control Manager
      ↓
Persistent service configuration
      ↓
Windows Registry
      ↓
mssecsvc2.0
      ↓
Automatic service execution
```

Accordingly, the service-related entries above should be treated as **registry-related persistence evidence**, not as direct registry IOCs.