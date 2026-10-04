
---
**Figure 1. Byte pattern for rule**
![](../Screens/YARA%20byte%20rule%204.png)

### Research Basis

The rule was derived from the reverse-engineering analysis of the payload transfer routine.

The analyzed code took from `0x00406F50` and implements a fixed-size transfer protocol in which each data block is transmitted using a `0x1052`-byte send operation. The routine then receives up to `0x1000` bytes and validates the response by checking for the ASCII byte `0x52` (`'R'`).

The observed sequence is:

```text
send(0x1052)
      ↓
recv(0x1000)
      ↓
response[0] == 'R' ?
      ↓
continue / abort
```

### Signature Construction

The signature targets the complete interaction sequence rather than individual API calls or constants.

The following elements are preserved:

- `0x1052` send size;
    
- `0x1000` receive size;
    
- `0x52` response validation;
    
- `SOCKET_ERROR` checks;
    
- the ordering of `send`, `recv`, and acknowledgement validation.
    

Relative call, stack displacement and branch offsets are wildcarded because they depend on the final binary layout.

### Detection Scope

The pattern is implementation-specific to the analyzed sample. The **combination** of `fixed transfer sizes, response validation, and the surrounding control flow` provides substantially **greater specificity** than generic `send`/`recv` usage.

An unrelated implementation may use the same APIs or acknowledgement concept while using different transfer sizes, response values, or control flow.

### Detection Value

The signature identifies a characteristic chunked and acknowledgement-driven transfer mechanism observed during the reverse-engineering of the WannaCry network module.

The rule therefore provides a **low-false-positive** code-level detection primitive for this specific implementation.