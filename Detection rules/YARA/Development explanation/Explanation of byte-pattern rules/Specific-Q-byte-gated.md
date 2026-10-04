
---
**Figure 1. Byte pattern for rule**
![](../Screens/YARA%20byte%20rule%206.png)

---

## 6. SMB `Q` Response Gate

### Research Basis

The rule was derived from the reverse-engineering analysis of the SMB processing path.

The analyzed code constructs a packet using response-derived values, sends it to the remote target, receives up to `0x400` bytes, and validates the response by checking for the ASCII byte `0x51` (`'Q'`).

The observed sequence is:

```text
response-derived data
        ↓
packet construction
        ↓
send()
        ↓
recv(0x400)
        ↓
response[0] == 'Q'
        ↓
continue / abort
```

### Signature Construction

The signature preserves the complete sequence of packet construction, transmission, response reception, and `Q` validation.

Absolute addresses of packet buffers and global data are wildcarded because they depend on the binary layout. Relative call and branch offsets, as well as stack-frame displacements, are also wildcarded.

The transfer size `0x400`, response value `0x51` (`'Q'`), and surrounding instruction structure are preserved.

### Detection Scope

The pattern is highly implementation-specific to the analyzed sample. Its specificity comes from the combination of response-derived packet construction, fixed receive size, SMB communication, and the subsequent `Q` response gate.

The rule is not intended to detect generic `send`/`recv` activity or the use of the character `Q`.

### Detection Value

This provides a `strong low-level signature` for the response-gated SMB processing stage identified during reverse engineering of the WannaCry network module.