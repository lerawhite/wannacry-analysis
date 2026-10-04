
---
**Figure 1. Byte pattern for rule**
![](YARA%20byte%20rule%203.png)

### Research Basis

The rule was derived from the reverse-engineering analysis of function `0x00406ED0`.

The function implements the characteristic XOR-key derivation algorithm associated with DOUBLEPULSAR. It transforms selected bytes of the input `DWORD`, combines the transformed value with the original value multiplied by two, and produces the resulting key through an XOR operation.

The core operation can be represented as:

```text
Input DWORD
    ↓
byte reordering
    ↓
bit shifting and combination
    ↓
2 × input
    ↓
XOR
    ↓
derived key
```

### Signature Construction

The complete instruction sequence implementing the transformation was preserved because it contains the distinctive combination of:

- byte masking;
    
- 16-bit shifts;
    
- bitwise OR operations;
    
- input doubling;
    
- final XOR;
    
- deterministic return of the derived value.
    

No address-dependent operands or relative branches are present in the analyzed function, so no wildcarding is required, **except a displacement** +**04** at begin of code.

### Detection Scope

The signature is algorithm-specific rather than API- or string-based.

Its primary detection value comes from the complete implementation of the DOUBLEPULSAR XOR-key derivation algorithm, rather than from generic XOR operations that are common in malware.

### Detection Value

The presence of this exact transformation provides **strong  evidence** of DOUBLEPULSAR-related protocol handling within the analyzed network module.
