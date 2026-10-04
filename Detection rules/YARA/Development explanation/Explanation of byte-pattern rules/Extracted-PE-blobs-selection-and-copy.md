
---
![](YARA%20byte%20rule%202.png)

---
**Figure 1. Byte pattern for rule**
![](YARA%20byte%20rule%202_.png)


---

### Research Basis

The rule was derived from the reverse-engineering analysis of function `0x00407A20`.

The analyzed code processes two embedded PE blobs stored in the `.data` section. A loop counter selects the corresponding blob, calculates its size, copies the blob into a working buffer, updates the destination pointer, and repeats the operation for the second blob.

The observed execution flow is:

```text
Blob index
    ↓
select embedded PE blob
    ↓
retrieve destination buffer
    ↓
calculate blob size
    ↓
copy data using REP MOVSD / REP MOVSB
    ↓
update destination pointer
    ↓
process next blob
```

### Signature Construction

The signature focuses on the characteristic blob-selection and copy mechanism.

The pattern preserves:

- the two-iteration selection logic;
    
- indexed access to the destination structure;
    
- size calculation using fixed constants;
    
- DWORD and byte-level memory copying;
    
- destination-pointer update;
    
- loop control.
    

The subsequent file-creation and additional copy operations were intentionally excluded because they belong to the following execution stage and are not required to identify the embedded-blob construction mechanism.

### Wildcard Strategy

Absolute addresses were wildcarded because they depend on the layout of the analyzed binary:

- addresses of the two embedded PE blobs;
    
- address of the destination buffer/table.
    

Relative conditional-jump offsets were also wildcarded because they depend on the final instruction layout.

In contrast, the size-related constants and the copy operations were preserved because they form part of the characteristic implementation of the blob-selection and construction mechanism.

### Detection Scope

The signature is highly implementation-specific to the analyzed sample.

Its specificity is derived from the combination of embedded-blob selection, indexed destination handling, size calculation, `REP MOVSD`/`REP MOVSB` copying, pointer updates, and the two-iteration control flow.

The rule is not intended to identify generic PE extraction or copying behaviour. Different malware implementing a similar payload-staging mechanism may use different data structures, copy routines, size calculations, or compiler-generated code.

### Detection Value

The pattern provides a low-false-positive code signature for the embedded payload construction stage identified during reverse engineering.

Unlike a generic search for `MZ`, embedded PE data, `memcpy`, or resource extraction APIs, the rule targets the specific low-level mechanism used by the analyzed sample to assemble its working data structures from embedded PE blobs.