
---

The program entry point is located at `0x00409A16`.

Execution follows a short sequence:

1. **CRT initialization** - the C Runtime Library performs the standard process initialization.
    
2. **Malware initialization** - control is transferred to [0x00408140](0x00408140.md), the first malware-specific routine executed after CRT initialization.
    
3. **Process termination** - after `0x00408140` returns, execution reaches `exit()`.