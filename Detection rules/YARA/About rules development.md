
---
# YARA Rule Development

The YARA rules in this project were developed from the results of the deep reverse-engineering stage rather than from generic malware indicators alone.

The rule set contains both **simple string-based YARA rules** and **more complex byte-pattern rules** designed around implementation-specific characteristics of the analyzed WannaCry sample. YARA supports text, hexadecimal, and regular-expression patterns, while hexadecimal patterns can additionally use **wildcards, jumps**, and **alternatives** for more precise **binary matching**.

Simple rules use distinctive sample-related strings and artifacts identified during static and dynamic analysis. More specific rules use byte sequences derived from the actual implementation of the malware.

Particular attention was given to **avoiding generic indicators** that could produce broad matches. Where possible, patterns were selected from code and data structures that are closely associated with the analyzed sample's implementation.

The most specific patterns were identified through **deep analysis in x64dbg**. During reverse engineering, assembly instructions, control-flow structures, API usage, embedded data, and characteristic code sequences were examined to identify byte-level patterns that distinguish the analyzed WannaCry implementation from unrelated PE files.

The resulting rules therefore combine:

- distinctive textual indicators;
    
- sample-specific binary patterns;
    
- characteristic code sequences identified during assembly analysis;
    
- implementation-specific data structures;
    
- logical conditions combining multiple indicators where appropriate.
    

The rules were designed with **false-positive reduction as a primary requirement**. Generic strings or common Windows API sequences were not treated as sufficient standalone signatures when they could occur in unrelated software.

The objective is not simply to detect a file containing a known WannaCry string, but to create signatures that reflect the **specific implementation characteristics discovered during reverse engineering**.

This approach makes the YARA rules directly traceable to the analytical findings documented throughout this project.

## Development Documentation

Detailed explanations of the rule-development process are provided in the adjacent *`Development explanation`* directory.

This directory documents the reasoning behind individual YARA rules, including the selection of byte patterns, wildcards, jumps, alternatives, relevant code locations, and the reverse-engineering evidence used to derive each signature.

It is intended to provide **traceability between the analyzed malware implementation and the resulting detection rules**, allowing each signature to be reviewed from its original reverse-engineering findings through to its final YARA implementation.