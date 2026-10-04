
---

# Deep Reverse Analysis

## Overview

This stage contains the **deep technical reverse engineering analysis** of the sample, performed using **x64dbg** and **Ghidra** as the primary tools.

The objective of this stage is to reconstruct the malware's actual execution flow and provide a detailed technical explanation of its implementation at the function and code-block level.

Unlike the previous stages, which focused on static artifacts and hypothesis development, this stage follows the sample's execution from the **Entry Point** and progressively analyzes the functions and execution branches encountered during runtime.

## Structure

The `Deep_Analysis/` directory is organized as follows:

```
Deep_Analysis/
│
├── README.md
│
└── Reverse analysis/
    │
    ├── Functions/
    │
    └── Screens/
```

### `Reverse analysis/`

Contains the complete technical reverse-engineering analysis.

#### `Functions/`

Contains the individual function analyses that form the execution-flow tree of the sample.

The analysis begins with:

```
Entry point
```

The `Entry_Point` analysis represents the starting point of the investigation. Each function called from the current execution path is documented in a separate Markdown file when it represents a relevant execution block or requires a detailed technical analysis.

Function relationships are represented through references between the corresponding Markdown files.

## How to Read the Analysis

The `ReverseAnalysis` should be read starting from:

```
Functions/Entry point.md
```

The `Entry point` file contains the detailed technical analysis of the initial execution stage, including the implementation of the code within the function's boundaries.

When the analyzed function calls another relevant function, the corresponding function is documented in a separate Markdown file and referenced from the current analysis.

The reader can therefore follow the execution flow progressively:

```
Entry point
    │
    ├── Function A
    │     ├── Function C
    │     └── Function D
    │
    └── Function B
          └── Function E
```

This structure represents the execution branches observed during the reverse-engineering process. By following the references between functions, the reader can progressively reconstruct the malware's implementation, execution flow, and behavioral logic at a technical level.

Each function analysis may contain:

- detailed assembly-level analysis;
- Ghidra decompilation and function relationships;
- x64dbg execution observations;
- relevant screenshots;
- execution branches and conditions;
- API calls and their context;
- memory and process observations;
- discovered IOC;
- references to supporting dumps;
- references to targeted dynamic analysis performed when required.

### `Screens/`

Contains screenshots collected during the reverse-engineering process.

Screenshots are referenced from the corresponding function analyses and provide visual evidence supporting the described execution flow and technical observations.

## Dynamic Analysis Integration

Dynamic-analysis tools are used selectively when static code tracing alone is insufficient to establish the behavior of a specific execution block.

Depending on the behavior under investigation, supporting tools such as **Wireshark, Process Monitor, Process Hacker**, and other analysis utilities may be used.

These observations are integrated into the corresponding function analysis rather than treated as a separate execution narrative.

IOC discovered during execution are documented at the point where they are identified and correlated with the corresponding execution path.

## Analysis Architecture

The function-based architecture was selected to preserve the **natural investigative flow of the reverse-engineering process**.

Rather than placing the entire technical analysis into a single large document, the analysis is divided into interconnected function-level documents. This allows the reader to move from one function to another, follow execution branches, inspect the corresponding technical evidence, and return to the parent function when necessary.

The structure is intended to reproduce the way the sample can be investigated interactively in a debugger:

> **Start at the Entry Point → follow execution → enter a called function → analyze its implementation → follow relevant branches → return to the calling context.**

This architecture provides a navigable representation of the malware's execution flow while preserving detailed technical analysis at each level.

The resulting `Reverse annalysis` therefore serves not only as a collection of reverse-engineering notes, but as a **reconstructed technical execution model of the sample**.