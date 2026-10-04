![](Analysis/Deep%20reverse/Screens/graph.png)


# Contents:

- _Overview_
    
- _Research Objectives_
    
- _Analysis Methodology_
    
- _Project Architecture_
    
- _How to Read This Project ?_
    
- _Analysis Status_
    

---

# WannaCry Malware Analysis

## Overview

This repository is structured as a **step-by-step malware analysis case study** of **WannaCry**.

**WannaCry** is a particularly valuable and multifaceted malware sample for research because its functionality spans multiple aspects of Windows operating system architecture and demonstrates a wide range of malware techniques and behaviors.

Its capabilities provide a practical research environment for examining how different modules of malware interact with the operating system, from process and service management to filesystem operations, networking, payload execution, propagation mechanisms, and data encryption. Several of these behaviors are also mapped to techniques documented by the **MITRE ATT&CK** framework.

Each stage of the investigation is documented separately, including the methodology, observations, hypotheses, evidence, reverse engineering, dynamic analysis, detection logic, and resulting conclusions.

Particular attention was given to maintaining a direct relationship between **observed behavior, reverse-engineered code, collected evidence, and analytical conclusions**. This allows individual findings to be traced back to the code and runtime observations that support them.

The project also includes a dedicated `Detection Rules` section containing **YARA and Sigma rules** developed from the results of the analysis. These rules range from characteristic behavioral patterns to more implementation-specific byte-level signatures derived directly from reverse engineering. The goal was not simply to create generic rules based on common APIs, but to demonstrate how `deep reverse-engineering findings can be transformed into practical detection logic`.

The project is intended not only to document the analysis of WannaCry, but also to provide a practical reference for understanding for other junior malware analysts **how a complex malware sample can be systematically investigated from initial triage to a validated behavioral model and finally converted into detection opportunities**.

At the same time, this repository represents the author's `first comprehensive malware research project`. It was designed according to principles applicable to professional malware research: evidence-driven analysis, hypothesis validation, reproducible investigation stages, technical documentation, IOC collection, reverse engineering, behavioral reconstruction, ATT&CK mapping, and detection-rule development.

Therefore, the repository can also be used as a `learning case study for junior malware analysts`, demonstrating not only what conclusions can be reached from a malware sample, but also **how those conclusions are reached, validated, documented, and converted into reusable analytical and detection knowledge**.

---

## Research Objectives

- This project was conducted as a first comprehensive malware analysis case study, with the primary objective of demonstrating a structured and reproducible malware analysis methodology.
    
- The research follows a sequential analytical workflow, progressing from _initial triage_ and _static analysis_ to _hypothesis development_, _deep reverse engineering_, _targeted dynamic analysis_, and _detection engineering_. Findings from each stage are used to formulate and refine hypotheses that guide subsequent investigation.
    
- The analysis aims to reconstruct the malware's _relevant execution paths_, identify its major _behavioral components_ and _points of interaction_ with the Windows operating system, and collect and _correlate_ relevant artifacts and _indicators_ of compromise (IOCs).
    
- A separate objective was to transform selected reverse-engineering findings into `YARA and Sigma detection rules`, demonstrating how low-level technical observations can be translated into practical malware-detection mechanisms.
    
- The final stage consolidates the findings into structured stage-specific **reports** and a comprehensive final **report**.
    

**The primary objective of this research is therefore not simply to analyze a single malware sample, but to demonstrate the methodology, reasoning, evidence-driven workflow, and detection-engineering process used to progress from initial observations to a validated behavioral understanding of the malware.**

---

## Analysis Methodology

The analysis was conducted as a sequential, evidence-driven process. Each stage was used to establish an initial understanding of the sample, formulate hypotheses, and provide a basis for the following stage.

### 1. Triage

The investigation began with a comprehensive triage of the sample. The objective of this stage was to establish its general characteristics and identify potentially significant artifacts.

The following aspects were examined:

- **Identification** — file type, architecture, compiler/linker information, hashes and related metadata;
    
- **System Information** — target operating system and relevant execution characteristics;
    
- **Optional Header** — PE metadata and executable configuration;
    
- **Sections Information** — section layout, sizes, permissions and entropy-related characteristics;
    
- **Suspicious Artifacts** — indicators identified by Detect It Easy (DIE);
    
- **Additional Suspicious Artifacts** — other notable structures, embedded data and anomalies identified during the initial inspection.
    

The triage stage concluded with:

- initial observations and conclusions;
    
- **initial behavioral hypotheses**;
    
- a dedicated **Triage Report**.
    

The primary tools used were:

- **Detect It Easy (DIE)** was used for initial file identification, compiler/linker and packer detection, and identification of potentially suspicious artifacts.
    
- **PE-bear** was used for detailed inspection of the PE structure, including the Optional Header, section layout, imports, resources, and other PE metadata.
    
- **HxD** was used for low-level inspection of the raw file structure and binary data, including verification of structures and embedded content identified during the analysis.
    

---

### 2. Initial Static Analysis

Static analysis was performed as a continuation of the triage stage, providing a more detailed examination of the sample without yet performing instruction-level reverse engineering.

At this stage, the **same tools** were used as in the **triage stage**.

The analysis focused on:

#### Imported DLLs and Functions

Imported libraries and functions were examined and organized into **logical behavioral groups** based on their functionality. This allowed potential capabilities and relationships between different components of the malware to be identified.

#### Strings

Strings were analyzed manually and grouped according to their probable functional context. Particular attention was given to strings that could indicate filesystem activity, process or service execution, networking, embedded components, configuration data, or other potentially relevant behavior.

#### Resources

The resource section was examined in detail, including its structure and embedded content. Particular attention was given to the identification and extraction of embedded PE components and archive-related data.

The static stage resulted in:

- identification of potential **behavioral paths**;
    
- formulation of **static-analysis hypotheses**;
    
- correlation of findings between imports, strings, resources and other static artifacts.
    

The hypotheses generated during triage were then **correlated and synchronized with the static-analysis hypotheses**, resulting in an initial behavioral model of the sample.

---

### 3. Deep Reverse Analysis

Once the preliminary behavioral model had been established, the investigation proceeded to **deep reverse analysis**.

The analysis followed an **Entry Point–driven approach**, tracing the execution flow through the malware's logical components and investigating relevant functions and their relationships.

Before beginning this stage, potential **early code-execution mechanisms**, such as TLS callbacks, were examined and ruled out where applicable, allowing the analysis to proceed from the appropriate execution point.

The primary tools used were:

- **x64dbg** — runtime execution tracing, breakpoints, registers, memory and API-level observation;
    
- **Ghidra** — control-flow reconstruction, pseudocode analysis, function relationships and analysis of complex functions.
    

Other dynamic-analysis tools were used **selectively and at specific points of the execution flow** when additional runtime evidence was required, including:

- Wireshark;
    
- Process Monitor;
    
- Process Hacker;
    
- and other supporting tools where necessary.
    

This approach avoided treating dynamic monitoring as an independent source of unstructured telemetry. Instead, runtime tools were applied to answer specific questions arising during reverse engineering.

Particular attention was given to `architecture reconstruction`, including relationships between functions, execution gates, worker creation, network propagation, embedded payload staging, service execution, and protocol-specific processing.

---

### 4. Hypothesis Validation and Evidence Collection

Throughout the deep analysis, previously established hypotheses were continuously tested against observed code execution and runtime behavior.

Each investigation cycle followed the general pattern:

```text
Hypothesis
    ↓
Reverse Engineering
    ↓
Runtime Observation
    ↓
Evidence
    ↓
Confirmed / Rejected / Refined
```

During this process, the following were continuously collected and documented:

- execution-flow observations;
    
- screenshots and annotated reverse-engineering findings;
    
- memory and process dumps;
    
- extracted files and other artifacts;
    
- network captures where applicable;
    
- Indicators of Compromise (IOCs);
    
- analytical notes and observations.
    

The deep reverse-engineering process itself was documented through screenshots accompanied by explanations of the analyzed code, execution flow, and relevant findings.

An important principle throughout the investigation was maintaining a `direct connection between evidence and conclusions`. Where possible, behavioral claims were supported by specific instructions, API calls, runtime observations, memory structures, network activity, or extracted artifacts.

---

### 5. Detection Engineering

The findings obtained during reverse engineering were additionally used to develop `YARA and Sigma detection rules`.

The detection stage was treated as a continuation of the research rather than as an independent activity. Detection logic was derived from previously validated technical findings.

The YARA rules include both behavioral and implementation-specific signatures. Particular attention was given to `byte-level patterns derived directly from reverse engineering`, including characteristic algorithms, protocol-processing sequences, response validation logic, embedded-payload handling, and other distinctive code structures.

Where appropriate, absolute addresses, stack offsets, and relative branch displacements were wildcarded to reduce unnecessary dependence on the exact memory layout while preserving the characteristic algorithm or instruction sequence.

The Sigma rules were developed from `validated behavioral observations`, allowing relevant process, service, file, registry, and other telemetry patterns to be represented as higher-level detection logic.

The objective of the detection stage was therefore not simply to produce generic rules, but to demonstrate the complete analytical path:

```text
Malware Behavior
      ↓
Reverse Engineering
      ↓
Technical Evidence
      ↓
Behavioral Pattern
      ↓
YARA / Sigma Detection Logic
```

This provides an additional layer of practical value to the research by demonstrating how `malware research findings can be converted into reusable defensive detection mechanisms`.

---

### 6. Reporting and Final Reconstruction

The results of each analytical stage were consolidated into dedicated reports:

- **Triage Report**
    
- **Static Analysis Report**
    
- **Deep Reverse Analysis Report**
    
- **Final Report**
    

The final report consolidates the evidence collected throughout the investigation and presents the reconstructed behavioral model of the malware, including its relevant execution paths, interaction with the Windows operating system, identified artifacts, validated behavioral findings, and detection opportunities.


Thus, the overall methodology follows:

![](Analysis/Deep%20reverse/Screens/Analysis%20paradigm.png)



---

## Project Architecture

```text
wannacry_analysis/
│
├── README.md
│
├── Analysis/
│   ├── Triage/
│   │   ├── README.md
│   │   ├── Analysis.md
│   │   └── Screens/
│   │
│   ├── Static/
│   │   ├── README.md
│   │   ├── Imports.md
│   │   ├── Strings.md
│   │   ├── Resources.md
│   │   └── screens/
│   │
│   └── Deep reverse/
│       ├── README.md
│       ├── Functions(Entry point/-->(full execution))
│       └── Screens/
│
│
└── Detection rules/
    ├── Yara
    ├── Sigma
│
│
├── Dumps/
│   ├── triage stage/
│   ├── static stage/
│   └── deep reverse stage/
│
│
├── Evidance&IOCs/
│   ├── files/
│   ├── network/
│   ├── registry/
│   └── processes/
│
│
└── Mitre Att&ck mapping.md
│
│
└── Reports/
    ├── Triage report.md
    ├── Static analysis report.md
    ├── Deep reverse report.md
    └── Final report.md
```

The project architecture is intentionally organized around the `analytical lifecycle of the investigation`. Analysis, evidence, dumps, detection logic, ATT&CK mapping, and reporting are kept as separate components while remaining interconnected through the documented research workflow.

---

# How to Read This Project

This repository is designed to be read **sequentially**, following the same progression used during the investigation.

- Readers are recommended to begin with the **Triage Analysis**, including the corresponding collected artifacts, initial hypotheses, and the **Triage Report**. This establishes the initial understanding of the sample and the assumptions that guided the subsequent investigation.
    
- The next step is the **Static Analysis** stage. This section should be reviewed together with its associated dumps, extracted artifacts, IOCs, and hypotheses, followed by the **Static Analysis Report**. At this point, the reader should have a preliminary understanding of the malware's potential capabilities and behavioral paths.
    
- With this context established, the reader can proceed to **Deep Reverse Analysis**. The recommended starting point is `Entry point.md`, which serves as the entry point into the detailed technical investigation. From there, the analysis progresses through the malware's execution flow and gradually expands into the individual components and behavioral paths identified during reverse engineering.
    
- Throughout the deep analysis, references are provided to the relevant **dumps, IOCs, screenshots, and supporting evidence** collected during the investigation. These artifacts should be examined alongside the corresponding technical findings to maintain a direct connection between the observed behavior and the supporting evidence.
    
- After completing the technical analysis, readers can examine the `Detection Rules` section to see how selected reverse-engineering findings were converted into **YARA and Sigma rules**. This section is particularly useful for understanding the transition from low-level malware analysis to practical detection engineering.
    
- Finally, after completing the deep technical analysis and detection stage, readers should proceed to the **Reports + Mitre ATT&CK** mapping. This section consolidates the results of the entire investigation, including the validated behavioral findings, relevant IOCs, execution paths, detection logic, and final conclusions.
    

The recommended reading order is therefore:

```text
Analysis Methodology
        ↓
Triage Analysis
        ├── Triage Dumps
        ├── Initial Hypotheses
        └── Triage Report
        ↓
Static Analysis
        ├── Static Dumps
        ├── IOCs
        ├── Behavioral Hypotheses
        └── Static Analysis Report
        ↓
Deep Reverse Analysis
        ├── Entry point.md
        ├── Execution Flow
        ├── Technical Analysis
        ├── Dumps / IOCs / Screenshots
        └── Behavioral Validation
        ↓
Detection Rules
        ├── YARA
        ├── Sigma
        └── Detection Research
        ↓
Final Report + Mitre ATT&CK
        ├── Consolidated IOCs
        ├── Confirmed Behavior
        ├── Detection Findings
        └── Final Conclusions
```

This structure allows the reader to follow the investigation from **initial observations and hypotheses to technical validation, behavioral reconstruction, and detection engineering**, while maintaining a clear relationship between analytical conclusions and the evidence supporting them.

The repository can therefore be approached in two complementary ways:

- as a `complete malware-analysis case study`, following the entire investigation from beginning to end;
    
- or as a `learning reference for junior malware analysts`, where individual stages, reverse-engineered functions, evidence, and detection techniques can be studied independently.
    

---

## Analysis Status

```text
[✓] Triage Analysis
[✓] Static Analysis
[✓] Initial Behavioral Hypotheses
[✓] Deep Reverse Analysis
[✓] Evidence & IOCs
[✓] Reports
[✓] MITRE ATT&CK Mapping
[✓] YARA Rules
[✓] Sigma Rules
[✓] Detection Engineering
```

---

## Research & AI Assistance

This project was developed as an independent malware-analysis research project, with `AI-assisted research and technical writing support` used throughout the investigation.

ChatGPT was used as a research and analytical assistant for activities including:

- discussion and validation of analytical hypotheses;
    
- explanation of Windows internals, PE structures, APIs, networking and malware techniques;
    
- assistance with reverse-engineering reasoning;
    
- refinement of technical English for reports and documentation;
    
- development and review of YARA and Sigma detection logic;
    
- organization of research findings and documentation;
    
- discussion of alternative interpretations of observed behavior.
    

The final analytical conclusions, observations, reverse-engineering work, evidence collection, screenshots, experiments, and research decisions were produced as part of the author's own investigation.

`Special thanks to ChatGPT — GPT-5.6 Luna — for assisting throughout the entire research process. <3`

