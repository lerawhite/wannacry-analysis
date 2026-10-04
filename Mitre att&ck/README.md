
---
# MITRE ATT&CK Mapping

## 1. What is MITRE ATT&CK?

**MITRE ATT&CK** is a knowledge base and behavioral framework that categorizes adversary activity based on real-world observations. It provides a common structure for describing **what an adversary is trying to achieve, how the behavior is performed, and how specific implementations can be identified**.

ATT&CK is organized around several core concepts:

- **Tactics** — describe **why** an adversary performs an action, representing the tactical objective.
    
- **Techniques** — describe **how** the objective is achieved.
    
- **Sub-techniques** — provide a more specific description of a technique.
    
- **Procedures** — describe a concrete implementation of a technique by a specific adversary or piece of software.
    

For malware analysis, ATT&CK provides a standardized way to translate low-level reverse-engineering findings into recognizable adversarial behaviors.

---

## 2. Why ATT&CK is Used in This Project

The primary purpose of the mapping is to connect the technical findings of the reverse-engineering process with a standardized behavioral model.

The analysis identifies low-level implementation details such as:

```text
API calls
    ↓
Control flow
    ↓
Network operations
    ↓
SMB processing
    ↓
Payload staging
    ↓
Propagation behavior
```

ATT&CK provides a higher-level representation of these findings:

```text
Technical Evidence
        ↓
Observed Behavior
        ↓
ATT&CK Technique
        ↓
Tactic / Adversarial Objective
```

This allows the reader to understand not only **how the analyzed sample works internally**, but also how its behavior corresponds to techniques commonly used to describe adversary activity.

ATT&CK can also support detection engineering, threat intelligence, and defensive analysis by providing a common behavioral vocabulary.

---

## 3. How to Read the Mapping

The mapping in this project should be read from **evidence to technique**, rather than treating the ATT&CK technique as proof by itself.

For example:

```text
GetAdaptersInfo
        ↓
Local network configuration obtained
        ↓
Network boundaries calculated
        ↓
Target addresses generated
        ↓
T1016 / T1018
```

The ATT&CK ID is therefore the classification of behavior established through the analysis.

Each technique is assigned an analysis status:

### Confirmed

The behavior was directly identified in the examined sample through static and/or dynamic analysis.

The project contains technical evidence supporting the mapping.

### Confirmed / strongly supported

The analyzed implementation provides strong evidence for the technique, but some part of the complete attack chain could not be reproduced in the laboratory environment.

This status is used where the local evidence is substantial but the full remote-side effect was not independently demonstrated.

### Supported by the analyzed propagation architecture

The technique is supported by the observed implementation and data flow, but the evidence does not justify treating every aspect of the ATT&CK procedure as independently reproduced.

### Documented by MITRE; not reproduced in this project

The technique is associated with WannaCry in the MITRE ATT&CK knowledge base, but the corresponding behavior was outside the directly verified scope of this analysis.

Such techniques are intentionally included for context and are **not presented as findings independently established by this reverse-engineering work**.

---

## 4. Scope of This Mapping

The mapping combines two different information sources:

1. **Sample-specific evidence** obtained during this reverse-engineering project.
    
2. **Publicly documented WannaCry capabilities** represented in MITRE ATT&CK.
    

These sources must not be treated as equivalent.

The ATT&CK Software pages represent publicly reported technique use or capability and do not necessarily describe every behavior that a particular sample contains.

Therefore, a technique appearing in the mapping does not automatically mean that the behavior was observed in the laboratory.

The **Status in this Analysis** field is used to preserve this distinction.

---

## 5. Reading the Analysis-Specific Coverage

The most important part of this mapping is the subset of techniques directly supported by the analyzed sample.

For example:

```text
T1016
System Network Configuration Discovery
        ↓
T1018
Remote System Discovery
        ↓
T1210
Exploitation of Remote Services
        ↓
T1570
Lateral Tool Transfer
        ↓
Payload Transfer / Propagation
```

This chain represents the relationship between the technical findings documented throughout the project and their ATT&CK classification.

Other techniques associated with WannaCry by MITRE are retained in the mapping when relevant, but are explicitly marked when they were not independently reproduced.

---

## 6. Interpretation

ATT&CK should therefore be treated as a **behavioral classification layer over the reverse-engineering results**, not as a replacement for technical evidence.

The detailed analysis answers:

> **How does the malware implement the behavior?**

The ATT&CK mapping answers:

> **Which adversarial behavior does this implementation represent?**

This separation keeps the mapping evidence-driven while allowing the technical findings to be interpreted within a standardized cybersecurity framework.