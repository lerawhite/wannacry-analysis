
---
# Triage Stage

## Overview

Triage is the initial and rapid assessment of the analyzed malware sample. Its purpose is to establish a general understanding of the file, identify notable or potentially suspicious characteristics, and define the initial direction of the investigation.

The triage stage focuses on collecting and organizing preliminary information rather than performing detailed reverse engineering.

## Structure

The analysis is organized around the following areas:

- **Identification** — file type, architecture, compiler/linker information, hashes and related metadata;
- **System Information** — target operating system and relevant execution characteristics;
- **Optional Header** — PE metadata and executable configuration;
- **Sections Information** — section layout, sizes, permissions and entropy-related characteristics;
- **Suspicious Artifacts** — indicators identified by Detect It Easy (DIE);
- **Additional Suspicious Artifacts** — other notable structures, embedded data and anomalies identified during the initial inspection.
- **Initial Hypotheses** — preliminary behavioral assumptions derived from the collected observations.
- **Conclusions** — summary of the findings and their implications for subsequent analysis.

## Stage Output

The results of this stage are documented in:

- `Analysis.md` — detailed triage findings with hypotheses and supporting screenshots;
- `Screens/` — screenshots and visual evidence collected during triage.

The final conclusions and initial behavioral hypotheses are used as a starting point for the subsequent **Static Analysis** stage.