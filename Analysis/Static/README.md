  
---
# Static Analysis Stage

## Overview

Static Analysis extends the initial findings obtained during triage by examining the sample's internal artifacts without executing it.

The purpose of this stage is to identify potentially relevant functionality, correlate static artifacts, and develop preliminary behavioral paths and hypotheses that will guide the subsequent **Deep Reverse Analysis**.

## Structure

The `Static/` directory is organized into the following components:

### `Analysis/`

Contains the documented results of the static investigation:

- `Imports.md` — analysis of imported DLLs and functions, including their grouping into logical behavioral categories.
- `Strings.md` — analysis of relevant strings and their potential behavioral context.
- `Resources.md` — analysis of the resource section and its embedded content.
- `Results/` — consolidated findings derived from the static analysis:
    - `Behavioral paths.md` — potential execution and behavioral paths identified from static evidence.
    - `Hypotheses.md` — hypotheses developed from the combined triage and static findings.
    - `Strings overall.md` — consolidated assessment of the analyzed strings.

### `Screens/`

Contains screenshots and supporting visual evidence collected during the static analysis.

The findings produced during this stage are used to establish a preliminary behavioral model and define the investigation priorities for the subsequent **Deep Reverse Analysis**.