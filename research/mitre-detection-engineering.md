---
layout: single
title: "MITRE ATT&CK Detection Engineering Notes"
permalink: /research/mitre-detection-engineering/
---

A working notebook for mapping:

- Techniques → **Telemetry sources**
- Telemetry → **Concrete detection logic**
- Detections → **Test cases**

Example mapping:

- `T1059.003 – Command and Scripting Interpreter: Windows Command Shell`  
  - Telemetry: process creation logs, command-line auditing  
  - Detection idea: suspicious use of `cmd.exe /c` with **lateral movement** tools  
  - Test: atomic test executing crafted commands in a lab environment
