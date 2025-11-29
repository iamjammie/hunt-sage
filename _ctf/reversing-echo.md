---
title: "Reversing Echo"
excerpt: "Reverse engineer a custom binary protocol used by an operator backdoor."
order: 2
---

You obtain a small ELF binary captured from a suspected **command-and-control (C2)** staging host.

Goals:

1. Identify the custom **packet structure**  
2. Decode the **operator commands** from a provided PCAP  
3. Reconstruct the final **exfiltrated secret**

Flag format:

```text
flag{decoded_secret_phrase}
```
