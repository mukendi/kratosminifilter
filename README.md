# 🛡️ Kratos Minifilter — Windows Kernel Anti-Ransomware Driver


> **Defensive Security Research Project** — Windows minifilter driver developed in C++ for the real-time detection and neutralization of ransomware at the kernel level (Ring 0).

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Mechanisms](#detection-mechanisms)
- [Blacklist by Fingerprint](#blacklist-by-fingerprint)
- [Installation](#installation)
- [Configuration](#configuration)
- [Limitations](#limitations)
- [Legal Warnings](#legal-warnings)

---

## Overview

Kratos (`Kratos.sys`) is a Windows minifilter driver operating at altitude **425342** (Anti-Virus tier) via the Filter Manager (`fltmgr.sys`). Unlike static signature-based antivirus solutions, Kratos adopts a **purely behavioral** approach:

- **No signature database** — detects unknown ransomware
- **Kernel-mode** — atomic interception before validation on disk
- **Multi-level** — behavioral + entropic + structural
- **Persistent** — blacklist by hash to block re-executions

### Goals

| Objective | Result |

|----------|---------|

| Affected Files (First Run) | < 5 |

| Affected Files (Reruns) | **0** |

| False Positive Rate | **0%** (After Tuning) |

| Compatibility | NTFS / ReFS |

---

## Architecture

```
User-Mode
    │
    ▼
Filter Manager (fltmgr.sys) ← Altitude 425342
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                  KRATOS.SYS                         │
│                                                     │
│  IRP_MJ_CREATE      → Initializing contexts         │
│  IRP_MJ_WRITE       → Entropic analysis             │
│  IRP_MJ_READ        → R/W ratio counting            │
│  IRP_MJ_SET_INFORMATION → Delete/Rename Detection   │
│                                                     │
│  RTL_AVL_TABLE  → KS_PROCESS_CONTEXT per PID        │
│  FLT_FILE_CONTEXT → Entropy + state per file        │
└─────────────────────────────────────────────────────┘
    │
    ▼
NTFS / ReFS
```


## Detection Mechanisms

### Level 1 — Behavioral

Kratos distinguishes between deletions of **valuable files** (`.docx`, `.pdf`, `.jpg`...) and deletions of system/cache files using `KS_IsValuableFile()`:

- **ValuableDeleteCount** — deletions outside system directories
- **RenameToSuspicious** — renaming to an unknown extension
- **HighEntropyWrites** — entropy increase detected

### Level 2 — Entropy

Calculation via a **pre-calculated LUT** (`KratosEntropyLUT512`) — avoids the use of `log2()`, which is unavailable in kernel mode. 512-byte sample per write operation.

- **Delta**: existing file with low entropy → encrypted data
- **Absolute**: new `.tmp` file with entropy ≥ 7.5/8 bits

### Level 3 — Structural (Inverse Whitelist)

> **Main innovation**: instead of a blacklist of malicious extensions, Kratos uses a **whitelist of legitimate extensions**.

```
Original extension is valuable? YES
New extension is recognized? NO
→ SUSPECT — regardless of the extension chosen
```

This approach can detect LockBit 3.0 (`.xmjzh8q`), BlackCat/ALPHV (random) and any future ransomware using an unknown extension.

### Scoring Formula

```
ValuableDeleteCount > 10 → +10 pts
RenameToSuspicious > 2 → +40 pts
HighEntropyWrites > 3 → +40 pts
RansomNoteCreated → +60 pts
ShadowCopyDeleted → +75 pts

Score ≥ 60 → WARNING
Score ≥ 80 → CRITICAL + Kill + Blacklist
```

---

## Blacklist by Digital Footprint

Once ransomware is detected, Kratos calculates its **64-bit FNV-1a hash** on the first 4096 bytes of the executable (PE Header + beginning of code) and persists it in the registry:

```
\Registry\Machine\SOFTWARE\Kratos\Blacklist
  └── 1F81F13004B5B920 = "C:\Users\...\Hercule.exe"
```

Each time a process is created, `ProcessNotifyCallback` checks the blacklist **before** any execution. The process is blocked via `CreationStatus = STATUS_ACCESS_DENIED`.

**Renaming resistance**: the FNV-1a hash is identical regardless of the file name (`Hercule-AES.exe`, `HERCUL~1.EXE`, `chrome.exe`...).

**Protection against spoofing**: Whitelisted processes are validated by **Expected Name + Path**:

```c
chrome.exe + \Program Files\Google\Chrome\Application\ → Legitimate
chrome.exe + C:\Users\...\Desktop\                    → IMPOSTOR
```

---

## Installation

### Prerequisites

- Windows 10/11 (x64)
- Visual Studio 2022 with WDK (Windows Driver Kit)
- VM with Secure Boot **disabled** (or test signing enabled)

### Compilation

```bash
# Open KratosMinifilter.sln in Visual Studio
# Configuration: Debug or Release / x64
# Build → Build Solution
```

### Deployment (Test VM)

```powershell
# On the target VM — enable test mode
bcdedit /set testsigning on

# Copy Kratos.sys and Kratos.inf
# Install via Device Manager or sc.exe
sc create Kratos type= kernel start= boot binPath= "C:\Kratos\Kratos.sys"
sc start Kratos
```

---

## Configuration

### Monitored Extensions (Reverse Whitelist)

Modify `g_LegitExtensions[]` in `KratosDetection.cpp` to adjust the extensions considered legitimate after a renaming.

### Whitelisted Processes

Modify `g_TrustedProcesses[]` to add legitimate processes with their expected path:

```c
{ "myapp.exe", L"\\Program Files\\MyApp\\" },
```

### Scoring Thresholds

Modify `KS_EvaluateThreatScore()` in `KratosDetection.cpp` to adjust the WARNING/CRITICAL thresholds according to your environment.

---


## Limitations

- 1 to 3 files may be affected during the **first** execution
- No automatic recovery mechanism for encrypted files
- FNV-1a is not resistant to intentional collision forging (SHA-256 recommended for production)

---

## Legal Warnings

> ⚠️ **This driver is developed within a defensive security research framework.**
>
> - Use is **strictly reserved** for isolated test environments (VMs without network access)
> - Any deployment on a production system is carried out under the user's sole responsibility
> - The author disclaims all liability for any damage resulting from improper use
> - Modifying this driver to bypass security systems without authorization is **illegal**
---
