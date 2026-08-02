# Kratos MiniFilter

> A research-oriented Windows Kernel MiniFilter designed to study behavioral ransomware detection at the file-system level.

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Language](https://img.shields.io/badge/Language-C%2B%2B-orange)
![Driver](https://img.shields.io/badge/Kernel-Minifilter-success)
![Research](https://img.shields.io/badge/Focus-Behavioral%20Detection-red)

---

# Overview

Kratos is an educational Windows File System Minifilter built on top of Microsoft's Filter Manager (`fltmgr.sys`).

Instead of relying on malware signatures, Kratos explores how ransomware can be detected by observing file-system behavior directly inside the Windows kernel.

The project demonstrates how a security driver can:

- monitor file creation, deletion and renaming;
- analyze write entropy in real time;
- correlate multiple suspicious activities;
- assign behavioral threat scores;
- terminate malicious processes;
- prevent reinfection using kernel-level fingerprinting.

Kratos is **not intended to become a commercial antivirus**.

Its primary objective is to understand how modern Endpoint Detection and Response (EDR) products implement behavioral ransomware detection inside the Windows kernel.

---

# Why Kratos?

Traditional antivirus products depend heavily on signatures.

Modern ransomware changes constantly.

Instead of asking

> "Do I know this malware?"

Kratos asks

> "Does this process behave like ransomware?"

This project demonstrates how multiple weak signals can be correlated into a high-confidence behavioral detection engine.

---

# High-Level Architecture

```
                User Applications
                        │
                        ▼
              Windows I/O Manager
                        │
                        ▼
          Filter Manager (fltmgr.sys)
                        │
                        ▼
         ┌────────────────────────────┐
         │        Kratos.sys          │
         │                            │
         │  IRP_MJ_CREATE             │
         │  IRP_MJ_READ               │
         │  IRP_MJ_WRITE              │
         │  IRP_MJ_SET_INFORMATION    │
         │                            │
         │  Process Contexts          │
         │  File Contexts             │
         │  Threat Scoring            │
         └────────────────────────────┘
                        │
                        ▼
                  NTFS / ReFS
```

---

# Detection Pipeline

Kratos does not rely on a single indicator.

Every process accumulates evidence.

```
Process

↓

Create File

↓

Write Data

↓

Entropy Analysis

↓

Delete Files

↓

Rename Files

↓

Threat Score

↓

Warning

↓

Critical

↓

Process Termination

↓

Fingerprint Blacklist
```

---

# Detection Engine

Kratos combines three independent detection layers.

## Behavioral Analysis

- Valuable file deletion
- Suspicious rename operations
- Ransom note creation
- Shadow Copy deletion

---

## Entropy Analysis

Each write operation is sampled.

Instead of calling floating-point functions unavailable inside the kernel, Kratos uses a precomputed lookup table.

The detector identifies:

- encrypted overwrite
- high-entropy temporary files
- sudden entropy increase

---

## Structural Analysis

Instead of maintaining a blacklist of malicious extensions, Kratos introduces an **inverse whitelist**.

```
Original extension

↓

Valuable ?

↓

YES

↓

New Extension

↓

Known ?

↓

NO

↓

Suspicious
```

Because of this approach, Kratos does not need to know future ransomware extensions.

---

# Threat Scoring

Every suspicious action contributes to a cumulative score.

| Event | Score |
|-------|-------:|
| Valuable File Deletion | +10 |
| Suspicious Rename | +40 |
| High Entropy Writes | +40 |
| Ransom Note Creation | +60 |
| Shadow Copy Deletion | +75 |

```
0 ─────────────── Normal

60 ───────────── Warning

80 ───────────── Critical

Terminate Process

Blacklist Fingerprint
```

---

# Fingerprint Blacklist

Once ransomware is confirmed, Kratos computes a 64-bit FNV-1a fingerprint from the executable.

The fingerprint is stored inside:

```
HKLM\SOFTWARE\Kratos\Blacklist
```

Future executions are blocked **before** the ransomware starts encrypting files.

Unlike filename-based blacklists, fingerprinting survives:

- renamed binaries
- copied executables
- random filenames

---

# Driver Architecture

Major components include:

- DriverEntry
- Filter Registration
- Instance Callbacks
- Process Notifications
- File Context Management
- Process Context Management
- Threat Scoring Engine
- Entropy Engine
- Fingerprint Database

---

# Current Features

- Kernel MiniFilter
- Behavioral Detection
- Entropy Detection
- Reverse Whitelist
- Threat Scoring
- Process Fingerprinting
- Registry Blacklist
- Process Creation Callback
- Kernel Process Blocking
- DebugView Logging

---

# Build Requirements

- Windows 10 / 11 x64
- Visual Studio 2022
- Windows Driver Kit (WDK)
- Test Signing enabled
- Secure Boot disabled (recommended)

---

# Research Goals

Kratos serves as an experimental platform for studying:

- Behavioral ransomware detection
- Windows File System MiniFilters
- Kernel-mode telemetry
- File-system monitoring
- EDR detection logic
- Process reputation
- Anti-ransomware techniques

---

# Roadmap

## Completed

- Behavioral Engine
- Entropy Engine
- Threat Scoring
- Fingerprint Blacklist
- Registry Persistence

## Planned

- SHA-256 fingerprinting
- ETW telemetry
- User-mode service
- Cloud reputation
- YARA integration
- Machine-learning assisted scoring
- Hypervisor-assisted protection (ArgusVisor integration)

---

# Screenshots

<p align="center">
<img src="[docs/images/demo.pn](https://github.com/mukendi/kratosminifilter/blob/master/Screenshot%202026-07-13%20095112.png)g" width="650">
</p>

---

# Safety Warning

Kratos executes inside the Windows kernel.

Incorrect callbacks or synchronization bugs may result in system crashes.

Use only inside isolated research environments.

---

# Educational Mission

Kratos is not designed to compete with commercial antivirus software.

Its objective is to demonstrate how modern behavioral anti-ransomware technologies can be implemented inside a Windows Kernel MiniFilter while remaining understandable, extensible and suitable for research.

---

# License

Educational and Research Purposes.
