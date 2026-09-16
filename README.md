# Kratos MiniFilter

> A research-oriented Windows Kernel MiniFilter designed to study behavioral ransomware detection at the file-system level.

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Language](https://img.shields.io/badge/Language-C%2B%2B-orange)
![Driver](https://img.shields.io/badge/Kernel-Minifilter-success)
![Research](https://img.shields.io/badge/Focus-Behavioral%20Detection-red)

---

# Overview

Kratos is a research Windows File System Minifilter built on top of Microsoft's Filter Manager (`fltmgr.sys`).

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
# Attack timeline

Here is the exact chronology of this Ring 0 neutralization by Kratos (the anti-ransomware minifilter driver I am developing), reconstructed from kernel logs—featuring an unexpected twist on hypervisor shared folders:

​1. Note Drop (Silent Pass)
DarkSide begins by generating its .txt ransom note. Because text files generate low entropy and standard I/O patterns, Kratos triggers no alerts.
Intentional architectural choice: zero false positives on legitimate text editors and office software.

​2. Behavioral Breach (Guest VM)
The malware shifts to its destructive phase, targeting desktop files with the .27efa0d1 extension.
After 3 suspicious renames (a ZIP archive and 2 PNG images), syntax analysis combined with high entropy pushes the Threat Score past the critical threshold (\ge 80).
​Action: Kratos denies I/O (STATUS_ACCESS_DENIED), terminates the process (PID 6412), samples the first 4096 bytes of the PE header, and registers its FNV-1a hash (07BACD78B04E01D9) in the kernel blacklist.

​3. Cross-Boundary Attack: Saving the HOST System! 🛑
A second thread (PID 5236) rushes into the blog-security-main directory on HarddiskVolume5.
​The Twist: This volume mapped directly to the hypervisor's shared folder connected to the HOST physical drive. DarkSide was attempting a Guest-to-Host lateral infection.
​Outcome: Attached to all volumes, Kratos intercepts the renaming after just 2 files (about.html and a web page). The process is killed instantly, preserving the host-based project in its entirety.

​4. The Final Blow: O(1) Immunization
A third launch attempt of the binary is initiated (PID 704).
Right at the PreCreate callback, Kratos hashes the PE header, matches the blacklisted fingerprint, and smothers execution at the source: 0 files touched.

## Battle Report:

- User files impacted: 5 total (3 on Guest, 2 on Host via Shared Folder).

​- Guest-to-Host Guest-to-Host lateral infection: Completely blocked from Ring 0 inside the VM.

- Ressponse time: Microseconds (fixed-point LUT entropy calculation, zero flooperationst operations)

- ​Proactive defense: 100% FNV-1a fingerprinting efficacy upon re-execution.

## PoC

![Architecture](https://github.com/mukendi/kratosminifilter/blob/master/Kratos_DarkSide.png)

‎Figure : Kratos vs DarkSide


# Safety Warning

Kratos executes inside the Windows kernel.

Incorrect callbacks or synchronization bugs may result in system crashes.

Use only inside isolated research environments.

---

# Research Mission

Kratos is not designed to compete with commercial antivirus software.

Its objective is to demonstrate how modern behavioral anti-ransomware technologies can be implemented inside a Windows Kernel MiniFilter while remaining understandable, extensible and suitable for research.

---

# License

Educational and Research Purposes.
