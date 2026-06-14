# kratosminifilter
 Kratos is a high-performance Windows File System Minifilter driver designed to detect, block, and permanently immunize
  systems against ransomware attacks in real-time. Unlike user-mode solutions, Kratos operates at the kernel level (Ring
  0), providing absolute visibility into I/O operations and resilience against evasion techniques like Direct Syscalls.

  🚀 Key Features

   * Behavioral Entropy Analysis: Real-time Shannon entropy calculation on write buffers to detect encryption patterns.
     Optimized with a Fixed-Point LUT (Look-Up Table) for near-zero CPU overhead.
   * Rename & Extension Monitoring: Tracks suspicious renaming patterns (e.g., .tmp to .locked or random extensions)
     using cumulative scoring.
   * Digital Fingerprinting (FNV-1a): When a threat is confirmed, Kratos captures a Partial Hash (64KB sampling) of the
     malicious binary to permanently blacklist it.
   * Spoofing Protection: Kernel-namespace absolute path validation to detect impersonators (e.g., a malware named
     svchost.exe running from the Desktop).
   * Surgical Termination: Immediate process termination via Kernel WorkItems (PsTerminateProcess) upon reaching the
     critical threat threshold.
   * Performance First: Zero dynamic memory allocation in critical paths, O(1) hash table lookups, and efficient AVL
     tree process tracking.

  🏗️ Architecture

  Kratos sits in the Anti-Ransomware Altitude (400000-409999) of the Windows filter stack.

  ┌─────────────────┬──────────────────────────────────────────────────────────────────────────────────┐
  │ Component       │ Description                                                                      │
  ├─────────────────┼──────────────────────────────────────────────────────────────────────────────────┤
  │ Pre-Create      │ Identifies caller identity and checks against the FNV-1a immunization table.     │
  │ Pre-Write       │ Measures data entropy delta. High entropy + high frequency = ransomware signal.  │
  │ Pre-SetInfo     │ Intercepts renames and deletions. Core logic for detecting substitution ciphers. │
  │ Threat Engine   │ A weighted scoring system that accumulates signals to reach a verdict.           │
  │ Context Manager │ Manages KS_PROCESS_CONTEXT and KS_FILE_CONTEXT for zero-copy state tracking.     │
  └─────────────────┴──────────────────────────────────────────────────────────────────────────────────┘
  🛠️ Technical Specifications

   * Language: C / C++
   * Framework: Windows Driver Kit (WDK) / Minifilter (FltMgr.sys)
   * Algorithms:
       * Entropy: 64-bit Integer Fixed-Point Shannon Approximation.
       * Hashing: FNV-1a (Fowler–Noll–Vo) for high-speed indexing.
       * Data Structures: RTL_AVL_TABLE for per-process telemetry.

  📊 Threat Scoring Model

  Kratos uses a cumulative heuristic engine to minimize false positives:

   * High Entropy Write: +40 pts
   * Suspicious Rename: +40 pts
   * Shadow Copy Deletion Attempt: +75 pts
   * Ransom Note Creation: +60 pts
   * Verdict:
       * Score >= 60: WARNING (Logged to DebugView)
       * Score >= 80: CRITICAL (Block + Terminate + Immunize)

  🛡️ Resilience vs. Restoration

  Kratos follows a Secure by Design philosophy. Instead of wasting resources on unstable backup mechanisms (like ADS or
  Shadow Copy clones during an attack), Kratos prioritizes Blocking Speed. It allows a strict quota of < 3 files to be
  manipulated before neutralizing the threat and immunizing the system for the rest of its lifecycle.

  📦 Installation & Testing

  > Warning: Running experimental kernel drivers can cause system instability (BSOD). Always test in a virtual
  environment (VMWare/Hyper-V).

   1. Enable Test Signing: bcdedit /set testsigning on
   2. Right-click kratosminifilter.inf and select Install.
   3. Load the driver:
   1     sc start kratosminifilter
   4. Monitor activity via DebugView (run as Administrator, enable Kernel Capture).

  📄 License

  This project is intended for security research and educational purposes only.

  ---
  Author: Simon Ngoy
  Focus: Windows Internals / Kernel Development / Red Team Research
