# Hypervisor-Based Rootkit Detection System

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux_KVM/QEMU-green.svg)]()
[![LibVMI](https://img.shields.io/badge/Library-LibVMI-v0.13+-purple.svg)]()

A standalone, out-of-band security solution that detects kernel-level rootkits in Linux Virtual Machines using Hardware Virtualization (Intel VT-x).

## Table of Contents

- [About The Project](#about-the-project)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation and Setup](#installation-and-setup)
- [Usage](#usage)
- [Testing and Results](#testing-and-results)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Academic Context](#academic-context)

## About The Project

Traditional antivirus software runs inside the operating system it tries to protect. Modern Rootkits exploit this by hiding inside the kernel, blindfolding the AV and stealing data undetected.

This project solves that problem by moving the detection logic outside the guest OS. Using Virtual Machine Introspection (VMI) via the LibVMI library, this system monitors the physical memory of a Guest VM from the Host Hypervisor layer. It provides an unalterable "ground truth" of the system state, bypassing any lies the rootkits tell the operating system.

### Why This Matters

- **Tamper-Resistant:** The detector runs on the Host; the malware in the Guest cannot see, stop, or modify it.
- **Real-Time:** Scans memory every few seconds without stopping the VM.
- **Forensic Integrity:** Maintains an immutable, append-only log of all security events.

## Key Features

| Feature | Description |
| :--- | :--- |
| Hidden Process Detection | Compares the trusted process list (from physical memory traversal) against the untrusted list (from Guest OS) to find hidden PIDs. |
| Syscall Integrity Check | Validates the sys_call_table handlers to ensure they point to legitimate kernel text, detecting syscall hooks. |
| IDT Integrity Monitor | Checks the Interrupt Descriptor Table for hijacked vectors (limited by KPTI on newer kernels). |
| Heuristic Fallback | Scans physical memory for known rootkit signatures (e.g., Diamorphine, Adore-ng) when kernel symbols are unavailable (KASLR mitigation). |
| Dashboard | A custom C-based HTTP server with alerts and forensic logs. |
| Thread-Safe Alerting | Uses POSIX Mutexes and a Circular Buffer to handle concurrent detection threads without data corruption. |

## System Architecture

The system follows a Hybrid Three-Tier Client-Server Architecture:

1. **Presentation Tier:** Web Dashboard (HTML/CSS/JS) running in the browser.
2. **Application Tier:** Custom C HTTP Server + Detection Modules (Process, Syscall, IDT, Fallback).
3. **Data Tier:** LibVMI Engine interacting with KVM/QEMU Hypervisor to read Guest Physical Memory.

```mermaid
graph TD
    User[Security Analyst] -->|HTTP Request| Dashboard[Web Dashboard]
    Dashboard -->|API Call| Server[C-Based HTTP Server]
    Server -->|Reads Buffer| AlertMgr[Alert Manager]
    AlertMgr -->|Mutex Lock| Buffer[Circular Buffer]
    Server -->|Start Scan| Monitor[Monitoring Loop]
    Monitor -->|LibVMI| Hypervisor[KVM/QEMU Hypervisor]
    Hypervisor -->|Reads RAM| GuestVM[Guest VM Infected]
    Monitor -->|Writes Alert| AlertMgr
    AlertMgr -->|Append Only| Log[Forensic Audit Log]
