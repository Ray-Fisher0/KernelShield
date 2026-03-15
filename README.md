
# Rootkit Detector Group Project

In this project, the contributers each worked together to create similar yet different approaches for detecting rootkit activity to determine which one was the most effective for detection. What follows is the details of our work. This project is designed for educational and research purposes, providing a robust foundation for kernel security analysis.

--

## Table of Contents
- [What is a Rootkit?](#what-is-a-rootkit)
- [Why Rootkit Detection Matters](#why-rootkit-detection-matters)
- [Overview of Layer 1](#overview-of-approach-1)
- [How to Run the Detector](#how-to-run-the-detector)
- [Project Structure](#project-structure)
- [License](#license)
- [Contributing](#contributing)
- [Contact](#contact)

---

## What is a Rootkit?

A rootkit is a type of malicious software designed to gain unauthorized access to a computer system, often by hiding its presence and activities from users and security tools. Rootkits typically operate at the kernel level, allowing attackers to intercept system calls, modify kernel data structures, and conceal files or processes. This makes them extremely difficult to detect and remove.

Rootkits are dangerous because they can provide persistent, stealthy control over a system, enabling attackers to steal sensitive information, disable security mechanisms, and install additional malware. Detecting rootkits is crucial for maintaining the integrity and security of operating systems, especially in environments where sensitive data or critical infrastructure is involved.

## Why Rootkit Detection Matters

Rootkit detection is important because rootkits can compromise the trustworthiness of a system, evade traditional antivirus tools, and facilitate further attacks. By monitoring for suspicious kernel activity—such as attempts to access the system call table—our detection module helps identify potential rootkit behavior early, allowing administrators to respond before significant damage occurs.

## Overview of Project

For Layer 1, the strategy implemented leverages kernel probes (kprobes and kretprobes) to monitor the usage of the `kallsyms_lookup_name` function, which is frequently used by rootkits to locate and manipulate sensitive kernel symbols. By tracking calls to this function, it can detect attempts to resolve addresses of critical kernel structures, such as the system call table, even if the attacker does not directly modify the table 

Additionally a second Linux kernel module was created to detect rootkit activity by monitoring suspicious modifications to the system call table. This approach is based on the idea that many rootkits attempt to alter syscall table entries to hijack system functionality.

**How Layer1 Works:**
- Registers a kretprobe on `kallsyms_lookup_name` to intercept and log symbol lookups.
- Captures process information and the symbol being queried, providing context for potential rootkit activity.
- Alerts are written to the kernel log and via a `/proc` entry for user-space monitoring.
- Supports multiple architectures (x86, x86_64, ARM64) with safe handling of kernel strings and register sets.
**How Layer2 Works**
- Takes a baseline snapshot of the syscall table(s) at module load.
- Periodically compares the current table entries to the baseline.
- Logs any detected changes, which may indicate rootkit activity.
- Alerts are written to the kernel log and via a `/proc` entry for user-space monitoring.

**Summary:**
- Provides direct detection of syscall table modifications, a common rootkit technique.
- Simple and effective for older kernels where the syscall table is exported.
- First part detects rootkit behavior before actual modification occurs, by monitoring suspicious symbol resolution attempts while the second part can monitor anything that is missed.
- Works on newer kernels where direct syscall table access is restricted, as it does not require exported syscall table symbols.
- It provides early warning of rootkit activity by tracking symbol resolution attempts, not just table modifications.

---

## How to Run the Detector For Layer 1 and 2 for X86

Follow these steps to build and run the kernel module:

1. **Build the module:**
   - Ensure you have the necessary kernel headers installed for your system.
   - Run `make` in the project directory to compile the module.

2. **Load the module:**
   - Use `sudo insmod module.ko` to insert the Layer1 module into the kernel.
   - Navigate to X86 folder in Layer2:
      - Use the command `sudo insmod module_scan.ko` to create Layer2
   - Check the kernel log (`dmesg`) for messages indicating successful registration with `sudo dmesg | tail`

3. **Monitor alerts:**
   - Read the latest alert message from `/proc/kallsyms_alert` using `cat /proc/kallsyms_alert`.
   - Alerts will also appear in the kernel log.

When you want to unload the module:

- **Unload the module:**
   - Use `sudo rmmod module` to remove the module from the kernel.
      - The same goes for module_scan
   - Check `dmesg` for cleanup messages.

**Note:** Running kernel modules requires root privileges and can affect system stability. Only test on systems where you can safely experiment.

---

## Project Structure

- `module.c` — Main kernel module implementation for rootkit detection.
- `module.h` — Header file containing core definitions and function prototypes.
- `module_scan.c` — Syscall table watcher for Linux Kernel 4.0 and lower.
- `module_scan.h` — Header for syscall table watcher.
- `Makefile` — Build instructions for compiling the kernel module.
- `README.md` — Project documentation and instructions.
- `test_module/` — Directory for test modules.

## License

This project is licensed under the GPL-2.0. More information can be found under the LICENSE file.

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request for review.

## Contact

For questions or collaboration, please contact the project maintainers via GitHub or email.
