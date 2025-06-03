# Evasive Process Hypnosis
## Overview
This project implements an advanced version of the Process Hypnosis technique for shellcode injection, designed to be more evasive against modern antivirus and EDR solutions. It builds upon the original technique by @NUL0x4C and @mrd0x from MalDevAcademy, adding features like shellcode encryption, random process selection, APC injection, and anti-debugging checks.

## Features
- Shellcode Encryption: XOR-encrypts the shellcode (calc.exe launcher) to evade static analysis.
- Random Process Selection: Targets common Windows processes (e.g., svchost.exe, explorer.exe) to blend in.
- APC Injection: Uses QueueUserAPC for less detectable shellcode execution.
- Anti-Debugging: Detects debuggers using IsDebuggerPresent and CheckRemoteDebuggerPresent.
- Dynamic Process Enumeration: Finds running processes with CreateToolhelp32Snapshot.
- Clean Memory Management: Minimizes forensic artifacts by freeing allocated memory and closing handles.

## Requirements

- Windows OS (tested on Windows 10/11)
- Windows SDK
- C compiler (e.g., Visual Studio)
- Administrative privileges for process injection

## Compilation

Clone the repository:
```
git clone https://github.com/yourusername/process-hypnosis.git
```
Open the project in Visual Studio or compile with a C compiler:
```
cl EvasiveProcessHypnosis.c /link /out:process_hypnosis.exe
```

Ensure the Windows SDK is installed for required headers (Windows.h, TlHelp32.h).

## Usage

Run the compiled executable in a controlled environment (e.g., a virtual machine):.\process_hypnosis.exe


The program will:
- Check for debuggers and exit if detected.
- Select a random target process (svchost.exe, explorer.exe, etc.).
- Inject encrypted shellcode into the target process using APC.
- Execute the shellcode (launches calc.exe for demonstration).



## Notes

Educational Use Only: This code is for learning and research purposes. Do not use it maliciously.
Shellcode: The included shellcode launches calc.exe. Replace it with custom shellcode as needed.
Limitations:
XOR encryption is basic; consider AES or polymorphism for production use.
APC injection requires the target thread to be alertable.
Additional anti-debugging techniques (e.g., timing checks) can be added.


Testing: Always test in a sandbox or virtual machine to avoid unintended consequences.

## Disclaimer
This project is for educational purposes only. The author is not responsible for any misuse or damage caused by this code. Use responsibly and in compliance with applicable laws.
Credits

Original Process Hypnosis technique by @NUL0x4C and @mrd0x (MalDevAcademy)
Enhanced by Cuong Nguyen

## License
MIT License. See LICENSE for details.
