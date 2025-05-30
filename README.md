# Process Hypnosis

An advanced Windows process injection tool demonstrating stealthy shellcode injection techniques to evade detection. This project showcases XOR-encrypted shellcode, dynamic target selection, APC injection, and anti-debugging measures designed for security research and red team engagements.

## Features

* **Shellcode Obfuscation:** XOR-encrypted shellcode decrypted at runtime to avoid static detection
* **Dynamic Process Selection:** Targets common Windows processes (e.g., `svchost.exe`, `explorer.exe`) to blend with legitimate activity
* **APC Injection:** Uses Asynchronous Procedure Calls to inject shellcode into a target thread, minimizing direct memory manipulation footprints
* **Anti-Debugging:** Detects debuggers with `IsDebuggerPresent` and `CheckRemoteDebuggerPresent` to evade analysis
* **Clean Resource Management:** Properly releases handles and memory to reduce forensic traces

## Prerequisites

* Windows OS (x64 architecture)
* C compiler (e.g., Microsoft Visual Studio)
* Windows SDK (for WinAPI functions)
* Administrative privileges for process manipulation

## Compilation

Compile using Microsoft Visual Studio’s command line:

```bash
cl main.c /link /out:EvasiveHypnosis.exe
```

## Usage

1. Compile the source code to produce the executable.
2. Run the executable with administrator privileges.
3. The program will:

   * Check for debugger presence and exit if detected
   * Dynamically select a target system process (e.g., `svchost.exe`)
   * Allocate memory within the target process
   * Decrypt and inject the XOR-encrypted shellcode using APC injection
   * Queue an APC on the target thread to execute the shellcode

### Example output

```
[+] APC queued to thread 1234 in process 5678
```

## Notes

* The example shellcode launches `calc.exe` as a demonstration payload; replace with custom shellcode for your needs.
* APC injection requires the target thread to be in an alertable state. If injection fails, consider alternative approaches or methods to induce an alertable state.
* This tool is intended strictly for educational and authorized security research purposes. Ensure compliance with all applicable laws and organizational policies.

## Disclaimer

This project is for educational use only and should only be run in controlled, authorized environments. The author is not liable for misuse or legal violations resulting from this code.

## License

MIT License – See LICENSE file for details.

## Acknowledgments

* Inspired by advanced malware and red team evasion techniques
* Thanks to the security research community for pioneering injection and evasion methods
