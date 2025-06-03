# Process Hypnosis Injector

This repository contains a Windows-based shellcode injector that uses the process hypnosis technique to inject an XOR-encrypted calculator-launching shellcode into `notepad.exe`. The technique leverages the Windows debugging API to inject code into a newly created thread’s start address, with XOR encryption applied to the shellcode and target process path for obfuscation.

## Features
- Implements the process hypnosis injection technique using the Windows debugging API.
- XOR-encrypts the shellcode and target path (`C:\Windows\System32\notepad.exe`) with a key (`0x5A`) at compile time.
- Decrypts data at runtime for process creation and injection.
- Includes robust memory management and error handling.
- Written in C for Windows (x64).

## Prerequisites
- Windows OS (tested on Windows 10/11 x64).
- A C compiler (e.g., Microsoft Visual Studio or MinGW).
- Basic understanding of shellcode, process injection, and the Windows debugging API.

## Building the Project
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/process-hypnosis-injector.git
   cd process-hypnosis-injector
   ```
2. Compile the code using a C compiler. For Visual Studio:
   ```bash
   cl injector.c /Fe:injector.exe
   ```
   For MinGW:
   ```bash
   gcc injector.c -o injector.exe
   ```

## Usage
1. Ensure the target process path (`C:\Windows\System32\notepad.exe`) exists on your system.
2. Run the compiled executable:
   ```bash
   .\injector.exe
   ```
3. The program will:
   - Decrypt the XOR-encrypted shellcode and target path.
   - Create a `notepad.exe` process in debug mode using `CreateProcessW`.
   - Wait for the `CREATE_THREAD_DEBUG_EVENT` and inject the decrypted shellcode into the thread’s start address.
   - Detach the debugger, allowing the shellcode to execute (launching `calc.exe`).
4. Check the console output for status messages or errors.

## Code Structure
- `injector.c`: Main source file containing the process hypnosis injector.
  - `EncryptedShellcode`: XOR-encrypted calculator shellcode.
  - `EncryptedTargetPath`: XOR-encrypted path to `notepad.exe`.
  - `XorDecryptBytes` and `XorDecryptWString`: Functions to decrypt data at runtime.
  - Main logic: Process creation, debug event handling, shellcode injection, and debugger detachment.

## Customization
- **Change XOR Key**: Modify `#define XOR_KEY 0x5A` in `injector.c` and regenerate the encrypted arrays using an XOR encryption tool.
- **New Shellcode**: Replace `EncryptedShellcode` with your own XOR-encrypted shellcode, ensuring compatibility with x64 Windows.
- **Target Process**: Update `EncryptedTargetPath` with the encrypted path to a different target process.

## Security Notes
- **XOR Encryption**: The XOR encryption is basic and reversible with analysis. For stronger obfuscation, consider advanced encryption or shellcode polymorphism.
- **Debugging Detection**: The use of `DEBUG_ONLY_THIS_PROCESS` may be detected by anti-debugging mechanisms in modern security software.
- **Responsible Use**: Use this code only in controlled, authorized environments for educational or research purposes.

## Disclaimer
This project is for educational purposes only. Unauthorized use of process injection techniques may be illegal and unethical. The authors are not responsible for misuse.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments
- Inspired by techniques from MalDevAcademy and the security research community.
- Thanks to contributors sharing knowledge on process injection and obfuscation techniques.