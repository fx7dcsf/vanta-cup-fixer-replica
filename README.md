# Vanta Cup Fixer Replica 🛠️

## Overview

Welcome to the Vanta Cup Fixer Replica project! 🎮🔧 This tool is a C++ based application designed to spoof certain system parameters, such as BIOS and Volume IDs, primarily used to bypass certain system checks. **This project is intended for educational purposes only**. Misuse of this software may violate terms of service or local laws.

## Features

- **Download Files**: Fetch necessary files from the internet.
- **File Management**: Check for the existence of files and delete them.
- **Spoofing**: Alter BIOS and Volume IDs to evade detection.
- **System Interaction**: Restart the system and clean up after execution.
- **Process Monitoring**: Continuously monitor and terminate specific processes.
- **HTTP Requests**: Perform HTTP GET requests to fetch data.

## Prerequisites

- **Windows Operating System**: This software is designed to work on Windows.
- **Visual Studio or Similar C++ IDE**: For compiling and building the project.
- **Required Libraries**:
  - WinINet (`wininet.lib`)
  - URLMon (`urlmon.lib`)

## How It Works

1. **Download and File Management**: 
   - The `DownloadFile` function uses WinINet to download files from a specified URL.
   - `checkFilesExist` and `fileExists` functions manage file checks and existence validation.

2. **Spoofing Functions**:
   - `spoofAMIDEWIN` and `spoofAFUWIN` use command-line tools to alter system parameters.
   - `spoofVolumeID` changes volume IDs for different drives using `Volumeid64.exe`.
     ## Sadly you have to add your own files 

3. **Process Monitoring**:
   - The `MonitorProcesses` function continuously checks and terminates specified processes like Task Manager and Explorer.

4. **System Interaction**:
   - `delete_current_executable` removes the current executable after downloading a new one.
   - `auto_update` manages updates by downloading and running a new version of the executable.

5. **User Interaction**:
   - The application prompts the user to restart the system and provides status messages during execution.

## Building the Project

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/vanta-cup-fixer-replica.git
cd vanta-cup-fixer-replica
```

### Step 2: Set Up Your Development Environment

- Open **Visual Studio** or your preferred C++ IDE.
- Create a new **C++ Project** and add the source files from the repository.

### Step 3: Configure Project Properties

- **Add Libraries**:
  - Go to Project Properties.
  - Under **Configuration Properties** > **Linker** > **Input**, add `wininet.lib` and `urlmon.lib` to the **Additional Dependencies**.

- **Include Directories**:
  - Under **Configuration Properties** > **C/C++** > **General**, add paths to any additional header files if needed.

### Step 4: Compile the Project

- Build the project by selecting **Build** > **Build Solution** in Visual Studio or use `make` if you're using a Makefile.

### Step 5: Run the Executable

- Run the compiled executable. The application will perform the spoofing tasks and interact with the system as described.

## Usage

1. **Initial Setup**: 
   - Ensure the required tools (e.g., `AMIDEWINx64.EXE`, `Volumeid64.exe`) are available in the specified paths.

2. **Executing the Program**:
   - The program will prompt for actions like cleaning the system or spoofing parameters.

3. **Monitoring**:
   - During execution, the program will monitor and terminate specific processes to prevent interference.

## Important Notes

- **Legal Notice**: Using spoofing software may breach software agreements and legal statutes. Ensure you understand the implications and legal risks.
- **Backup**: Always backup your data before running system-altering software.
- **Virus Scanning**: Ensure that the software you download and use is from a trusted source to avoid malware infections.

## Troubleshooting

- **Compilation Errors**: Ensure all libraries are properly linked and paths are set correctly.
- **Runtime Issues**: Verify that all external tools and dependencies are available and correctly configured.

## Contributing

If you have suggestions or improvements for the Vanta Cup Fixer Replica, feel free to open an issue or submit a pull request. Contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For any inquiries or support, please reach out to the repository owner through GitHub or email.

---

**Disclaimer**: This software is provided "as-is" without warranty of any kind. Use at your own risk. The authors are not responsible for any damage caused by the use of this software.

Happy coding! 🖥️🚀
