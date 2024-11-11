# PSMPChecker

## Description

A Python-based tool designed to verify the installation and compatibility of Privileged Session Manager Proxy (PSMP) on Linux systems. This tool evaluates PSMP and SSHD service statuses, supported Linux distributions, configuration compliance, and generates necessary system logs for diagnostic purposes.

## Installation

To install the dependencies required for this tool, you can use pip and the provided `requirements.txt` file. Make sure you have Python and pip installed on your system. Then, follow these steps:

```bash
git clone https://github.com/TalMaIka/PSMPChecker.git
cd PSMPChecker
Requirments are python3-devel and python3-pip
[RHEL/CentOS] pip3 install -r requirements.txt / python3 prerequisite.py
```

## Usage

To use the tool, run the `main.py` script with optional arguments.

### Checking PSMP Compatibility and Configuration

Run the script without any arguments to check the PSMP compatibility with the current system:

```bash
python3 main.py
```
![Example-Use](https://i.imgur.com/OsVDvUy.png)

### Collecting Logs

To collect logs from specified locations and create a zip file, use the `logs` argument:

```bash
python3 main.py logs
```
![Example-Logs](https://i.imgur.com/JPNZOVs.png)

### Restoring SSHD Configuration

To restore the SSHD configuration from a backup, use the `restore-sshd` argument:

```bash
python3 main.py restore-sshd
```
![Example-Sshd](https://i.imgur.com/LBrUQH7.png)

### Generating PSMP Connection String

To generate a PSMP connection string, use the `string` argument:

```bash
python3 main.py string
```
![Example-String](https://i.imgur.com/5lPEP5c.png)


## Features

- **Compatibility Validation:** Ensures that the installed PSMP version is compatible with the detected Linux distribution.
- **Service Monitoring:** Checks and verifies the status of PSMP and SSHD services.
- **OpenSSH Version Check:** Verifies if the installed OpenSSH version meets the required version.
- **PAM Configuration Check:** Validates the PAM configuration for certain Linux distributions.
- **SSHD Configuration Check:** Ensures proper configuration of the SSHD service.
- **Logs Collection:** Collects logs from specified locations and creates a zip file for analysis.
- **SSHD Configuration Restoration:** Restores the SSHD configuration from a backup file.
- **SSHD Debug Level Check:** Checks if the SSHD debug level is set to DEBUG3.
- **PSMP Connection String Generation:** Generates a PSMP connection string based on user input.
- **Disk Space Check:** Verifies if there is sufficient disk space on the system.
- **System Resource Check:** Monitors CPU and memory usage to ensure they are within acceptable limits.
- **Failed Connection Attempt Detection:** Searches system logs for failed connection attempts.
- **PSMP Trace Log Pattern Search:** Searches the PSMPTrace.log file for specific error patterns.
- **Hostname Validation:** Checks if the system hostname is set to a unique value to avoid future issues.

## Contributing

Contributions are welcome! Fork the repository and submit a pull request with your changes.

