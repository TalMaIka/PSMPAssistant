# PSMPChecker

## Description

A Python-based tool designed to verify the installation and compatibility of Privileged Session Manager Proxy (PSMP) on Linux systems. This tool evaluates PSMP and SSHD service statuses, supported Linux distributions, configuration compliance, and generates necessary system logs for diagnostic purposes.

## Installation

To install the dependencies required for this tool, you can use pip and the provided `requirements.txt` file. Make sure you have Python and pip installed on your system. Then, follow these steps:

```bash
git clone https://github.com/TalMaIka/PSMPChecker.git
cd PSMPChecker
Requirments are Python3.6+ and Python3-pip
[RHEL/CentOS] pip3 install -r requirements.txt / python3 prerequisite.py (offline machines)
```

## Usage

To use the tool, run the `main.py` script with optional arguments.

### Checking PSMP Compatibility and Configuration

Run the script without any arguments to check the PSMP compatibility with the current system:

```bash
python3 main.py
```
<img src="https://i.postimg.cc/zf9GLpwM/123.png" alt="Tool landing page" style="width:92%;">

### Collecting Logs

To collect logs from specified locations and create a zip file, use the `logs` argument:

```bash
python3 main.py logs
```

### RPM Repair Automation

To execute the PSMP RPM repair process `repair` argument:

```bash
python3 main.py repair
```

### Generating PSMP Connection String

To generate a PSMP connection string, use the `string` argument:

```bash
python3 main.py string
```

### Restoring SSHD Configuration

To restore the SSHD configuration from a backup, use the `restore-sshd` argument:

```bash
python3 main.py restore-sshd
```


## Features

### Compatibility Validation
- Ensures that the installed PSMP version is compatible with the detected Linux distribution and version based on official CyberArk documentation.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20sysreq/system%20requirements%20-%20psmp.htm

### Service Monitoring
- Checks and verifies the status of PSMP and SSHD services.
 + Checks communication between PSMP and Vault server, including options to update the Vault IP address if needed.
 + Disbale NSCD - https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm#DisableNSCD

### OpenSSH Version Check
- Verifies if the installed OpenSSH version meets the required version.

### Hostname Validation
- Checks if the system hostname is set to a unique value to avoid future issues.

### System Resource Check
- Monitors CPU and memory usage to ensure they are within acceptable limits and verifies if there is sufficient disk space.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20sysreq/system%20requirements%20-%20psmp.htm

### PAM Configuration Check
- Validates the PAM configuration for certain Linux distributions.
 + https://community.cyberark.com/s/article/00004683

### NSswitch Configuration Check
- Validates the NSswitch configuration based on PSMP version.
 + https://community.cyberark.com/s/article/PSM-SSH-Proxy-Failed-to-start

### SSHD Configuration Check
- Ensures proper configuration of the SSHD service to allow proper PSMP flow.

### Logs Collection
- Collects logs from specified locations and creates a zip file for analysis.
 + Checks if the SSHD debug level is set to DEBUG3.
 + https://community.cyberark.com/s/article/00003368

### RPM Installation Repair
- Automates the pre-installation steps by locating the RPM folder *matching* the PSMP installed version followed by executing the repair.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm

### SSHD Configuration Restoration
- Restores the SSHD configuration from a backup file located in opt/CARKpsmp/backup/sshd_config_backup.

### PSMP Connection String Generation
- Generates a PSMP connection string based on user input. 
 + https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet

### Secure and PSMPTrace Logs Pattern Detection
- Searches the `PSMPTrace.log` and `secure` files for specific error patterns and alerts to diagnose potential issues.



