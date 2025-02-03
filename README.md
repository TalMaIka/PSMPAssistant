# PSMPWizard

## Description

A Python-based tool designed to verify the installation and compatibility of Privileged Session Manager Proxy (PSMP) on Linux systems. This tool evaluates PSMP and SSHD service statuses, supported Linux distributions, configuration compliance, and generates necessary system logs for diagnostic purposes.

## Installation

```bash
git clone https://github.com/TalMaIka/PSMPWizard.git
cd PSMPWizard
Requirements are Python3.6 +
```

## Usage

To use the tool, run the `PSMPWizard.py` script with optional arguments.

### Checking PSMP Compatibility and Configuration

Run the script without any arguments to check the PSMP compatibility with the current system:

```bash
python3 PSMPWizard.py
```
<img src="https://i.postimg.cc/vZqBXszB/main.png" alt="Tool landing page" style="width:80%;">

### Collecting Logs

To collect logs from specified locations and create a zip file, use the `logs` argument:

```bash
python3 PSMPWizard.py logs
```
<img src="https://i.postimg.cc/1zbzhrb1/logs.png" alt="Tool landing page" style="width:80%;">

### RPM Repair Automation

To execute the PSMP RPM repair process `repair` argument:

```bash
python3 PSMPWizard.py repair
```
<img src="https://i.postimg.cc/dt9DkdZG/repair.png" style="width:80%;">

### RPM Install Automation

To execute the PSMP RPM repair process `install` argument:

```bash
python3 PSMPWizard.py install
```

### Generating PSMP Connection String

To generate a PSMP connection string, use the `string` argument:

```bash
python3 PSMPWizard.py string
```
<img src="https://i.postimg.cc/HLrLhhZt/string.png" alt="Tool landing page" style="width:80%;">

### Restoring SSHD Configuration

To restore the SSHD configuration from a backup, use the `restore-sshd` argument:

```bash
python3 PSMPWizard.py restore-sshd
```


## Features

### Compatibility Validation
- Ensures that the installed PSMP version is compatible with the detected Linux distribution and version based on official CyberArk documentation.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20sysreq/system%20requirements%20-%20psmp.htm

### Service Monitoring
- Checks and verifies the status of PSMP and SSHD services.
 + Checks communication between PSMP and Vault server, including options to update the Vault IP address if needed.
 + Disable NSCD - https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm#DisableNSCD

### OpenSSH Version Check
- Verifies if the installed OpenSSH version meets the required version.

### Hostname Validation
- Checks if the system hostname is set to a unique value to avoid future issues.

### System Resource Check
- Monitors CPU and memory usage to ensure they are within acceptable limits and verifies if there is sufficient disk space.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20sysreq/system%20requirements%20-%20psmp.htm

### NSswitch Configuration Check
- Validates the NSswitch configuration based on the PSMP version.
 + https://community.cyberark.com/s/article/PSM-SSH-Proxy-Failed-to-start

### SSHD Configuration Check
- Ensures proper configuration of the SSHD service to allow proper PSMP flow.

### Logs Collection
- Collect logs from specified locations and create a zip file for analysis.
 + Checks if the SSHD debug level is set to DEBUG3.
 + https://community.cyberark.com/s/article/00003368

### RPM Installation - Repair
- Automates the pre-installation steps by locating the RPM folder *matching* the PSMP installed version and executing the repair.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm

### RPM Installation - Upgrade
-  Simplifies upgrading to the latest available PSMP version.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/upgrading-the-psmp.htm

### RPM Installation - Install
-  Automates the process of installing the PSMP package.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm

### SSHD Configuration Restoration
- Restores the SSHD configuration from a backup file located in opt/CARKpsmp/backup/sshd_config_backup.

### PSMP Connection String Generation
- Generates a PSMP connection string based on user input. 
 + https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet

### Secure and PSMPTrace Logs Pattern Detection
- Searches the `PSMPTrace.log` and `secure` files for specific error patterns and alerts to diagnose potential issues.



