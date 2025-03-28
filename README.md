# PSMPAssistant

## Description

A Python-based tool designed to verify the installation and compatibility of Privileged Session Manager Proxy (PSMP) on Linux systems. This tool evaluates PSMP and SSHD service statuses, supported Linux distributions, configuration compliance, and generates necessary system logs for diagnostic purposes.

## Cloning

```bash
git clone https://github.com/TalMaIka/PSMPAssistant.git
cd PSMPAssistant
Requirements are Python3.6 +
```

## Usage

To use the tool, run the `PSMPAssistant.py` script with optional arguments.

### Checking PSMP Compatibility and Configuration

Run the script without any arguments to check the PSMP compatibility with the current system:

```bash
python3 PSMPAssistant.py
```
<img src="https://i.imgur.com/FJ93No4.gif" alt="Tool landing page">

### Collecting Logs

To collect logs from specified locations and create a zip file, use the `logs` argument:

```bash
python3 PSMPAssistant.py logs
```
<img src="https://i.postimg.cc/vTpzjcqy/logs.gif" alt="Tool landing page">

### RPM Repair Automation

To execute the PSMP RPM repair process `repair` argument:

```bash
python3 PSMPAssistant.py repair
```
<img src="https://i.postimg.cc/cLGhBttM/repair.gif">

### Generating PSMP Connection String

To generate a PSMP connection string, use the `string` argument:

```bash
python3 PSMPAssistant.py string
```
<img src="https://i.postimg.cc/sf8w1NVL/string.gif" alt="Tool landing page">


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

### RPM Repair
- Automates the pre-installation steps by locating the RPM folder *matching* the PSMP installed version and executing the repair.
 + https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm

### PSMP Connection String Generation
- Generates a PSMP connection string based on user input. 
 + https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet

### Secure and PSMPTrace Logs Pattern Detection
- Searches the `PSMPTrace.log` and `secure` files for specific error patterns and alerts to diagnose potential issues.



