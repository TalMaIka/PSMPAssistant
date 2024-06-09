# PSMPChecker

## Description

This Python tool validates compatibility between installed CyberArk Privileged Session Manager (PSMP) versions and various Linux distributions. It checks if the PSMP version is supported on the detected Linux distribution, verifies the status of the PSMP service, and ensures proper OpenSSH configuration. With just a few commands, it provides valuable insights into PSMP compatibility and system configuration.

## Installation

To install the dependencies required for this tool, you can use pip and the provided `requirements.txt` file. Make sure you have Python and pip installed on your system. Then, follow these steps:

```bash
git clone https://github.com/TalMaIka/PSMPChecker.git
cd PSMPChecker
[RHEL/CentOS] pip3 install -r requirements.txt
```

## Usage

To use the tool, run the `main.py` script with optional arguments.

### Checking PSMP Compatibility

Run the script without any arguments to check the PSMP compatibility with the current system:

```bash
python3 main.py
```

### Collecting Logs

To collect logs from specified locations and create a zip file, use the `logs` argument:

```bash
python3 main.py logs
```

### Restoring SSHD Configuration

To restore the SSHD configuration from a backup, use the `restore-sshd` argument:

```bash
python3 main.py restore-sshd
```

## Features

- **Compatibility Check:** Validates compatibility between installed PSMP versions and Linux distributions.
- **Service Status:** Verifies the status of PSMP and SSHD services.
- **OpenSSH Configuration:** Ensures proper configuration of OpenSSH.
- **Logs Collection:** Collects logs from specified locations and creates a zip file for analysis.
- **SSHD Configuration Restoration:** Restores the SSHD configuration from a backup file.

## Contributing

Contributions are welcome! Fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
