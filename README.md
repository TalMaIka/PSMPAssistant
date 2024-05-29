# PSMPChecker

## Description

This Python tool validates compatibility between installed CyberArk Privileged Session Manager (PSMP) versions and various Linux distributions. It checks if the PSMP version is supported on the detected Linux distribution, verifies the status of the PSMP service, and ensures proper OpenSSH configuration. With just a few commands, it provides valuable insights into PSMP compatibility and system configuration.


## Installation

To install the dependencies required for this tool, you can use pip and the provided `requirements.txt` file. Make sure you have Python and pip installed on your system. Then, follow these steps:

```bash
git clone https://github.com/TalMaIka/PSMPChecker.git
cd PSMPChecker
pip install -r requirements.txt / [RHEL] pip3 install -r requirements.txt

