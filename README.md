# PSMPChecker

## Description

PSMPChecker is a Python tool designed to streamline the process of verifying compatibility between the installed version of a proprietary software known as PSMP (Privileged Session Management Proxy) and various Linux distributions.

This tool automates the retrieval of the installed PSMP version and the version of the Linux distribution in use. It then cross-references this information with a predefined set of compatibility rules stored in a JSON file to determine if the combination is officially supported.

PSMPChecker provides clear insights into whether the current PSMP version is compatible with the installed Linux distribution, enabling system administrators and IT professionals to make informed decisions regarding software updates and system configurations.


## Installation

To install the dependencies required for this tool, you can use pip and the provided `requirements.txt` file. Make sure you have Python and pip installed on your system. Then, follow these steps:

```bash
git clone https://github.com/yourusername/your-project.git
cd your-project
pip install -r requirements.txt
