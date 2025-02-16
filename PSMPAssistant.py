# Copyright: © 2025 CyberArk Community, Developed By Tal.M
# Version: 1.1
# Description: This tool performs a series of checks and operations related to CyberArk's Privileged Session Manager for SSH Proxy (PSMP) and SSHD configuration on Linux systems.

import json
import subprocess
import re
import os
import shutil
import datetime
import zipfile
import sys
import socket
from time import sleep
from collections import deque
import logging
from datetime import datetime
import signal
import getpass
import glob


# Global flag for repair
REPAIR_REQUIRED = False

# Logging to write to the dynamically named file and the console
log_filename = datetime.now().strftime("PSMPAssistant-%m-%d-%y-%H:%M.log")
logging.basicConfig(
    level=logging.INFO,  
    format='%(message)s',  
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

# Verifing privileged user
def check_privileges():
    if os.geteuid() != 0:
        print("\n[!] PSMPAssistant tool must be run as root!")
        sleep(2)
        sys.exit(1)

# Define the signal handler
def handle_signal(signal, frame):
    print("\n\nTerminating tool...") 
    delete_file(log_filename)
    sleep(2)  
    sys.exit(0) 

# Set up the signal handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, handle_signal)

# File deletion as argument.
def delete_file(file_path):
    try:
        os.remove(file_path)
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except PermissionError:
        print(f"Permission denied: Unable to delete '{file_path}'.")
    except Exception as e:
        print(f"An error occurred: {e}")


# PSMPAssistant Logo
def print_logo():
    logo = r"""
 ____  ____  __  __ ____   _            _     _              _   
|  _ \/ ___||  \/  |  _ \ / \   ___ ___(_)___| |_ __ _ _ __ | |_ 
| |_) \___ \| |\/| | |_) / _ \ / __/ __| / __| __/ _` | '_ \| __|
|  __/ ___) | |  | |  __/ ___ \\__ \__ \ \__ \ || (_| | | | | |_ 
|_|   |____/|_|  |_|_| /_/   \_\___/___/_|___/\__\__,_|_| |_|\__|
      © 2024 CyberArk Community, Developed By Tal.M"""
    logging.info(logo)


# Load PSMP versions from a JSON file

def load_psmp_versions_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Get the installed PSMP version

def get_installed_psmp_version():
    try:
        result = subprocess.check_output("rpm -qa | grep -i cark", shell=True, universal_newlines=True).strip()
        
        if result:
            lines = result.splitlines()
            for line in lines:
                if "infra" in line.lower():
                    continue
                
                parts = line.split('-')
                if len(parts) > 1:
                    version = parts[1]
                    
                    # Extract major and minor version numbers
                    try:
                        major, minor, *_ = version.split('.')
                        main_version = f"{major}.{minor}"
                        
                        # Map version 12.0X to 12.X format
                        if main_version.startswith("12.0"):
                            main_version = main_version.replace("12.0", "12.")
                        
                        return main_version
                    except ValueError:
                        logging.warning(f"Unable to parse version from: {version}")
        
        # Return None if no valid version is found
        return None
    
    except subprocess.CalledProcessError:
        # Log and return None if the command fails
        for arg in sys.argv:
            if arg == "install":
                 return None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return None


# Get the Linux distribution and version

def get_linux_distribution():
    try:
        # Check CentOS or Red Hat release files
        for release_file in ["/etc/centos-release", "/etc/redhat-release"]:
            try:
                with open(release_file, "r") as f:
                    content = f.read().strip()
                    if content:
                        # Remove "Core" if present and extract major.minor version
                        content = content.replace("Core", "").strip()
                        version_parts = content.split("release")[1].strip().split(" ")
                        major_minor_version = version_parts[0].split(".")[:2]
                        # Format the output for CentOS and RHEL
                        if "CentOS" in content:
                            return "CentOS Linux", '.'.join(major_minor_version)
                        elif "Red Hat" in content:
                            return "Red Hat Enterprise Linux", '.'.join(major_minor_version)
            except FileNotFoundError:
                continue

        # Parse /etc/os-release as fallback
        try:
            with open("/etc/os-release", "r") as f:
                distro_info = {}
                for line in f:
                    key, _, value = line.partition("=")
                    distro_info[key.strip()] = value.strip().strip('"')
                distro_name = distro_info.get("NAME", "Unknown")
                distro_version = distro_info.get("VERSION_ID", "Unknown")
                # Ensure the return format is the same
                return distro_name, distro_version
        except FileNotFoundError:
            pass

        # Use uname as a last resort
        try:
            uname_result = subprocess.run(
                ["uname", "-r"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            if uname_result.returncode == 0:
                return "Linux Kernel", uname_result.stdout.strip()
        except Exception:
            pass

        # If all else fails
        return "Unknown Linux Distribution", "Unknown"

    except Exception as e:
        return f"Error determining Linux distribution: {e}"


# Check if the PSMP version is supported for the given Linux distribution and version

def is_supported(psmp_versions, psmp_version, distro_name, distro_version):
    # Sort the versions to find the nearest fallback
    sorted_versions = sorted(psmp_versions.keys(), key=lambda v: tuple(map(int, v.split('.'))))
    
    # Find the closest previous version
    fallback_version = None
    for version in sorted_versions:
        if tuple(map(int, version.split('.'))) <= tuple(map(int, psmp_version.split('.'))):
            fallback_version = version
        else:
            break

    # If no fallback is found, return False
    if fallback_version is None:
        return False
    
    # Check the distribution and version support
    for distro_info in psmp_versions[fallback_version]['supported_distributions']:
        if distro_info['name'].lower() == distro_name.lower():
            for supported_version in distro_info.get('versions', []):
                if distro_version.startswith(supported_version):
                    return True

    return False

# Check if PSMP is in integrated mode

def is_integrated(psmp_version):
    try:

        # Check if the PSMP version is 13.2 or higher (Last availableversion for non-integrated.)
        if float(psmp_version) > 13.2:
            return True

        result = subprocess.run(['rpm', '-qa'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        installed_packages = result.stdout.splitlines()

        # Search for the required packages in the installed RPMs
        psmp_infra_installed = any(package.startswith("CARKpsmp-infra") for package in installed_packages)

        if psmp_infra_installed:
            return True

        return False

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to retrieve RPM packages: {e}")
        return False


# Check the status of PSMP and SSHD services

def check_services_status():
    logging.info("\nServices Availability Check:")
    sleep(2)

    service_statuses = {}
    # Check PSMP service status
    try:
        result_psmpsrv = subprocess.check_output("systemctl status psmpsrv", shell=True, universal_newlines=True)
        if "Active: active" in result_psmpsrv:
            with open("/var/opt/CARKpsmp/logs/PSMPConsole.log", "r") as log_file:
                log_content = log_file.read()
                if "is up and working with Vault" and not "Sockets server is down" in log_content:
                    service_statuses["psmpsrv"] = "Running and communicating with Vault"
                else:
                    service_statuses["psmpsrv"] = "[-] Running but not communicating with Vault"
        elif "Active: inactive" in result_psmpsrv:
            service_statuses["psmpsrv"] = "[-] Inactive"
        else:
            service_statuses["psmpsrv"] = "[-] Inactive"
    except subprocess.CalledProcessError:
        service_statuses["psmpsrv"] = "[-] Inactive"

    # Check SSHD service status
    try:
        result_sshd = subprocess.check_output("systemctl status sshd", shell=True, universal_newlines=True)
        if "Active: active" in result_sshd:
            service_statuses["sshd"] = "Running"
        elif "Active: inactive" in result_sshd:
            service_statuses["sshd"] = "[-] Inactive"
        else:
            service_statuses["sshd"] = "[-] Inactive"
    except subprocess.CalledProcessError:
        service_statuses["sshd"] = "[-] Inactive"
    
    return service_statuses


# Function to check if 'nc' is installed
def is_nc_installed():
    try:
        subprocess.run(["nc", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

# Check the communication between PSMP and Vault server

def check_vault_comm(service_status):
    if service_status["psmpsrv"] == "[-] Inactive" or service_status["psmpsrv"] == "[-] Running but not communicating with Vault":
        logging.info("[-] The PSMP service is inactive.")
        # Communication check with vault server
        if not is_nc_installed():
            logging.info("[!] Netcat (nc) is not installed. Please install it to proceed with the communication check.")
            sys.exit(1)

        # Fetch the vault address from the /opt/CARKpsmp/vault.ini file
        vault_address = ""
        try:
            with open("/etc/opt/CARKpsmp/vault/vault.ini", "r") as file:
                for line in file:
                    if line.startswith("ADDRESS="):
                        vault_address = line.split("=")[1].strip()
                        break
        except FileNotFoundError:
            logging.info("[-] Vault.ini file not found.")
            sys.exit(1)

        # Check if the vault_address is empty
        if len(vault_address) == 0:
            logging.info("[-] Vault address is empty.")
            sys.exit(1)

        # If multiple IP addresses are found, select the first one
        vault_addresses = vault_address.split(",")
        vault_ip = vault_addresses[0].strip()

        # Ask client for confirmation on the fetched Vault IP address
        print(f"Fetched Vault IP: {vault_ip}")
        client_confirmation = input(f"Does the fetched Vault IP is correct: {vault_ip}? (y/n): ")
        if client_confirmation.lower() != "y" and client_confirmation.lower() != "yes":
            logging.info("Wrong Vault IP address, Kindly edit the address under '/etc/opt/CARKpsmp/vault/vault.ini'.")
            sys.exit(1)

        # Perform the communication check to the Vault IP
        logging.info("Checking communication to the vault...")
        sleep(2)
        try:
            subprocess.run(["nc", "-zv", vault_ip, "1858"], check=True)
            logging.info("[+] Communication to the vault is successful.")

            restart_confirmation = input("Restart PSMP service? (y/n): ")
            if restart_confirmation.lower() == "y" or restart_confirmation.lower() == "yes":
                logging.info("[+] Restarting PSMP service...")
                try:
                    subprocess.run(["systemctl", "restart", "psmpsrv"], check=True, timeout=30)
                    service_status = check_services_status()
                    if service_status["psmpsrv"] == "[-] Inactive" or service_status["psmpsrv"] == "[-] Running but not communicating with Vault":
                        logging.info("[-] PSMP service issue.")
                    else:
                        return True
                except subprocess.CalledProcessError as e:
                    logging.info(f"Unable to restart service: {e}")
                    sys.exit(1)
        except subprocess.CalledProcessError as e:
            logging.info(f"Communication to the vault failed: {e}")
            sys.exit(1)

# OpenSSH version check regarding the PSMP compatibility

def get_openssh_version():
    try:
        # Get the version of OpenSSH installed
        ssh_version_output = subprocess.check_output(["ssh", "-V"], stderr=subprocess.STDOUT, universal_newlines=True)
        ssh_version_match = re.search(r"OpenSSH_(\d+\.\d+)", ssh_version_output)
        if ssh_version_match:
            ssh_version = float(ssh_version_match.group(1))
            return ssh_version
        else:
            return None
    except subprocess.CalledProcessError as e:
        return None

# Check OpenSSH version for PSMP compatibility

def check_openssh_version():
    try:
        # Get the version of OpenSSH installed
        ssh_version = get_openssh_version()
        if ssh_version is not None:
            sleep(2)
            if ssh_version >= 7.7:
                return True, "", ssh_version
            else:
                return False, f"[!] OpenSSH version is: {ssh_version}, required version 7.7 and above.", ssh_version
        else:
            return False, "Failed to determine OpenSSH version.", None
    except subprocess.CalledProcessError as e:
        return False, f"Error: {e}", None

# Backup a file by making .bak copy

def backup_file(file_path):
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' does not exist.")
        return False
    log_filename = datetime.now().strftime("PSMPAssistant-%m-%d-%y-%H:%M.bak")
    backup_path = file_path + "_" + log_filename
    
    try:
        shutil.copy2(file_path, backup_path)
        print(f"Backup created: '{backup_path}'")
        return True
    except Exception as e:
        print(f"An error occurred while creating the backup: {e}")


# Restore the sshd_config file from a backup and rename the current one
def restore_sshd_config_from_backup():
    # Path to the backup sshd_config file
    backup_file_path = "/opt/CARKpsmp/backup/sshd_config_backup"
    current_sshd_config_path = "/etc/ssh/sshd_config"
    
    try:
        # Ask for confirmation from the user
        confirmation = input("Do you want to restore sshd_config from backup? (y/n): ")
        if confirmation.lower() != "y" and confirmation.lower() != "yes":
            logging.info("Restoration aborted.")
            return
        if backup_file(current_sshd_config_path):
            # Move the backup insted of the curent sshd
            subprocess.run(["cp", "-i", backup_file_path, current_sshd_config_path])
            logging.info("Successfully restored sshd_config from backup.")

    except FileNotFoundError:
        logging.error("Backup file not found.")
    except Exception as e:
        logging.error(f"Error: {e}")
        
# Check the sshd_config file for misconfigurations

def check_sshd_config():
    global REPAIR_REQUIRED
    logging.info("\nSSHD Configuration Check:")
    sleep(2)
    intergated_psmp = is_integrated(psmp_version)
    sshd_config_path = "/etc/ssh/sshd_config"
    found_psmp_auth_block = False  # PSMP Authentication Configuration Block Start
    found_allow_user = False  # AllowUser should not be present
    found_pubkey_accepted_algorithms = False  # PubkeyAcceptedAlgorithms
    permit_empty_pass = False  # PermitEmptyPasswords yes
    pubkey_auth = False # PubkeyAuthentication yes  
    try:
        with open(sshd_config_path, "r") as file:
            for line in file:
                # Check if the file is managed by a configuration tool
                if "Ansible managed" in line.strip() or "Puppet managed" in line.strip() or "Chef managed" in line.strip():
                    logging.info(f"[!] The sshd_config is managed by a configuration tool: {line.strip()}\n     Make sure to update the latest version if change where made.\n")
                # Check for PSMP Authentication Configuration Block Start
                if line.strip() == "# PSMP Authentication Configuration Block Start":
                    found_psmp_auth_block = True
                # Check for AllowUser line
                if line.strip().startswith("AllowUser"):
                    found_allow_user = True
                # Check if the line contains PubkeyAcceptedAlgorithms and is uncommented
                if "PubkeyAcceptedAlgorithms" in line and not line.strip().startswith("#"):
                    found_pubkey_accepted_algorithms = True
                if "PermitEmptyPasswords yes" in line and not line.strip().startswith("#"):
                    permit_empty_pass = True
                if "PubkeyAuthentication yes" in line and not line.strip().startswith("#"):
                    pubkey_auth = True
    except FileNotFoundError:
        logging.info("sshd_config file not found.")
        sleep(2)
        return

    if not found_psmp_auth_block and intergated_psmp:
        logging.info("[-] PSMP authentication block not found.")
        REPAIR_REQUIRED = True
    if not permit_empty_pass and not intergated_psmp:
        logging.info("[!] PermitEmptyPasswords missing.")
        REPAIR_REQUIRED = True
    if found_allow_user:
        logging.info("[!] AllowUser mentioned in sshd_config and should not be present.")
    if not pubkey_auth:
        logging.info("[!] PubkeyAuthentication is not enabled.")
    if not found_pubkey_accepted_algorithms:
        logging.info("[!] MFA Caching using RSA disabled, required 'PubkeyAcceptedAlgorithms +ssh-rsa' in sshd_config.")
    

    # If misconfigurations found, repair is required.
    if not REPAIR_REQUIRED: 
        logging.info("[+] No misconfiguration found related to sshd_config.")
    else:
        logging.info("[-] SSHD misconfiguration found.")
        sleep(2) 

# Collect PSMP machine logs and creating a zip file

def truncate_logs(file_path, max_lines=1500):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            if len(lines) > max_lines:
                lines = lines[-max_lines:]  # Keep only the last 'max_lines' lines
            return ''.join(lines)
    except Exception as e:
        logging.error(f"Error truncating {file_path}: {e}")
        return None

def load_config(file_name):
    with open(file_name, "r") as file:
        return json.load(file)

def logs_collect():
    logging.info("PSMP Logs Collection:")

    # Check sshd_config file elevated debug level
    delete_file(log_filename)
    if not check_debug_level():
        sys.exit(1)
    sleep(2)

    # Load configuration from JSON
    config = load_config("src/logs_config.json")

    # Get the directory of the currently running script
    script_directory = os.path.dirname(os.path.abspath(__file__))

    # Define the pattern to match log files in the script's directory
    log_file_pattern = os.path.join(script_directory, "PSMPAssistant-*.log")

    # Use glob to find all files matching the pattern
    log_files_to_collect = glob.glob(log_file_pattern)

    # Combine JSON-defined log folders with dynamically found log files
    log_folders = config["log_folders"] + log_files_to_collect

    # List of commands whose output we want to capture
    commands = config["commands"]

    print("\nThe logs will be collected from the following folders:\n")
    for folder in log_folders:
        if "PSMPAssistant-" not in folder:
            print(folder)
    print("\nAs long as command output from these commands:")
    for command in commands:
        print(command)
    print("\nDocs Link https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PAS%20INST/The-PSMP-Environment.htm")
    print("Do you wish to continue? (y/n): ")
    choice = input().lower()
    if choice.lower() != 'y' and choice.lower() != "yes":
        print("Logs collection aborted.")
        return

    # Create the PSMPAssistant-Logs directory for storing the collected logs
    psmp_logs_directory = os.path.join(script_directory, "PSMPAssistant-Logs")
    os.makedirs(psmp_logs_directory, exist_ok=True)

    # Create directories for the different categories inside the PSMPAssistant-Logs directory
    os.makedirs(os.path.join(psmp_logs_directory, "OS"), exist_ok=True)
    os.makedirs(os.path.join(psmp_logs_directory, "PAM.d"), exist_ok=True)
    os.makedirs(os.path.join(psmp_logs_directory, "PSMP"), exist_ok=True)
    os.makedirs(os.path.join(psmp_logs_directory, "PSMP/Installation"), exist_ok=True)
    os.makedirs(os.path.join(psmp_logs_directory, "PSMP/Conf"), exist_ok=True)
    os.makedirs(os.path.join(psmp_logs_directory, "PSMP/Temp"), exist_ok=True)
    
    # Create a directory to store command outputs
    os.makedirs(os.path.join(psmp_logs_directory, "command_output"), exist_ok=True)

    try:
        # Collect logs and copy to respective directories
        for folder in log_folders:
            if os.path.exists(folder):
                if os.path.isdir(folder):
                    # Copy entire directories inside respective categories
                    if "secure" in folder or "messages" in folder or "sshd_config" in folder or "ssh_config" in folder or "nsswitch.conf" in folder:
                        # Truncate and copy the last 1500 lines of secure and messages logs
                        if folder == "/var/log/secure" or folder == "/var/log/messages":
                            truncated_content = truncate_logs(folder)
                            if truncated_content:
                                truncated_file_path = os.path.join(psmp_logs_directory, "OS", os.path.basename(folder))
                                with open(truncated_file_path, 'w') as f:
                                    f.write(truncated_content)
                        else:
                            shutil.copytree(folder, os.path.join(psmp_logs_directory, "OS", os.path.basename(folder)))
                    elif "sshd" in folder or "password-auth" in folder or "system-auth" in folder:
                        shutil.copytree(folder, os.path.join(psmp_logs_directory, "PAM.d", os.path.basename(folder)))
                    elif "CARKpsmp/logs" in folder:
                        shutil.copytree(folder, os.path.join(psmp_logs_directory, "PSMP", os.path.basename(folder)))
                    elif "psmp_install.log" in folder or "EnvManager.log" in folder:
                        shutil.copy(folder, os.path.join(psmp_logs_directory, "PSMP/Installation", os.path.basename(folder)))
                else:
                    # Copy individual files into respective categories
                    if "secure" in folder or "messages" in folder or "sshd_config" in folder or "ssh_config" in folder or "nsswitch.conf" in folder:
                        # Truncate and copy the last 1500 lines of secure and messages logs
                        if folder == "/var/log/secure" or folder == "/var/log/messages":
                            truncated_content = truncate_logs(folder)
                            if truncated_content:
                                truncated_file_path = os.path.join(psmp_logs_directory, "OS", os.path.basename(folder))
                                with open(truncated_file_path, 'w') as f:
                                    f.write(truncated_content)
                        else:
                            shutil.copy(folder, os.path.join(psmp_logs_directory, "OS"))
                    elif "sshd" in folder or "password-auth" in folder or "system-auth" in folder:
                        shutil.copy(folder, os.path.join(psmp_logs_directory, "PAM.d"))
                    elif "CARKpsmp/logs" in folder:
                        shutil.copy(folder, os.path.join(psmp_logs_directory, "PSMP"))
                    elif "psmp_install.log" in folder or "EnvManager.log" in folder:
                        shutil.copy(folder, os.path.join(psmp_logs_directory, "PSMP/Installation"))
                    elif "basic_psmpserver.conf" in folder or "basic_psmpadbridge.conf" in folder:
                        shutil.copy(folder, os.path.join(psmp_logs_directory, "PSMP/Conf", os.path.basename(folder)))
                    elif "PVConfiguration.xml" in folder or "Policies.xml" in folder:
                        shutil.copy(folder, os.path.join(psmp_logs_directory, "PSMP/Temp", os.path.basename(folder)))

        # Now, collect the PSMPAssistant-*.log files directly into the PSMPAssistant-Logs directory (outside of subdirectories)
        for log_file in log_files_to_collect:
            shutil.copy(log_file, psmp_logs_directory)

        # Capture and save the output of each command
        for command in commands:
            try:
                # Run the command and capture the output
                command_output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                # Define a file path using the command name (sanitized)
                command_filename = command.replace(" ", "_").replace("-", "_").replace("/", "_") + ".txt"
                command_file_path = os.path.join(psmp_logs_directory, "command_output", command_filename)
                # Save the output to the file
                with open(command_file_path, 'w') as f:
                    f.write(command_output)
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to execute command: {command} with error: {e}")

        # Create a zip file with the specified name format
        current_date = datetime.now().strftime("-%m-%d-%y-%H:%M")
        zip_filename = f"PSMPAssistant_Logs_{current_date}.zip"
        with zipfile.ZipFile(zip_filename, "w") as zipf:
            # Walk through the directory and add files to the zip with the appropriate paths
            for root, dirs, files in os.walk(psmp_logs_directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, psmp_logs_directory))

        print(f"Logs copied and zip file created: {zip_filename}")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Clean up the PSMPAssistant-Logs directory (optional)
        shutil.rmtree(psmp_logs_directory, ignore_errors=True)

        
# Debug level verification on sshd_config and TraceLevel on PSMPTrace
def check_debug_level():
    ssh_config_path = "/etc/ssh/sshd_config"
    psmp_log_path = "/var/opt/CARKpsmp/logs/PSMPTrace.log"
    changes_made = False
    desired_log_level = "DEBUG3"

    # Read the sshd_config file
    with open(ssh_config_path, 'r') as file:
        lines = file.readlines()

    for _, line in enumerate(lines):
        stripped_line = line.strip()

        # Check if LogLevel is commented out and appears exactly once
        if stripped_line.startswith("#") and stripped_line.count("LogLevel") == 1:
            print("[!] LogLevel should be uncommented; required DEBUG3.")
            sleep(2)
            sys.exit(1)

        # Check if LogLevel is uncommented and valid
        if stripped_line.startswith("LogLevel "):
            if stripped_line == f"LogLevel {desired_log_level}":
                print("[+] Correct SSHD LogLevel found in sshd_config")
            elif stripped_line == "LogLevel INFO":
                    print("[!] LogLevel found as INFO; required DEBUG3.")
                    sys.exit(1)

    # Check for the TraceLevels update message in PSMPTrace.log
    trace_message = "PSMPPS170I Configuration parameter [TraceLevels] updated [value: 1,2,3,4,5,6,7]"
    trace_found = False

    try:
        with open(psmp_log_path, 'r') as file:
            for line in file:
                if trace_message in line:
                    trace_found = True
                    print("[+] Correct TraceLevels found in PSMPTrace.log.")
                    break
        if not trace_found:
            # Note for the user
            print("\nVerify TraceLevel in the PVWA:")
            print("1. Go to Administration → Options → Privileged Session Management → General Settings.")
            print("2. Under Server Settings set TraceLevels=1,2,3,4,5,6,7")
            print("3. Under Connection Client Settings set TraceLevels=1,2")
            print("* Make sure to Save and Restart psmpsrv service.")
    except FileNotFoundError:
        print(f"PSMPTrace.log file not found at {psmp_log_path}.")

    return (not changes_made) and trace_found


# Generate PSMP connection string based on user inputs

def generate_psmp_connection_string():
    print("PSMP Connection String Generator")
    print("Example: [vaultuser]@[targetuser]#[domainaddress]@[targetaddress]#[targetport]@[PSM for SSH address]")
    print("More information: https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet")
    print("Please provide the following details to generate the connection string:\n")
    # Collect inputs from the user
    print("[!] MFA Caching requires FQDN of the Domain-Vault user.\n")
    print("[!] Target user and target FQDN are case sensitive.\n")
    vault_user = input("Enter vault user: ")
    target_user = input("Enter target user: ")
    target_user_domain = input("Enter target user domain address (leave empty if local): ")
    target_address = input("Enter target address: ")
    target_port = input("Enter target port (leave empty if default port 22): ")
    psm_for_ssh_address = input("Enter PSM for SSH address: ")

    # Construct the connection string
    connection_string = f"{vault_user}@{target_user}"
    
    if target_user_domain:
        connection_string += f"#{target_user_domain}"
    
    connection_string += f"@{target_address}"
    
    if target_port and target_port != '22':
        connection_string += f"#{target_port}"
    
    connection_string += f"@{psm_for_ssh_address}"

    return "The connection string is: "+connection_string

# Checking system resources

def check_system_resources():
    logging.info("\nChecking system resources load:")
    sleep(2)

    try:
        # Get CPU Load
        cpu_result = subprocess.run(["cat", "/proc/loadavg"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if cpu_result.returncode == 0:
            load_avg = float(cpu_result.stdout.split()[0])  # 1-minute load average
            # Get the number of CPU cores
            with open("/proc/cpuinfo") as f:
                cores = sum(1 for line in f if line.startswith("processor"))
            if cores > 0:
                load_percentage = ((load_avg / cores) * 100) % 100
                if load_percentage > 100:
                    cpu_info = f"High CPU Load: {load_percentage:.2f}% (Overloaded)"
                else:
                    cpu_info = f"CPU Load within the normal limits."
            else:
                cpu_info = "Unable to determine CPU core count."
        else:
            cpu_info = f"Error retrieving CPU load: {cpu_result.stderr.strip()}"

        # Get Disk Space
        disk_result = subprocess.run(["df", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if disk_result.returncode == 0:
            disk_lines = disk_result.stdout.strip().split("\n")[1:]  # Skip the header line
            high_usage_partitions = []
            for line in disk_lines:
                parts = line.split()
                if len(parts) >= 5:  # Ensure the line has enough parts
                    usage_percent = int(parts[4][:-1])  # Strip the '%' from the 'Use%' value
                    if usage_percent > 85:  # Check if usage is more than 85%
                        high_usage_partitions.append(f"{parts[0]}: {usage_percent}% used (Mounted on {parts[5]})")
            if high_usage_partitions:
                disk_info = "High Disk Usage:\n" + "\n".join(high_usage_partitions)
            else:
                disk_info = "Sufficient disk space."
        else:
            disk_info = f"Error retrieving disk space: {disk_result.stderr.strip()}"

        # Combine Results
        return f"{cpu_info}\n{disk_info}"
    
    except Exception as e:
        return f"Error retrieving system status: {e}"

# Search the secure amd messages log file for known patterns

def search_logs_patterns(distro_name):
    logging.info("\nSearching patterns in the secure logs...")
    sleep(1)

    config = load_config("src/logs_pattern_config.json")
    found_entries = {"secure_logs": [], "psmp_logs": []}  # Ensure correct dictionary keys

    # Determine the security log file based on the OS distribution
    log_file = next((config["log_files"][key] for key in config["log_files"] if distro_name.startswith(key)), None)

    # Compile regex patterns
    failed_regexes = [re.compile(pattern) for pattern in config["failed_attempts_patterns"]]
    psmp_patterns = config["psmp_patterns"]

    # Search in security logs
    if log_file:
        try:
            with open(log_file, 'r', encoding='utf-8') as file:
                for line in file:
                    if any(regex.search(line) for regex in failed_regexes):
                        found_entries["secure_logs"].append(line.strip())
        except FileNotFoundError:
            logging.warning(f"Log file {log_file} not found.")
        except Exception as e:
            logging.error(f"Error reading log file {log_file}: {e}")

    # Search in PSMPTrace logs
    psmp_log_file = config["log_files"].get("PSMPTrace")
    if psmp_log_file:
        try:
            with open(psmp_log_file, 'r', encoding='utf-8') as file:
                for line in reversed(list(file.readlines())):  # Read from bottom to top
                    if any(pattern in line for pattern in psmp_patterns):
                        found_entries["psmp_logs"].append(line.strip())  # Corrected key name
                        break  # Stop after first match
        except FileNotFoundError:
            logging.warning(f"PSMPTrace log file {psmp_log_file} not found.")
        except Exception as e:
            logging.error(f"Error reading PSMPTrace log file {psmp_log_file}: {e}")

    # Print results
    logging.info("\n=== Secure Logs ===")
    logging.info("\n".join(found_entries["secure_logs"]) if found_entries["secure_logs"] else "No matches found.")

    logging.info("\n=== Trace Logs ===")
    logging.info("\n".join(found_entries["psmp_logs"]) if found_entries["psmp_logs"] else "No matches found.")


    

# Verify unique hostname
def hostname_check():
    hostname = socket.gethostname()
    # Check if the hostname includes 'localhost'
    sleep(2)
    if 'localhost' in hostname.lower():
        logging.info(f"\n[!] Hostname: '{hostname}' as default value, Change it to unique hostname to eliminate future issues.")
    return hostname

#SELinux check
def print_latest_selinux_prevention_lines():
    log_file_path = '/var/log/messages'
    search_string = "SELinux is preventing"
    logging.info("\nChecking SELinux...")
    sleep(2)
    try:
        # Run the 'sestatus' command to check SELinux status
        result = subprocess.run(['sestatus'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError:
        logging.info("SELinux is not installed or not available on this system.")
    except FileNotFoundError:
        logging.info("The 'sestatus' command is not found. SELinux may not be installed.")
    try:
        # Use a deque to keep the latest 10 matching lines
        latest_lines = deque(maxlen=2)

        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                # Check if the line contains the search string
                if search_string in line:
                    # Add the line to the deque
                    latest_lines.append(line.strip())
        
        if len(latest_lines) > 0:
            # Print each line in the deque on a new line
            for line in latest_lines:
                # If the line is longer than 200 characters, truncate it to 200 characters
                if len(line) > 200:
                    logging.info(line[:200] + "...")
                else:
                    logging.info(line)
        else:
            logging.info("[+] SElinux is not preventing PSMP components.")
        
        # Check if SELinux is enforcing
        if "SELinux status:                 enabled" in result.stdout and "Current mode:                   enforcing" in result.stdout:
            logging.info("SELinux is in enforcing mode.")

            # Prompt the user for agreement to temporarily disable SELinux
            user_input = input("SELinux is enforcing. Would you like to temporarily disable SELinux for testing purposes until the next reboot? (y/n): ").strip().lower()
            if user_input.lower() == 'y' or user_input.lower() == "yes":
                try:
                    # Disable SELinux temporarily by setting it to permissive
                    logging.info("Disabling SELinux temporarily (setenforce 0)...")
                    subprocess.run(['setenforce', '0'], check=True)
                    logging.info("[!] SELinux has been temporarily disabled. It will revert to enforcing mode after the next reboot.")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to disable SELinux: {e}")
            else:
                logging.info("SELinux will remain in enforcing mode.")


    except FileNotFoundError:
        logging.info(f"Error: The file '{log_file_path}' does not exist.")
    except PermissionError:
        logging.info(f"Error: You do not have permission to access '{log_file_path}'.")


# Disable nscd service (if running, stop and disble)

def disable_nscd_service():
    try:
        # Check if the nscd service is running
        result = subprocess.run(["systemctl", "is-active", "nscd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.stdout.strip() == "active":
            logging.info("\nNSCD service is active and should be diabled\nhttps://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm?tocpath=Installer%7CInstall%20PAM%20-%20Self-Hosted%7CInstall%20PSM%20for%20SSH%7C_____1#DisableNSCD")
            confirmation = input("\nDo you allow to terminate and disable NSCD? (y/n): ")
            if confirmation.lower() == "y" or confirmation.lower() == "yes":
                # Stop and disable the nscd service
                subprocess.run(["systemctl", "stop", "nscd"], check=True)
                subprocess.run(["systemctl", "disable", "nscd"], check=True)
                logging.info("NSCD Stopped and Disabled.")
        else:
            logging.info("NSCD service is not running as expected.")
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e}")

# Veify nsswitch configuration

def verify_nsswitch_conf(psmp_version):

    global REPAIR_REQUIRED
    nsswitch_path = "/etc/nsswitch.conf"
    logging.info("\nConfiguration Check for nsswitch.conf:")
    sleep(2)
    try:
        psmp_version = float(psmp_version)
    except ValueError:
        logging.info("Invalid PSMP version.")
        return False
    
    # Define expected configurations based on PSMP version
    expected_config_v12_2_or_newer = {
        "passwd": "files psmp sss",
        "shadow": "files sss",
        "group": "files psmp sss",
        "initgroups": "files psmp"
    }

    expected_config_older_than_v12_2 = {
        "passwd": "files psmp sss",
        "shadow": "files sss",
        "group": "files psmp sss",
        "initgroups": "files sss" 
    }
    
    # Choose expected config based on version
    if is_integrated(psmp_version) or psmp_version > 13.0:
            logging.info("nsswitch.conf is correctly configured.")
            return False
    if psmp_version >= 12.2:
        expected_config = expected_config_v12_2_or_newer
    else:
        expected_config = expected_config_older_than_v12_2

    # Read the file content
    try:
        with open(nsswitch_path, "r") as f:
            content = f.readlines()
    except FileNotFoundError:
        logging.info(f"{nsswitch_path} not found.")
        return False

    # Parse the file content
    actual_config = {}
    for line in content:
        line = line.strip()
        if line and not line.startswith("#"):  # Ignore empty lines and comments
            key, *value = line.split(":")
            actual_config[key.strip()] = value[0].strip() if value else ""

    # Compare actual config with expected config
    misconfigurations = []
    for key, expected_value in expected_config.items():
        actual_value = actual_config.get(key)
        if actual_value != expected_value:
            misconfigurations.append((key, actual_value, expected_value))

    # If discrepancies are found, prompt for confirmation
    if misconfigurations:
        logging.info("[-] Misconfigurations found in /etc/nsswitch.conf:")
        REPAIR_REQUIRED = True
        for key, actual, expected in misconfigurations:
            logging.info(f" - {key}: found '{actual}', expected '{expected}'")
        return True
    else:
        logging.info("[+] The nsswitch.conf is correctly configured.")
        return False

# Automates RPM repair for the specified PSMP version.

def rpm_repair(psmp_version):
    logging.info(f"\nPSMP documentation for installation steps.\n https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/content/pas%20inst/installing-the-privileged-session-manager-ssh-proxy.htm?tocpath=Installation%7CInstall%20PAM%20-%20Self-Hosted%7CInstall%20PSM%20for%20SSH%7C_____0")
    logging.info("\nPSMP RPM Installation Repair:")
    logging.info(f"PSMP Version Detected: {psmp_version}")
    sleep(2)
    try:
        # Step 1: Manually search for RPM files
        rpm_files = []
        for root, dirs, files in os.walk('/'):
            for file in files:
                if file.startswith('CARK') and file.endswith('.rpm'):
                    file_path = os.path.join(root, file)
                    # Exclude paths containing "/Trash/files/"
                    if '/Trash/files/' not in file_path:
                        rpm_files.append(file_path)

        # Filter RPM files by PSMP version in the file name
        matching_rpms = [rpm for rpm in rpm_files if psmp_version in rpm and "infra" not in rpm]

        if not matching_rpms:
            logging.info(f"No RPM file found matching version {psmp_version}. Please ensure the correct version is installed.")
            return  # No matching RPM found

        
        # If there are multiple matches, select the first one (or apply more logic if needed)
        rpm_location = matching_rpms[0]
        install_folder = os.path.dirname(rpm_location)
        logging.info(f"Installation folder found at: {install_folder}")

        # Validate installation folder
        install_folder_input = input(f"Is the installation folder {install_folder} correct? (y/n): ").strip().lower()
        if install_folder_input.lower() != 'y' and install_folder_input.lower() != "yes":
            logging.info("Installation folder not confirmed by user. Exiting.")
            return
            
        # Step 3: Check and modify vault.ini file
        vault_ini_path = os.path.join(install_folder, "/etc/opt/CARKpsmp/vault/vault.ini") # Fetching the current vault.ini
        if os.path.exists(vault_ini_path):
            with open(vault_ini_path, "r") as f:
                vault_ini_content = f.readlines()

            # Extract the vault IP from the file and confirm with the user
            vault_ip = None
            for line in vault_ini_content:
                if line.startswith("ADDRESS="):
                    vault_ip = line.strip().split("=")[1]
                    break
            vault_ini_path = os.path.join(install_folder, "vault.ini") # Back to the installation folder vault.ini
            if vault_ip:
                logging.info(f"Fetched vault IP: {vault_ip}")
                user_ip = input(f"Is the vault IP {vault_ip} correct? (y/n): ").strip().lower()
                if user_ip.lower() != 'y' and user_ip.lower() != "yes":
                    vault_ip = input("Please enter the vault IP: ").strip()
                    while len(vault_ip) < 5:
                        vault_ip = input("Please enter a valid vault IP: ").strip()
                # Update the vault.ini file
                for i, line in enumerate(vault_ini_content):
                    if line.startswith("ADDRESS="):
                        vault_ini_content[i] = f"ADDRESS={vault_ip}\n"
                        break
                        
                with open(vault_ini_path, "w") as f:
                    f.writelines(vault_ini_content)
                logging.info(f"Updated vault IP to {vault_ip} in vault.ini.")
            else:
                logging.info("No vault IP address found in vault.ini.")
                vault_ip = input("Please enter the vault IP: ").strip()
                while len(vault_ip) < 5:
                    vault_ip = input("Please enter a valid vault IP: ").strip()
                # Update the vault.ini file
                for i, line in enumerate(vault_ini_content):
                    if line.startswith("ADDRESS="):
                        vault_ini_content[i] = f"ADDRESS={vault_ip}\n"
                        break

                with open(vault_ini_path, "w") as f:
                    f.writelines(vault_ini_content)
                logging.info(f"Updated vault IP to {vault_ip} in vault.ini.")
        else:
            logging.info(f"vault.ini not found in {install_folder}")
            sys.exit(1)

        # Step 4: Modify psmpparms.sample file based on user input
        psmpparms_sample_path = os.path.join(install_folder, "psmpparms.sample")
        if os.path.exists(psmpparms_sample_path):
            with open(psmpparms_sample_path, "r") as f:
                psmpparms_content = f.readlines()

            logging.info("Found psmpparms.sample file.")

            for i, line in enumerate(psmpparms_content):
                if line.startswith("InstallationFolder="):
                    psmpparms_content[i] = f"InstallationFolder={install_folder}\n"
                    break
            logging.info(f"Installation folder updated to {install_folder} in psmpparms.")

            # Accept CyberArk EULA
            accept_eula = input("Do you accept the CyberArk EULA? (y/n): ").strip().lower()
            if accept_eula.lower() == 'y' or accept_eula.lower() == "yes":
                for i, line in enumerate(psmpparms_content):
                    if line.startswith("AcceptCyberArkEULA="):
                        psmpparms_content[i] = "AcceptCyberArkEULA=Yes\n"
                        break
                logging.info("CyberArk EULA accepted.")
            else:
                logging.info("CyberArk EULA not accepted.")
                sleep(2)
                sys.exit(1)

            # Update CreateVaultEnvironment and EnableADBridge
            skip_vault_env = input("Do you want to skip Vault environment creation? (y/n): ").strip().lower()
            if skip_vault_env.lower() == 'y' or skip_vault_env.lower() == "yes":
                for i, line in enumerate(psmpparms_content):
                    if line.startswith("#CreateVaultEnvironment="):
                        psmpparms_content[i] = "CreateVaultEnvironment=No\n"
                        break
                logging.info("Vault environment creation set to No.")
            else:
                logging.info("Vault environment creation set to Yes.")

            # Update Integration state
            for i, line in enumerate(psmpparms_content):
                if line.lower().startswith("installcyberarksshd="):
                    if is_integrated(psmp_version):
                        psmpparms_content[i] = "InstallCyberArkSSHD=Integrated\n"
                        logging.info("PSMP set to integrated.")
                    else:
                        psmpparms_content[i] = "InstallCyberArkSSHD=Yes\n"
                        logging.info("PSMP set to non-integrated.")
                    break

            disable_adbridge = input("Do you want to disable ADBridge? (y/n): ").strip().lower()
            if disable_adbridge.lower() == 'y' or disable_adbridge.lower() == "yes":
                for i, line in enumerate(psmpparms_content):
                    if line.startswith("#EnableADBridge="):
                        psmpparms_content[i] = "EnableADBridge=No\n"
                        break
                logging.info("ADBridge disabled.")
            else:
                logging.info("ADBridge set to Yes.")
            sleep(1)

            # Save changes to psmpparms.sample file
            with open("/var/tmp/psmpparms", "w") as f:
                f.writelines(psmpparms_content)
            logging.info("psmpparms file updated and copied to /var/tmp/psmpparms.")

        else:
            logging.info(f"psmpparms.sample not found in {install_folder}")

        # Step 5: Execute CreateCredFile and follow instructions
        create_cred_file_path = os.path.join(install_folder, "CreateCredFile")
        if os.path.exists(create_cred_file_path):
            os.chmod(create_cred_file_path, 0o755)  # Make it executable
            logging.info("\nCreateCredFile executed.\n")
            vaultAdmin = input("Vault Username ==> ")
            vaultPass = getpass.getpass("Vault Password (will be encrypted in secret file) ==> ")
            subprocess.run([create_cred_file_path, "user.cred", "Password", "-Username", vaultAdmin, "-Password", vaultPass, "-EntropyFile"])
            # Copy user.cred and user.cred.entropy to installation folder
            try:
                subprocess.run(["mv", "-f", "user.cred", "user.cred.entropy", install_folder], check=True)
                logging.info("\nuser.cred and user.cred.entropy copied to installation folder.")
            except FileNotFoundError:
                logging.error("\nuser.cred or user.cred.entropy file not found.")
            except Exception as e:
                logging.error(f"Error: {e}")
        else:
            logging.info(f"\nCreateCredFile not found in {install_folder}")

        # Step 6: Repair the RPM
        try:
            if is_integrated(psmp_version) and float(psmp_version) <= 13.2:
                integrated_rpm_dir = os.path.join(install_folder, "IntegratedMode")
                integrated_rpm_files = [
                    os.path.join(integrated_rpm_dir, rpm)
                    for rpm in os.listdir(integrated_rpm_dir)
                    if rpm.endswith(".rpm")
                ]
                
                if not integrated_rpm_files:
                    logging.warning("No IntegratedMode RPM file found.")
                else:
                    integrated_rpm_path = integrated_rpm_files[0]  # Repair the first RPM found
                    logging.info(f"\nRepairing IntegratedMode RPM from: {integrated_rpm_path}")
                    subprocess.run(["rpm", "-Uvh", "--force", integrated_rpm_path])
                    
                    logging.info(f"\n[+] IntegratedMode RPM {integrated_rpm_path} installed successfully.")
            
            # Proceed with the main RPM repair
            rpm_file_path = os.path.join(install_folder, matching_rpms[0])
            logging.info(f"\nRepairing main RPM from: {rpm_file_path}")
            process = subprocess.Popen(["rpm", "-Uvh", "--force", rpm_file_path], stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
            
            succeed = True
            for line in process.stdout:
                print(line.strip())  # Display to the customer
                if "errors" in line:
                    logging.info(f"[-] Main RPM {rpm_file_path} Installation completed with errors.")
                    succeed = False
                    break
            if succeed:
                logging.info(f"\n[+] Main RPM {rpm_file_path} installed successfully.")
        except subprocess.CalledProcessError:
            logging.error("\n[-] Error during RPM file search or installation.")
            confirmation = input("Do you want to see the installation logs? (y/n): ")
            if confirmation.lower() == "y" or confirmation.lower() == "yes":
                try:
                    with open("/var/tmp/psmp_install.log", "r") as f:
                        for line in f:
                            print(line.strip())
                except Exception as e:
                    logging.error(f"Could not read log file: {e}")

    except Exception as e:
        logging.error(f"An error occurred during the RPM repair process: {e}")


# Checking for command-line argument
def command_line_args(psmp_version):
    for arg in sys.argv:
            if arg == "logs":
                logs_collect()
                sys.exit(1)
            elif arg == "restore-sshd":
                restore_sshd_config_from_backup()
                delete_file(log_filename)
                sys.exit(1)
            elif arg == "string":
                logging.info(generate_psmp_connection_string())
                delete_file(log_filename)
                sys.exit(1)
            elif arg == "repair":
                log_filename = datetime.now().strftime("PSMPAssistant-Repair-%m-%d-%y-%H:%M.log")
                rpm_repair(psmp_version)
                sys.exit(1)


# Validating machine configuration

def machine_conf_valid():
    # Check if PSMP installed.
    if not psmp_version:
        logging.info("\n[-] No PSMP version found.")
        logging.info("\n[!] Kindly proceed with PSMP RPM repair by executing: 'python3 PSMPAssistant.py repair'")
        sys.exit(1)
        
    # Get the Linux distribution and version
    logging.info("\nPSMP Compatibility Check:")
    sleep(2)
    distro_name, distro_version = get_linux_distribution()
    # Check compatibility
    if is_supported(psmp_versions, psmp_version, distro_name, distro_version):
        logging.info(f"PSMP Version {psmp_version} Supports {distro_name} {distro_version}")
    else:
        logging.info(f"PSMP Version {psmp_version} Does Not Support {distro_name} {distro_version}")
        # Fixes typo in the version numeric value
        logging.info(f"Please refer to the PSMP documentation for supported versions.\n https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/Content/PAS%20SysReq/System%20Requirements%20-%20PSMP.htm")
        
    # Check if the hostname changed from default value
    hostname_check() 

    # Check OpenSSH version
    success, message, ssh_version = check_openssh_version()
    if not success:
        logging.info("\n"+message)

    # Check nsswitch configuration
    if is_integrated(psmp_version):
        nsswitch_changes=verify_nsswitch_conf(psmp_version)

    # Check system resources load.
    logging.info(check_system_resources())

    # Check SSHD configuration
    check_sshd_config()

    #Check SELinux
    print_latest_selinux_prevention_lines()

    #Check for REPAIR_REQUIRED flag
    if REPAIR_REQUIRED:
        logging.info("\n[!] RPM Repair required, for repair automation execute ' python3 PSMPAssistant.py repair '")
        sleep(2)
        sys.exit(1)

    # Search for failed connection attempts in the secure log
    search_logs_patterns(distro_name)

    # Check service status
    service_status = check_services_status()

    # Check if service status is Inactive
    if check_vault_comm(service_status):
        service_status = check_services_status()
    sleep(2)
    logging.info(f"PSMP Service Status: {service_status.get('psmpsrv', 'Unavailable')}")
    logging.info(f"SSHD Service Status: {service_status.get('sshd', 'Unavailable')}")
    
    # NSCD service check and disable. 
    disable_nscd_service()

     # Offer the customer to repair the PSMP Installation RPM
    if service_status.get('psmpsrv', 'Unavailable') != "Running and communicating with Vault":
        if not nsswitch_changes:
            logging.info("\n[!] Recommended to proceed with a RPM installation repair, for repair automation execute ' python3 PSMPAssistant.py repair '")


if __name__ == "__main__":

    # Print the PSMPAssistant logo
    print_logo()

    #Verifing privileged user
    check_privileges()

    # Load PSMP versions from a JSON file
    psmp_versions = load_psmp_versions_json('src/versions.json')

    # Get the installed PSMP version
    psmp_version = get_installed_psmp_version()

    # Check if the command-line argument is 'logs', 'string', 'restore-sshd' or 'repair'.
    command_line_args(psmp_version)

    # Running main configuration validnation on the machine
    machine_conf_valid()
