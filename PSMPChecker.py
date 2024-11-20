# Copyright: © 2024 CyberArk Community, Made By Tal.M
# Version: 1.1
# Description: This tool performs a series of checks and operations related to CyberArk's Privileged Session Manager for SSH Proxy (PSMP) and SSHD configuration on Linux systems.

import json
import subprocess
import distro
import re
import os
import shutil
import datetime
import zipfile
import sys
import psutil
import socket
from time import sleep
from collections import deque
import logging
from datetime import datetime
import signal


# Logging to write to the dynamically named file and the console

log_filename = datetime.now().strftime("PSMPChecker-%m-%d-%y-%H:%M.log")
logging.basicConfig(
    level=logging.INFO,  
    format='%(message)s',  
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)

# Define the signal handler
def handle_signal(signal, frame):
    print("\n\nTerminating tool...") 
    delete_file(log_filename)
    sleep(2)  
    sys.exit(0) 

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

# Set up the signal handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, handle_signal)

# PSMPChecker Logo

def print_logo():
    logo = r"""
 _____ _____ _____ _____     _____ _           _           
|  _  |   __|     |  _  |___|     | |_ ___ ___| |_ ___ ___ 
|   __|__   | | | |   __|___|   --|   | -_|  _| '_| -_|  _|
|__|  |_____|_|_|_|__|      |_____|_|_|___|___|_,_|___|_|  
      © 2024 CyberArk Community, Made By Tal.M"""
    logging.info(logo)
    logging.info("\n")


# Load PSMP versions from a JSON file

def load_psmp_versions_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Get the installed PSMP version

def get_installed_psmp_version():
    try:
        result = subprocess.check_output("rpm -qa | grep -i cark", shell=True, universal_newlines=True).strip()
        if result:
            # Extract version number, assuming the result format is "CARKpsmp-14.0.0-14.x86_64"
            version = result.split('-')[1]
            # Extract major and minor version numbers
            major, minor, _ = version.split('.', 2)
            main_version = f"{major}.{minor}"
            return main_version
    except subprocess.CalledProcessError:
        return None

# Get the Linux distribution and version

def get_linux_distribution():
    version_info = distro.version(best=True)
    version_parts = version_info.split('.')
    major = version_parts[0]
    minor = version_parts[1] if len(version_parts) > 1 else '0'
    main_version = f"{major}.{minor}"
    return distro.name(), main_version

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
        # Check if CARKpsmp and CARKpsmp-infra packages are installed
        result = subprocess.run(['rpm', '-qa'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        installed_packages = result.stdout.splitlines()

        # Parse and compare the PSMP version
        try:
            major, minor = map(int, psmp_version.split('.'))
        except ValueError:
            logging.error(f"Invalid PSMP version format: {psmp_version}")
            return False

        # Check if the PSMP version is 13.2 or higher
        if major > 13 or (major == 13 and minor >= 2):
            return True

        # Search for the required packages in the installed RPMs
        psmp_infra_installed = any(package.startswith("CARKpsmp-infra") for package in installed_packages)

        # Return True if the infra package is installed
        if psmp_infra_installed:
            return True

        return False

    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to retrieve RPM packages: {e}")
        return False


# Check the status of PSMP and SSHD services

def check_services_status():
    service_statuses = {}
    # Check PSMP service status
    try:
        result_psmpsrv = subprocess.check_output("systemctl status psmpsrv", shell=True, universal_newlines=True)
        if "Active: active" in result_psmpsrv:
            with open("/var/opt/CARKpsmp/logs/PSMPConsole.log", "r") as log_file:
                log_content = log_file.read()
                if "is up and working with Vault" in log_content:
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
            # Check if 'nc' (Netcat) is installed
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

        # If multiple IP addresses are found, select the first one
        vault_addresses = vault_address.split(",")
        vault_ip = vault_addresses[0].strip()

        # Ask client for confirmation on the fetched Vault IP address
        print(f"Fetched Vault IP: {vault_ip}")
        client_confirmation = input(f"Does the fetched Vault IP is correct: {vault_ip}? (y/n): ")
        if client_confirmation.lower() != "y":
            # Allow the user to change the Vault IP address
            new_vault_ip = input(f"Please enter the new Vault IP address (current: {vault_ip}): ").strip()
            if new_vault_ip:
                vault_ip = new_vault_ip
                # Update the vault.ini with the new address
                try:
                    with open("/etc/opt/CARKpsmp/vault/vault.ini", "r") as file:
                        lines = file.readlines()
                    with open("/etc/opt/CARKpsmp/vault/vault.ini", "w") as file:
                        for line in lines:
                            if line.startswith("ADDRESS="):
                                file.write(f"ADDRESS={vault_ip}\n")
                            else:
                                file.write(line)
                    logging.info(f"Vault IP address updated to {vault_ip} in vault.ini.")
                except FileNotFoundError:
                    logging.info("[-] Vault.ini file not found.")
                    sys.exit(1)
            else:
                logging.info("No new IP entered, proceeding with the existing address.")

        # Perform the communication check to the Vault IP
        logging.info("Checking communication to the vault...")
        sleep(2)
        try:
            subprocess.run(["nc", "-zv", vault_ip, "1858"], check=True)
            logging.info("[+] Communication to the vault is successful.")
            # Optionally restart PSMP service after communication check
            restart_confirmation = input("Restart PSMP service? (y/n): ")
            if restart_confirmation.lower() == "y":
                logging.info("[+] Restarting PSMP service...")
                try:
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

# PAM.d file check for 'nullok' in the line 'auth sufficient pam_unix.so nullok try_first_pass'

def check_pam_d(distro_name):
    if distro_name == "CentOS Linux" or distro_name.startswith("Red Hat"):
        pam_d_path = "/etc/pam.d/password-auth"
    elif distro_name.startswith("SUSE Linux"):
        pam_d_path = "/etc/pam.d/common-auth-pc"
    else:
        return
    
    found_nullok = False

    try:
        with open(pam_d_path, 'r') as file:
            lines = file.readlines()

        for line in lines:
            if line.startswith("auth sufficient pam_unix.so"):
                if "nullok" in line:
                    found_nullok = True
                    break

    except FileNotFoundError:
        logging.info("pam.d file not found.")
        return
    
    if not found_nullok:
        logging.info("\n[-] pam.d file missing 'nullok' in the line 'auth sufficient pam_unix.so nullok try_first_pass'")
    else:
        logging.info("\npam.d is correctly configured.")

# Backup a file by making .bak copy

def backup_file(file_path):
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' does not exist.")
        return False
    log_filename = datetime.now().strftime("PSMPChecker-%m-%d-%y-%H:%M.bak")
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
        if confirmation.lower() != "y":
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
        logging.info("\nSSHD Configuration Check:")
        sleep(2)
        intergated_psmp = is_integrated(psmp_version)
        sshd_config_path = "/etc/ssh/sshd_config"
        found_pmsp_auth_block = False  # PSMP Authentication Configuration Block Start
        found_allow_user = False  # AllowUser should not be present
        found_pubkey_accepted_algorithms = False  # PubkeyAcceptedAlgorithms
        permit_empty_pass = False  # PermitEmptyPasswords yes
        changes_made = False  # Flag to track if any changes were made
        try:
            with open(sshd_config_path, "r") as file:
                for line in file:
                    # Check if the file is managed by a configuration tool
                    if "Ansible managed" in line.strip() or "Puppet managed" in line.strip() or "Chef managed" in line.strip():
                        logging.info(f"[!] The sshd_config is managed by a configuration tool: {line.strip()}\n     Make sure to update the latest version if change where made.\n")
                    # Check for PSMP Authentication Configuration Block Start
                    if line.strip() == "# PSMP Authentication Configuration Block Start":
                        found_pmsp_auth_block = True
                    # Check for AllowUser line
                    if line.strip().startswith("AllowUser"):
                        found_allow_user = True
                    # Check if the line contains PubkeyAcceptedAlgorithms and is uncommented
                    if "PubkeyAcceptedAlgorithms" in line and not line.strip().startswith("#"):
                        found_pubkey_accepted_algorithms = True
                    if "PermitEmptyPasswords yes" in line and not line.strip().startswith("#"):
                        permit_empty_pass = True
        except FileNotFoundError:
            logging.info("sshd_config file not found.")
            return

        if not found_pmsp_auth_block and intergated_psmp:
            logging.info("PSMP authentication block not found.")
            # Ask customer if they want to add the PSMP authentication block
            add_block_confirmation = input("Would you like to add the PSMP authentication block to the sshd_config file? (y/n): ")
            if add_block_confirmation.lower() == "y" and backup_file(sshd_config_path):
                try:
                    with open(sshd_config_path, "a") as file:
                        # Append the PSMP Authentication Configuration Block
                        file.write("\n# PSMP Authentication Configuration Block Start\n")
                        file.write("Match Group PSMConnectUsers\n")
                        file.write("  AuthenticationMethods publickey,keyboard-interactive keyboard-interactive\n")
                        file.write("  AuthorizedKeysCommand /opt/CARKpsmp/bin/psshkeys_runner.sh\n")
                        file.write("  AuthorizedKeysCommandUser root\n")
                        file.write("Match Group All\n")
                        file.write("# PSMP Authentication Configuration Block End\n")
                    logging.info("PSMP authentication block added to sshd_config.")
                    changes_made = True  # Mark that changes were made
                except Exception as e:
                    logging.info(f"Error while appending the authentication block: {e}")
            else:
                logging.info("PSMP authentication block was not added.")
        
        if not permit_empty_pass and not intergated_psmp:
            logging.info("PermitEmptyPasswords missing.")
        if found_allow_user:
            logging.info("AllowUser mentioned found.")
        if not found_pubkey_accepted_algorithms:
            logging.info("[!] SSH-Keys auth not enabled, sshd_config missing 'PubkeyAcceptedAlgorithms'.")
        else:
            logging.info("No misconfiguration found related to sshd_config.")

        # If changes were made, ask the user to restart the sshd service
        if changes_made:
            restart_confirmation = input("Changes were made to the sshd_config. Would you like to restart the sshd service for the changes to take effect? (y/n): ")
            if restart_confirmation.lower() == "y":
                try:
                    subprocess.run(["systemctl", "restart", "sshd"], check=True)
                    logging.info("[+] SSHD service restarted successfully.")
                except subprocess.CalledProcessError as e:
                    logging.info(f"Error while restarting sshd service: {e}")
            else:
                logging.info("Please restart the sshd service manually for the changes to take effect.")

# Collect PSMP machine logs and creating a zip file

def logs_collect():
    logging.info("PSMP Logs Collection:")
    # Check sshd_config file elevated debug level
    if(not check_debug_level()):
        sys.exit(1)
    sleep(2)   

    # Define folders to copy logs from
    log_folders = [
        "/var/log/secure",
        "/var/log/messages",
        "/var/opt/CARKpsmp/logs",
        "/etc/ssh/sshd_config",
        "/etc/pam.d/sshd",
        "/etc/pam.d/password-auth",
        "/etc/pam.d/system-auth",
        "/etc/nsswitch.conf",
        "/var/opt/CARKpsmp/temp/EnvManager.log"
    ]
    print("\nThe logs will be collected from the following folders:\n")
    for folder in log_folders:
        print(folder)
    print("\nDocs Link https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PAS%20INST/The-PSMP-Environment.htm")
    print("\nDo you wish to continue? (y/n)")
    choice = input().lower()
    if choice != 'y':
        print("Logs collection aborted.")
        return
    

    # Create a folder for temporary storage
    temp_folder = "/tmp/psmp_logs"
    os.makedirs(temp_folder, exist_ok=True)

    try:
        for folder in log_folders:
            if os.path.exists(folder):
                if os.path.isdir(folder):
                    shutil.copytree(folder, os.path.join(temp_folder, os.path.basename(folder)))
                else:
                    shutil.copy(folder, temp_folder)
            else:
                print(f"Folder not found: {folder}")

        current_date = datetime.now().strftime("PSMPChecker-%m-%d-%y-%H:%M")

        # Create a zip file with the specified name format
        zip_filename = f"PSMP_Logs_{current_date}.zip"
        with zipfile.ZipFile(zip_filename, "w") as zipf:
            for root, dirs, files in os.walk(temp_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, temp_folder))

        print(f"Logs copied and zip file created: {zip_filename}")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Clean up temporary folder
        shutil.rmtree(temp_folder, ignore_errors=True)


# Debug level verification on sshd_config and TraceLevel on PSMPTrace
def check_debug_level():
    ssh_config_path = "/etc/ssh/sshd_config"
    psmp_log_path = "/var/opt/CARKpsmp/logs/PSMPTrace.log"
    changes_made = False
    desired_log_level = "DEBUG3"

    # Check and update LogLevel in sshd_config only if it's set to INFO
    with open(ssh_config_path, 'r') as file:
        lines = file.readlines()

    for i, line in enumerate(lines):
        if line.strip().startswith("LogLevel "):
            if line.strip() == f"LogLevel {desired_log_level}":
                print("[+] Correct SSHD LogLevel found in sshd_config")
            elif line.strip() == "LogLevel INFO":
                confirmation = input("The LogLevel for 'sshd' is not set to DEBUG3. Would you like to elevate it to DEBUG3? (y/n): ").strip().lower()
                if confirmation == "y" and backup_file(ssh_config_path):
                    lines[i] = f"LogLevel {desired_log_level}\n"
                    changes_made = True
                else:
                    print("LogLevel remains INFO; required DEBUG3.")
                    sys.exit(1)
            break

    # Write back the modified lines to sshd_config if changes were made
    if changes_made:
        with open(ssh_config_path, 'w') as file:
            file.writelines(lines)
        print("LogLevel updated to DEBUG3 in sshd_config.")
        confirmation = input("\nDo you want to restart SSHD for the changes to take effect? \nWill not affect ongoing sessions ! (y/n):")
        if confirmation.lower() == "y":
            try:
                subprocess.run(["systemctl", "restart", "sshd"], check=True)
                print("SSHD service restarted successfully.")
                print("* Kindly reproduce the issue and then collect the logs !.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to restart sshd service: {e}")
        else:
            print("Restart the SSHD service is needed for the changes to take effect.")
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
            print("* Make Sure to Save and Restart psmpsrv service.")
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
    print("[!] MFA Caching requires FQDN of the Vault user.\n")
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

def check_disk_space(threshold_percent=20):
    disk_usage = psutil.disk_usage('/')
    if disk_usage.percent > (100 - threshold_percent):
        return False, f"[-] Low disk space: {disk_usage.percent}% used."
    return True, "Disk space is sufficient."

def check_system_resources(threshold_cpu=80, threshold_memory=80):
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    if cpu_usage > threshold_cpu:
        return False, f"[-] High CPU usage: {cpu_usage}%"
    if memory_usage > threshold_memory:
        return False, f"[-] High Memory usage: {memory_usage}%"
    return True, "System resources are within normal limits."

# Search the secure log file for known patterns

def search_secure_log(distro_name):
    if distro_name == "CentOS Linux" or distro_name.startswith("Red Hat"):
        log_file = "/var/log/secure"
    elif distro_name.startswith("SUSE Linux"):
        log_file = "/var/log/messages"
    else:
        return []
    # Define patterns for failed connection attempts
    failed_patterns = [
        r'Permission denied',
        r'Server refused our key'
        r'Unable to negotiate with \S+ port \d+: no matching key exchange method found. Their offer: .+',
        r'Failed password for+',
        r'Authentication failure',
        r'Failed \S+ from \S+ port \d+ ssh2',
        r'Invalid user \S+ from \S+',
        r'Connection closed by \S+ port \d+ \[preauth\]',
        r'error: PAM: Authentication failure for \S+ from \S+',
    ]
    
    # Compile the patterns into regular expressions
    failed_regexes = [re.compile(pattern) for pattern in failed_patterns]
    
    # Read the log file and search for failed connection attempts
    failed_attempts = []
    with open(log_file, 'r') as file:
        for line in file:
            for regex in failed_regexes:
                if regex.search(line):
                    failed_attempts.append(line.strip())
                    break  # Avoid matching multiple patterns in the same line
    
    return failed_attempts

# Search the PSMPTrace.log file for known patterns

def search_log_for_patterns():
    log_file = '/var/opt/CARKpsmp/logs/PSMPTrace.log'
    found = False

    patterns = [
    "Permission denied",
    "PSMPPS276I Configuring SSH Proxy",
    "Could not chdir to home directory /home/PSMConnect: Permission denied",
    "Failed to add the host to the list of known hosts (/home/PSMShadowUser/.ssh/known_hosts).",
    "ITACM022S Unable to connect to the vault",
    "PSMPAP100E Failed to connect the PSM SSH Proxy to the Vault",
    "PSMPPS037E PSM SSH Proxy has been terminated.",
    "PSMSC023E LoadLocalUserProfile : Failed to load user profile for local user",
    "ITATS108E Authentication failure for User"
    ]

    # Open the log file in read mode ('r')
    with open(log_file, 'r', encoding='utf-8') as file:
        for line in reversed(list(file)):  # Read the file line by line from bottom to top
            for pattern in patterns:
                if pattern in line:
                    logging.info(line.strip())
                    found = True
                    break
            if found:
                break

    if not found:
        logging.info(f"No lines containing any of the patterns found.")

# Verify unique hostname
def hostname_check():
    hostname = socket.gethostname()
    # Check if the hostname includes 'localhost'
    sleep(2)
    if 'localhost' in hostname.lower():
        logging.info(f"\n[!] Hostname: '{hostname}' as default value, Change it to enique hostname to eliminate future issues.")
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
        
        # Print the output of 'sestatus' if SELinux is installed
        logging.info("SELinux Status:")
        logging.info(result.stdout)
        
    except subprocess.CalledProcessError:
        logging.info("SELinux is not installed or not available on this system.")
    except FileNotFoundError:
        logging.info("The 'sestatus' command is not found. SELinux may not be installed.")
    try:
        # Use a deque to keep the latest 10 matching lines
        latest_lines = deque(maxlen=10)

        # Open the log file in read mode
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                # Check if the line contains the search string
                if search_string in line:
                    # Add the line to the deque
                    latest_lines.append(line.strip())
        #No lines found
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
            confirmation = input("\nNSCD service is active, Terminate and disable to eliminate future issues? (y/n): ")
            if confirmation == "y":
                # Stop and disable the nscd service
                subprocess.run(["systemctl", "stop", "nscd"], check=True)
                subprocess.run(["systemctl", "disable", "nscd"], check=True)
                logging.info("NSCD Stopped and Disabled.")
        else:
            logging.info("NSCD service is Not Running as expected.")
    except subprocess.CalledProcessError as e:
        logging.info(f"Error: {e}")

# Veify nsswitch configuration

def verify_nsswitch_conf(psmp_version):

    nsswitch_path = "/etc/nsswitch.conf"
    logging.info("\nnsswitch.conf Configuration Check:")
    sleep(2)
    try:
        psmp_version = float(psmp_version)
    except ValueError:
        logging.info("Invalid PSMP version. Please provide a numeric version.")
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
        "initgroups": "files sss"  # Note that this is commented out in expected file
    }
    
    # Choose expected config based on version
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
    discrepancies = []
    for key, expected_value in expected_config.items():
        actual_value = actual_config.get(key)
        if actual_value != expected_value:
            discrepancies.append((key, actual_value, expected_value))

    # If discrepancies are found, prompt for confirmation
    if discrepancies:
        logging.info("Discrepancies found in /etc/nsswitch.conf:")
        for key, actual, expected in discrepancies:
            logging.info(f" - {key}: found '{actual}', expected '{expected}'")
        
        confirmation = input("Would you like to update /etc/nsswitch.conf to the expected configuration? (y/n): ")
        if confirmation.lower() == "y" and backup_file(nsswitch_path):
            sleep(2)
            # Update the file with the correct configuration
            try:
                with open(nsswitch_path, "w") as f:
                    for line in content:
                        key = line.split(":")[0].strip() if ":" in line else None
                        if key in expected_config:
                            f.write(f"{key}: {expected_config[key]}\n")
                        else:
                            f.write(line)
                logging.info("The nsswitch.conf has been updated.")
                logging.info("\n[!] Machine reboot is mandatory for the nsswitch.conf changes to take effect.")
                sleep(3)
                return True

            except Exception as e:
                logging.info(f"An error occurred while updating the file: {e}")
        else:
            logging.info("No changes made to /etc/nsswitch.conf.")
            return False
    else:
        logging.info("nsswitch.conf is correctly configured.")
        return False

# Automates the repair of the RPM for the specified PSMP version.

import os
import subprocess
import logging

def rpm_repair(psmp_version):
    logging.info(f"PSMP documentation for installation steps.\n https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/content/pas%20inst/installing-the-privileged-session-manager-ssh-proxy.htm?tocpath=Installation%7CInstall%20PAM%20-%20Self-Hosted%7CInstall%20PSM%20for%20SSH%7C_____0")
    logging.info("\nPSMP RPM Installation Repair:")

    # Step 1: Find the installation folder containing the RPM that matches the specified PSMP version
    find_cmd = "find / -type f -name 'CARK*.rpm'"
    
    try:
        logging.info("Searching for the RPM installation folder...")
        # Get all RPM file paths
        rpm_files = subprocess.check_output(find_cmd, shell=True, universal_newlines=True).splitlines()

        # Filter RPM files by PSMP version in the file name
        matching_rpms = [rpm for rpm in rpm_files if psmp_version in rpm]

        if not matching_rpms:
            logging.info(f"No RPM file found matching version {psmp_version}. Please ensure the correct version is installed.")
            return  # No matching RPM found
        
        # If there are multiple matches, select the first one (or apply more logic if needed)
        rpm_location = matching_rpms[0]
        install_folder = os.path.dirname(rpm_location)
        logging.info(f"Installation folder found at: {install_folder}")
        
        # Validate installation folder
        install_folder_input = input(f"Is the installation folder {install_folder} correct? (y/n): ").strip().lower()
        if install_folder_input != 'y':
            logging.info("Installation folder not confirmed by user. Exiting.")
            return

        # Step 2: Check and modify vault.ini file
        vault_ini_path = os.path.join(install_folder, "vault.ini")
        if os.path.exists(vault_ini_path):
            with open(vault_ini_path, "r") as f:
                vault_ini_content = f.readlines()

            # Extract the vault IP from the file and confirm with the user
            vault_ip = None
            for line in vault_ini_content:
                if line.startswith("ADDRESS="):
                    vault_ip = line.strip().split("=")[1]
                    break

            if vault_ip:
                logging.info(f"Found vault IP: {vault_ip}")
                user_ip = input(f"Is the vault IP {vault_ip} correct? (y/n): ").strip().lower()
                if user_ip != 'y':
                    new_ip = input("Please enter the correct vault IP: ").strip()
                    # Update the vault.ini file
                    for i, line in enumerate(vault_ini_content):
                        if line.startswith("ADDRESS="):
                            vault_ini_content[i] = f"ADDRESS={new_ip}\n"
                            break

                    with open(vault_ini_path, "w") as f:
                        f.writelines(vault_ini_content)
                    logging.info(f"Updated vault IP to {new_ip} in vault.ini.")
            else:
                logging.info("No vault IP address found in vault.ini.")
        else:
            logging.info(f"vault.ini not found in {install_folder}")

        # Step 3: Modify psmpparms.sample file based on user input
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
            if accept_eula == 'y':
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
            if skip_vault_env == 'n':
                for i, line in enumerate(psmpparms_content):
                    if line.startswith("#CreateVaultEnvironment="):
                        psmpparms_content[i] = "CreateVaultEnvironment=No\n"
                        break
                logging.info("Vault environment creation set to No.")

            disable_adbridge = input("Do you want to disable ADBridge? (y/n): ").strip().lower()
            if disable_adbridge == 'y':
                for i, line in enumerate(psmpparms_content):
                    if line.startswith("#EnableADBridge="):
                        psmpparms_content[i] = "EnableADBridge=No\n"
                        break
                logging.info("ADBridge disabled.")

            # Save changes to psmpparms.sample file
            with open("/var/tmp/psmpparms", "w") as f:
                f.writelines(psmpparms_content)
            logging.info("psmpparms file updated and copied to /var/tmp/psmpparms.")

        else:
            logging.info(f"psmpparms.sample not found in {install_folder}")

        # Step 4: Execute CreateCredFile and follow instructions
        create_cred_file_path = os.path.join(install_folder, "CreateCredFile")
        if os.path.exists(create_cred_file_path):
            confirmation = input("Do you allow chmod 755 CreateCredFile (y/n):")
            if confirmation == "y":
                os.chmod(create_cred_file_path, 0o755)  # Make it executable
                logging.info("\nCreateCredFile executed. [!] Please choose Yes on the Entropy file.\n")
            subprocess.run([create_cred_file_path, "user.cred"])
            # Copy user.cred and user.cred.entropy to installation folder
            try:
                subprocess.run(["mv", "-f", "user.cred", "user.cred.entropy", install_folder], check=True)
                logging.info("user.cred and user.cred.entropy copied to installation folder.")
            except FileNotFoundError:
                logging.error("user.cred or user.cred.entropy file not found.")
            except Exception as e:
                logging.error(f"Error: {e}")
        else:
            logging.info(f"CreateCredFile not found in {install_folder}")

        # Step 5: Install the RPM
        rpm_file_path = os.path.join(install_folder, matching_rpms[0])
        logging.info(f"Installing RPM from: {rpm_file_path}")
        subprocess.run(["rpm", "-Uvh", "--force", rpm_file_path])
        logging.info(f"RPM {rpm_file_path} installed successfully.")

    except subprocess.CalledProcessError:
        logging.info("Error during RPM file search or installation.")
        confirmation = input("Do you want to see the installation logs? (y/n): ")
        if confirmation.lower() == "y":
            try:
                with open("/var/tmp/psmp_install.log", "r") as f:
                    for line in f:
                        logging.info(line.strip())
            except FileNotFoundError:
                logging.info("Installation log file not found.")
    except Exception as e:
        logging.info(f"An error occurred: {e}")



if __name__ == "__main__":

    # Print the PSMPChecker logo
    print_logo()

    # Load PSMP versions from a JSON file
    psmp_versions = load_psmp_versions_json('src/versions.json')

    # Get the installed PSMP version
    psmp_version = get_installed_psmp_version()
    if not psmp_version:
        logging.info("[-] No PSMP version found.")
        sys.exit(1)

    # Check if the command-line argument is 'logs', 'string' or 'restore-sshd', then execute the function
    for arg in sys.argv:
        if arg == "logs":
            logs_collect()
            delete_file(log_filename)
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
            rpm_repair(psmp_version)
            delete_file(log_filename)
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
        if psmp_version == 12.06:
            psmp_version = 12.6
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
    logging.info("\nChecking system resources load:")
    sleep(2)
    logging.info(check_disk_space()[1])
    logging.info(check_system_resources()[1])

    # Check SSHD configuration
    check_sshd_config()

    #Check SELinux
    print_latest_selinux_prevention_lines()

    # Check PAM configuration
    if float(psmp_version) <= 13.0:
        logging.info("\nPAM Configuration Check:")
        check_pam_d(distro_name)

    # Search for failed connection attempts in the secure log
        logging.info("\nSearching patterns in the secure logs...")
        sleep(2)
        failed_attempts = search_secure_log(distro_name)
        if not failed_attempts:
            logging.info("No lines containing any of the patterns found.")
        else:
            for attempt in failed_attempts:
                logging.info(attempt)

    # Search for patterns in the PSMPTrace.log file
        logging.info("\nSearching patterns in the PSMPTrace.log...")
        sleep(2)
        search_log_for_patterns()

    # Check service status
    logging.info("\nServices Availability Check:")
    sleep(2)
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
            logging.info("\n[!] Recommended to proceed with a RPM installation repair, for repair automation execute 'python3 main.py repair'")
