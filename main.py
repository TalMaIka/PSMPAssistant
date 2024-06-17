# Copyright: Tal.M @ CyberArk Software
# Version: 1.0
# Description: This script performs a series of checks and operations related to CyberArk's Privileged Session Manager for SSH Proxy (PSMP) and SSHD configuration on Linux systems.
# - Validates PSMP version compatibility with the installed Linux distribution.
# - Checks the status of PSMP and SSHD services.
# - Verifies the installed OpenSSH version for PSMP compatibility.
# - Examines and restores SSHD configuration from a backup.
# - Collects relevant logs from system folders for troubleshooting.
# - Generates a PSMP connection string based on user inputs.

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
    if psmp_version not in psmp_versions:
        return False
    for version in psmp_versions:
        if version.startswith(psmp_version):  # Check if PSMP version starts with given major and minor version
            for distro_info in psmp_versions[version]['supported_distributions']:
                if distro_info['name'].lower() == distro_name.lower():
                    # Check if the distro version matches any of the supported versions
                    for supported_version in distro_info.get('versions', []):
                        if distro_version.startswith(supported_version):
                            return True
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
                    service_statuses["psmpsrv"] = "Running but not communicating with Vault"
        elif "Active: inactive" in result_psmpsrv:
            service_statuses["psmpsrv"] = "Inactive"
        else:
            service_statuses["psmpsrv"] = "Inactive"
    except subprocess.CalledProcessError:
        service_statuses["psmpsrv"] = "Inactive"

    # Check SSHD service status
    try:
        result_sshd = subprocess.check_output("systemctl status sshd", shell=True, universal_newlines=True)
        if "Active: active" in result_sshd:
            service_statuses["sshd"] = "Running"
        elif "Active: inactive" in result_sshd:
            service_statuses["sshd"] = "Inactive"
        else:
            service_statuses["sshd"] = "Inactive"
    except subprocess.CalledProcessError:
        service_statuses["sshd"] = "Inactive"
    
    return service_statuses

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
            if ssh_version >= 7.7:
                return True, "", ssh_version
            else:
                return False, f"[+] OpenSSH version is: {ssh_version}, required version 7.7 and above.", ssh_version
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
        print("pam.d file not found.")
        return
    
    if not found_nullok:
        print("pam.d file missing 'nullok' in the line 'auth sufficient pam_unix.so nullok try_first_pass'")

# Restore the sshd_config file from a backup

def restore_sshd_config_from_backup():
    # Path to the backup sshd_config file
    backup_file_path = "/opt/CARKpsmp/backup/sshd_config_backup"

    try:
        # Print the content of the backup file before changing
        print("Content of backup sshd_config file before restoring:")
        sleep(1)
        with open(backup_file_path, "r") as backup_file:
            print(backup_file.read())

        # Ask for confirmation from the user
        confirmation = input("Do you want to restore sshd_config from backup? (y/n): ")
        if confirmation.lower() != "y":
            print("Restoration aborted.")
            return

        # Run the cp command with the -i option to prompt before overwriting
        subprocess.run(["cp", "-i", backup_file_path, "/etc/ssh/sshd_config"])
        
        print("Successfully restored sshd_config from backup.")

    except FileNotFoundError:
        print("Backup file not found.")
    except Exception as e:
        print(f"Error: {e}")

        
# Check the sshd_config file for misconfigurations related to PSMP

def check_sshd_config():
    sshd_config_path = "/etc/ssh/sshd_config"
    found_pmsp_auth_block = False # PSMP Authentication Configuration Block Start
    found_allow_user = False # AllowUser should not be present
    found_pubkey_accepted_algorithms = False # PubkeyAcceptedAlgorithms
    permit_empty_pass = False # PermitEmptyPasswords yes
    
    try:
        with open(sshd_config_path, "r") as file:
            for line in file:
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
        print("sshd_config file not found.")
        return
    
    if not found_pmsp_auth_block:
        print("PSMP authentication block not found.")
    if not permit_empty_pass:
        print("PermitEmptyPasswords missing.")
    if found_allow_user:
        print("AllowUser mentioned found.")
    if not found_pubkey_accepted_algorithms:
        print("[+] SSH-Keys auth not enabled, sshd_config missing 'PubkeyAcceptedAlgorithms'.")
    else:
        print("No misconfiguration found related to sshd_config.")

# Collect PSMP machine logs and creating a zip file

def logs_collect():
    print("PSMP Logs Collection")
    # Check sshd_config file elevated debug level
    if(check_sshd_debug_level()):
        print("sshd_config file has been elevated to debug mode, Please reproduce the issue.")
        # Note for the user
        print("\nVerify debug level in the PVWA GUI:")
        print("1. Go to Administration → Options → Privileged Session Management → General Settings.")
        print("2. Under Server Settings set TraceLevels=1,2,3,4,5,6,7")
        print("3. Under Connection Client Settings set TraceLevels=1,2")
        print("* Make sure to Save and Restart sshd and psmpsrv Services.")
        sys.exit(1)
    sleep(1)   

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
    print("The logs will be collected from the following folders:\n")
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

        current_date = datetime.datetime.now().strftime("%m.%d.%y")

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


# Restore the sshd_config file from a backup

def check_sshd_debug_level():
    config_path = "/etc/ssh/sshd_config"
    changes_made = False
    # Desired lines
    desired_lines = {
        "SyslogFacility": "AUTHPRIV",
        "LogLevel": "DEBUG3"
    }
    
    # Boolean variables to track if lines are found exactly
    syslog_found = False
    loglevel_found = False
    
    # Read current lines from the file
    with open(config_path, 'r') as file:
        lines = file.readlines()
    
    # Check if each desired line is present and has the correct value
    for key, value in desired_lines.items():
        line_found = False
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key} {value}"):
                line_found = True
                break
        if line_found:
            if key == "SyslogFacility":
                syslog_found = True
            elif key == "LogLevel":
                loglevel_found = True
    
    # If any line is not found exactly, prompt user for permission to update
    if not syslog_found or not loglevel_found:
        changes_made = True
        print("The following lines need updating or are missing:")
        for key, value in desired_lines.items():
            if key == "SyslogFacility" and not syslog_found:
                print(f"{key} {value}")
            elif key == "LogLevel" and not loglevel_found:
                print(f"{key} {value}")
        
        permission = input("Do you want to update these lines and restart the service? (y/n): ").strip().lower()
        if permission in ['y', 'yes']:
            # Remove existing lines that start with the key and add correct ones
            updated_lines = []
            for key, value in desired_lines.items():
                updated_lines.append(f"{key} {value}\n")
            
            # Add existing lines that are not to be updated
            for line in lines:
                skip_line = False
                for key, value in desired_lines.items():
                    if line.strip().startswith(f"{key} "):
                        skip_line = True
                        break
                if not skip_line:
                    updated_lines.append(line)
            
            lines = updated_lines
    
    # Write back the modified lines to the file
    with open(config_path, 'w') as file:
        file.writelines(lines)
    
    # Check if both desired lines are present with correct values
    syslog_present = any(line.strip() == "SyslogFacility AUTHPRIV" for line in lines)
    loglevel_present = any(line.strip() == "LogLevel DEBUG3" for line in lines)
    if syslog_present and loglevel_present and changes_made: # Restart the sshd service if both lines are present
        try:
            subprocess.run(["systemctl", "restart", "sshd"], check=True)
            print("sshd service restarted successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to restart sshd service: {e}")
       
    return changes_made

# Generate PSMP connection string based on user inputs

def generate_psmp_connection_string():
    print("PSMP Connection String Generator")
    print("Example: [vaultuser]@[targetuser]#[domainaddress]@[targetaddress]#[targetport]@[PSM for SSH address]")
    print("More information: https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet")
    print("Please provide the following details to generate the connection string:\n")
    # Collect inputs from the user
    print("MFA Caching requires FQDN of the Vault user.")
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

    return "=> "+connection_string

def check_disk_space(threshold_percent=20):
    disk_usage = psutil.disk_usage('/')
    if disk_usage.percent > (100 - threshold_percent):
        return False, f"Low disk space: {disk_usage.percent}% used."
    return True, "Disk space is sufficient."

def check_system_resources(threshold_cpu=80, threshold_memory=80):
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    if cpu_usage > threshold_cpu:
        return False, f"High CPU usage: {cpu_usage}%"
    if memory_usage > threshold_memory:
        return False, f"High Memory usage: {memory_usage}%"
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
        r'Failed password for',
        r'authentication failure',
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
    "ITACM022S Unable to connect to the vault",
    "PSMPPS037E PSM SSH Proxy has been terminated.",
    "PSMSC023E LoadLocalUserProfile : Failed to load user profile for local user",
    "ITATS108E Authentication failure for User"
    ]

    # Open the log file in read mode ('r')
    with open(log_file, 'r', encoding='utf-8') as file:
        for line in reversed(list(file)):  # Read the file line by line from bottom to top
            for pattern in patterns:
                if pattern in line:
                    print(line.strip())
                    found = True
                    break
            if found:
                break

    if not found:
        print(f"No lines containing any of the patterns found.")

# Verify unique hostname

def hostname_check():
    hostname = socket.gethostname()
    # Check if the hostname includes 'localhost'
    if 'localhost' in hostname.lower():
        print(f"[+] Hostname: '{hostname}' as default value, Change it to enique name to eliminate future issues.")
    return hostname

if __name__ == "__main__":
    # Check if the command-line argument is 'logs' or 'restore-sshd', then execute the function
    for arg in sys.argv:
        if arg == "logs":
            logs_collect()
            sys.exit(1)
        elif arg == "restore-sshd":
            restore_sshd_config_from_backup()
            sys.exit(1)
        elif arg == "string":
            print(generate_psmp_connection_string())
            sys.exit(1)

    # Load PSMP versions from a JSON file
    psmp_versions = load_psmp_versions_json('src/versions.json')

    # Get the installed PSMP version
    psmp_version = get_installed_psmp_version()
    if not psmp_version:
        print("[+] No PSMP version found.")
        sys.exit(1)

    # Get the Linux distribution and version
    print("PSMP Compatibility Check:")
    distro_name, distro_version = get_linux_distribution()
    # Check compatibility
    if is_supported(psmp_versions, psmp_version, distro_name, distro_version):
        print(f"PSMP version {psmp_version} Supports {distro_name} {distro_version}")
    else:
        print(f"PSMP version {psmp_version} Does Not Support {distro_name} {distro_version}")
        print(f"Please refer to the PSMP documentation for supported versions.\n https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/Content/PAS%20SysReq/System%20Requirements%20-%20PSMP.htm")
    hostname_check() # Check if the hostname changed from default value


    # Check service status
    service_status = check_services_status()
    print("\nServices Availability Check:")
    print(f"PSMP Service Status: {service_status.get('psmpsrv', 'Unavailable')}")
    print(f"SSHD Service Status: {service_status.get('sshd', 'Unavailable')}")
    # Check OpenSSH version
    success, message, ssh_version = check_openssh_version()
    if not success:
        print(message)

    # Check SSHD configuration
    print("\nSSHD Configuration Check:")
    check_sshd_config()

    # Check PAM configuration
    if float(psmp_version) <= 13.0:
        print("\nPAM Configuration Check:")
        check_pam_d(distro_name)

    #System Resources Check
    print("\nSystem Resources Check:")
    print(check_system_resources()[1])
    print(check_disk_space()[1])

    # Search for failed connection attempts in the secure log
    print("\nSearch for patterns in secure logs:")
    failed_attempts = search_secure_log(distro_name)
    if not failed_attempts:
        print("No lines containing any of the patterns found.")
    else:
        for attempt in failed_attempts:
            print(attempt)
    
    # Search for patterns in the PSMPTrace.log file
    print("\nSearch for patterns in PSMPTrace.log:")
    search_log_for_patterns()
