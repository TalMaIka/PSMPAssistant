import json
import subprocess
import distro
import re
import argparse
import os
import shutil
import datetime
import zipfile
import sys

def load_psmp_versions_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

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

def get_linux_distribution():
    version_info = distro.version(best=True)
    version_parts = version_info.split('.')
    major = version_parts[0]
    minor = version_parts[1] if len(version_parts) > 1 else '0'
    main_version = f"{major}.{minor}"
    return distro.name(), main_version


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
        


def check_sshd_config():
    sshd_config_path = "/etc/ssh/sshd_config"
    found_pmsp_auth_block = False # PSMP Authentication Configuration Block Start
    found_allow_user = False # AllowUser
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
        print("[+] SSH-Key auth not enabled, sshd_config missing 'PubkeyAcceptedAlgorithms'.")

def logs_collect():
    # Define folders to copy logs from
    log_folders = [
        "/var/log/secure",
        "/var/log/messages",
        "/var/opt/CARKpsmp/logs",
        "/var/opt/CARKpsmp/logs/components",
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
        # Copy logs from each folder to the temporary folder
        for folder in log_folders:
            if os.path.exists(folder):
                if os.path.isdir(folder):
                    shutil.copytree(folder, os.path.join(temp_folder, os.path.basename(folder)))
                else:
                    shutil.copy(folder, temp_folder)
            else:
                print(f"Folder not found: {folder}")

        # Get the current date in the format DD.MM.YY
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

def restore_sshd_config_from_backup():
    # Path to the backup sshd_config file
    backup_file_path = "/opt/CARKpsmp/backup/sshd_config_backup"

    try:
        # Print the content of the backup file before changing
        print("Content of backup sshd_config file before restoring:")
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

def check_sshd_debug_level():
    sshd_config_path = "/etc/ssh/sshd_config"
    debug3_found = False
    
    try:
        with open(sshd_config_path, "r") as file:
            lines = file.readlines()
            for line in lines:
                # Check for uncommented line specifying LogLevel DEBUG3
                if line.strip() == "LogLevel DEBUG3":
                    debug3_found = True
    
    except FileNotFoundError:
        print("sshd_config file not found.")
        sys.exit(1)
    
    if not debug3_found:
        print("Debug level needs to be elevated.\nPlease ensure 'LogLevel DEBUG3' is either changed or added to the sshd_config.")
        print("As long as in the PVWA GUI:")
        print("1. Go to Administration → Options → Privileged Session Management → General Settings.")
        print("2. Under Server Settings set TraceLevels=1,2,3,4,5,6,7")
        print("3. Under Connection Client Settings set TraceLevels=1,2")
        print("* Make sure to Save and Restart sshd and psmpsrv Services.")
        sys.exit(1)

def generate_psmp_connection_string():
    print("PSMP Connection String Generator")
    print("Example: [vaultuser]@[targetuser]#[domainaddress]@[targetaddress]#[targetport]@[PSM for SSH address]")
    print("More information: https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet")
    print("Please provide the following details to generate the connection string:\n")
    # Collect inputs from the user
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


if __name__ == "__main__":
    # Check if the command-line argument is 'logs' or 'restore-sshd', then execute the function
    for arg in sys.argv:
        if arg == "logs":
            check_sshd_debug_level()
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
    distro_name, distro_version = get_linux_distribution()
    print(f"PSMP version: {psmp_version}")
    print(f"Linux distribution: {distro_name} {distro_version}")

    # Check PAM configuration
    if float(psmp_version) <= 13.0:
        check_pam_d(distro_name)

    # Check compatibility
    if is_supported(psmp_versions, psmp_version, distro_name, distro_version):
        print(f"PSMP version {psmp_version} Supports {distro_name} {distro_version}")
    else:
        print(f"PSMP version {psmp_version} Does Not Support {distro_name} {distro_version}")
        print(f"Please refer to the PSMP documentation for supported versions.\n https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/Content/PAS%20SysReq/System%20Requirements%20-%20PSMP.htm")

    # Check service status
    service_status = check_services_status()
    print(f"PSMP Service Status: {service_status.get('psmpsrv', 'Unavailable')}")
    print(f"SSHD Service Status: {service_status.get('sshd', 'Unavailable')}")

    success, message, ssh_version = check_openssh_version()
    if not success:
        print(message)

    check_sshd_config()
