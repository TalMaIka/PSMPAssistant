import json
import subprocess
import distro
import re

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


def check_service_status():
    try:
        # Run the systemctl status command for the specified service
        result_systemctl = subprocess.check_output("systemctl status psmpsrv", shell=True, universal_newlines=True)
        # Check the output for the service status
        if "Active: active" in result_systemctl:
            # Check if PSMP service is up and working with Vault in PSMPConsole.log
            with open("/var/opt/CARKpsmp/logs/PSMPConsole.log", "r") as log_file:
                log_content = log_file.read()
                if "is up and working with Vault" in log_content:
                    return "Running and communicating with Vault"
                else:
                    return "Running but not communicating with Vault"
        elif "Active: inactive" in result_systemctl:
            return "Inactive"
        else:
            return "Inactive"
    except subprocess.CalledProcessError:
        return "Inactive"

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

def get_openssl_version():
    try:
        # Get the version of OpenSSL installed
        openssl_version_output = subprocess.check_output(["openssl", "version"], universal_newlines=True)
        openssl_version_match = re.search(r"OpenSSL (\d+\.\d+\.\d+)", openssl_version_output)
        if openssl_version_match:
            openssl_version = openssl_version_match.group(1)
            return openssl_version
        else:
            return None
    except subprocess.CalledProcessError as e:
        return None

def check_openssh_openssl_requirement():
    try:
        # Get the version of OpenSSH installed
        ssh_version = get_openssh_version()
        if ssh_version is not None:
            if ssh_version >= 7.7:
                # Get the version of OpenSSL installed
                openssl_version = get_openssl_version()
                if openssl_version is not None:
                    openssl_major_version = int(openssl_version.split('.')[0])
                    if openssl_major_version >= 1:
                        return True, f"OpenSSH version {ssh_version} requires OpenSSL version {openssl_version} or above.", ssh_version, openssl_version
                    else:
                        return False, f"OpenSSH version {ssh_version} requires OpenSSL version 1.0.1 or above, but the installed version is {openssl_version}.", ssh_version, openssl_version
                else:
                    return False, "Failed to determine OpenSSL version.", ssh_version, None
            else:
                return False, f"OpenSSH version {ssh_version} does not have specific OpenSSL requirements.", ssh_version, None
        else:
            return False, "Failed to determine OpenSSH version.", None, None
    except subprocess.CalledProcessError as e:
        return False, f"Error: {e}", None, None

def check_sshd_config():
    sshd_config_path = "/etc/ssh/sshd_config"  # Modify this path as needed
    found_pmsp_auth_block = False
    found_allow_user = False
    
    try:
        with open(sshd_config_path, "r") as file:
            lines = file.readlines()
            for line in lines:
                # Check for PSMP Authentication Configuration Block Start
                if line.strip() == "# PSMP Authentication Configuration Block Start":
                    found_pmsp_auth_block = True
                # Check for AllowUser line
                if line.strip().startswith("AllowUser"):
                    found_allow_user = True
    except FileNotFoundError:
        print("sshd_config file not found.")
        return
    
    if not found_pmsp_auth_block:
        print("PSMP authentication block not found.")
    if found_allow_user:
        print("AllowUser mentioned found.")


# Load PSMP versions from a JSON file
psmp_versions = load_psmp_versions_json('src/versions.json')

# Get the installed PSMP version
psmp_version = get_installed_psmp_version()
if not psmp_version:
    print("No PSMP version found or PSMP is not installed.")
    exit(1)

# Get the Linux distribution and version
distro_name, distro_version = get_linux_distribution()

print(f"PSMP version: {psmp_version}")
print(f"Linux distribution: {distro_name} {distro_version}")


# Check compatibility
if is_supported(psmp_versions, psmp_version, distro_name, distro_version):
    print(f"PSMP version {psmp_version} Supports {distro_name} {distro_version}")
else:
    print(f"PSMP version {psmp_version} Does Not Support {distro_name} {distro_version}")

print(f"Service status: {check_service_status()}")

success, message, ssh_version, openssl_version = check_openssh_openssl_requirement()
if success:
    print("OpenSSH and OpenSSL versions meets the requirements.")
else:
    print("Requirement not fulfilled:", message)

check_sshd_config()
