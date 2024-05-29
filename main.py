import json
import subprocess
import distro

def load_psmp_versions_from_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def get_installed_psmp_version():
    try:
        result = subprocess.check_output("rpm -qa | grep -I cark", shell=True, universal_newlines=True).strip()
        if result:
            # Extract version number, assuming the result format is "cark-version"
            version = result.split('-')[1]
            return version
    except subprocess.CalledProcessError:
        return None

def get_linux_distribution():
    return distro.name(), distro.version()

def is_supported(psmp_versions, psmp_version, distro_name, distro_version):
    if psmp_version not in psmp_versions:
        return False
    for distro in psmp_versions[psmp_version]['supported_distributions']:
        if distro['name'].lower() == distro_name.lower() and distro_version in distro['versions']:
            return True
    return False

# Load PSMP versions from a JSON file
psmp_versions = load_psmp_versions_from_json('src/versions.json')

# Get the installed PSMP version
psmp_version = get_installed_psmp_version()
if not psmp_version:
    print("No PSMP version found or PSMP is not installed.")
    exit(1)

# Get the Linux distribution and version
distro_name, distro_version = get_linux_distribution()

# Check compatibility
if is_supported(psmp_versions, psmp_version, distro_name, distro_version):
    print(f"PSMP version {psmp_version} supports {distro_name} {distro_version}")
else:
    print(f"PSMP version {psmp_version} does not support {distro_name} {distro_version}")
