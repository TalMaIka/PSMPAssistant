import json
import subprocess
import distro

def load_psmp_versions_from_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def get_installed_psmp_version():
    try:
        # result = subprocess.check_output("rpm -qa | grep -i cark", shell=True, universal_newlines=True).strip()
        result = "CARKpsmp-14.0.0-14.x86_64"
        if result:
            # Extract version number, assuming the result format is "CARKpsmp-version"
            version = result.split('-')[1]  # Take the part after "CARKpsmp-"
            version = ".".join(version.split('.')[:2])  # Take only major and minor version
            return version
    except subprocess.CalledProcessError:
        return None

def get_linux_distribution():
    return distro.name(), distro.version()

def is_supported(psmp_versions, psmp_version, distro_name, distro_version):
    if psmp_version not in psmp_versions:
        return False

    for distro in psmp_versions[psmp_version]['supported_distributions']:
        distro_name_lower = distro['name'].lower()
        distro_version_lower = [v.lower() for v in distro['versions']]
        if distro_name_lower == distro_name.lower() and distro_version.lower() in distro_version_lower:
            return True
    return False

# Load PSMP versions from a JSON file
psmp_versions = load_psmp_versions_from_json('src/versions.json')

# Get the installed PSMP version
psmp_version = get_installed_psmp_version()
print(f"Installed PSMP version: {psmp_version}")
if not psmp_version:
    print("No PSMP version found or PSMP is not installed.")
    exit(1)

# Get the Linux distribution and version
distro_name, distro_version = get_linux_distribution()
print(f"Linux distribution: {distro_name} {distro_version}")

# Check compatibility
if is_supported(psmp_versions, psmp_version, distro_name, distro_version):
    print(f"PSMP version {psmp_version} supports {distro_name} {distro_version}")
else:
    print(f"PSMP version {psmp_version} does not support {distro_name} {distro_version}")
