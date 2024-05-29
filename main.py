import json
import subprocess
import distro

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
        result = subprocess.run(['systemctl', 'status', "psmppsrv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        # Check the output for the service status
        if "Active: active (running)" in result.stdout:
            return "Running"
        elif "Active: inactive (dead)" in result.stdout:
            return "Inactive"
        else:
            return "Unknown"
    except subprocess.CalledProcessError:
        # If the systemctl command fails, return "Error"
        return "Error"

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