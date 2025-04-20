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
from datetime import datetime, timedelta
import signal
import glob


# Define the signal handler
def handle_signal(signal, frame):
    print("\n\nTerminating tool...") 
    Utility.delete_file(Utility.log_filename)
    sleep(2)  
    sys.exit(0) 

# Set up the signal handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, handle_signal)

# Logging colors 
WARNING='\033[38;5;214m[!]\033[0m'
ERROR='\033[0;31m[-]\033[0m'
SUCCESS='\033[0;32m[+]\033[0m'


class Utility:

    # Logging to write to the dynamically named file and the console
    log_filename = datetime.now().strftime("PSMPAssistant-%m-%d-%y_%H-%M.log")
    logging.basicConfig(
        level=logging.INFO,  
        format='%(message)s',  
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )

    #Clean log file ANSI escape codes
    @staticmethod
    def clean_log_file(log_file_path):
        # Define ANSI escape code pattern
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        try:
            # Read the log file
            with open(log_file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            # Remove ANSI escape codes
            cleaned_lines = [ansi_escape.sub('', line) for line in lines]

            # Rewrite the cleaned content back to the log file
            with open(log_file_path, 'w', encoding='utf-8') as file:
                file.writelines(cleaned_lines)
        
        except Exception as e:
            return

    # File deletion as argument.
    @staticmethod
    def delete_file(file_path):
        try:
            os.remove(file_path)
        except FileNotFoundError:
            print(f"{WARNING} File '{file_path}' not found.")
        except PermissionError:
            print(f"{WARNING} Permission denied: Unable to delete '{file_path}'.")
        except Exception as e:
            print(f"{ERROR} An error occurred: {e}")

    # Verifing privileged user
    @staticmethod
    def check_privileges():
        if os.geteuid() != 0:
            print(f"{ERROR} PSMPAssistant tool must be run as root!")
            sleep(2)
            sys.exit(1)

    # PSMPAssistant Logo
    @staticmethod
    def print_logo():
        logo = r"""
     ____  ____  __  __ ____   _            _     _              _   
    |  _ \/ ___||  \/  |  _ \ / \   ___ ___(_)___| |_ __ _ _ __ | |_ 
    | |_) \___ \| |\/| | |_) / _ \ / __/ __| / __| __/ _` | '_ \| __|
    |  __/ ___) | |  | |  __/ ___ \\__ \__ \ \__ \ || (_| | | | | |_ 
    |_|   |____/|_|  |_|_| /_/   \_\___/___/_|___/\__\__,_|_| |_|\__|
        © 2025 CyberArk Community, Developed By Tal.M"""
        logging.info(f"{logo}\n\n")

    # Collect PSMP machine logs and creating a zip file
    @staticmethod
    def truncate_logs(file_path, max_lines=3000):
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                if len(lines) > max_lines:
                    lines = lines[-max_lines:]  # Keep only the last 'max_lines' lines
                return ''.join(lines)
        except Exception as e:
            logging.error(f"{ERROR} Error truncating {file_path}: {e}")
            return None

    # Load configuration from a JSON file
    @staticmethod
    def load_config(file_name):
        with open(file_name, "r") as file:
            return json.load(file)
    
    # Check systemd service status
    @staticmethod
    def get_service_status(service_name):
            try:
                result = subprocess.check_output(f"systemctl is-active {service_name}", shell=True, universal_newlines=True).strip()
                return f"{SUCCESS} Running" if result == "active" else f"{ERROR} Inactive"
            except subprocess.CalledProcessError:
                return f"{ERROR} Inactive"
            
    # Read a file and return its content. Defaults to text mode with UTF-8 encoding.
    @staticmethod
    def read_file(file_path, mode="r"):
        try:
            with open(file_path, mode) as file:
                return file.readlines() if "b" not in mode else file.read()
        except FileNotFoundError:
            logging.error(f"{WARNING} File not found: {file_path}")
        except PermissionError:
            logging.error(f"{WARNING} Permission denied: {file_path}")
        except Exception as e:
            logging.error(f"{ERROR} Error reading {file_path}: {e}")
        return None


class SystemConfiguration:

    # Constructor for SystemConfiguration
    def __init__(self):
        self.psmp_version = self.get_installed_psmp_version()
    
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
                            logging.warning(f"{WARNING} Unable to parse version from: {version}")
            
            # Return None if no valid version is found
            return None
        
        except subprocess.CalledProcessError:
            # Log and return None if the command fails
            for arg in sys.argv:
                if arg == "install":
                    return None
        except Exception as e:
            logging.error(f"{ERROR} An error occurred: {e}")
            return None

    # Get the Linux distribution and version
    def get_linux_distribution():
        distro_name = "Unknown"
        version = "Unknown"

        # First, check /etc/os-release to identify the distro
        try:
            with open("/etc/os-release", "r") as f:
                distro_info = dict(
                    line.strip().split("=", 1) for line in f if "=" in line
                )
                os_name = distro_info.get("NAME", "").strip('"')
                os_version = distro_info.get("VERSION_ID", "").strip('"')

                if "CentOS" in os_name:
                    distro_name = "CentOS Linux"
                    file_path = "/etc/centos-release"
                elif "Red Hat" in os_name:
                    distro_name = "Red Hat Enterprise Linux"
                    file_path = "/etc/redhat-release"
                elif "Rocky" in os_name:
                    return os_name, os_version  # Just return directly for Rocky
                else:
                    return os_name, os_version  # Fallback for others

                # If CentOS or RHEL, parse release file for full version
                with open(file_path, "r") as f:
                    content = f.read()
                    match = re.search(r"release\s+([\d\.]+)", content)
                    if match:
                        version = match.group(1)

                return distro_name, version
        except FileNotFoundError:
            pass

        # Last resort: uname
        try:
            uname_version = subprocess.run(
                ["uname", "-r"], capture_output=True, text=True, check=True
            ).stdout.strip()
            return "Linux Kernel", uname_version
        except subprocess.CalledProcessError:
            pass

        return distro_name, version


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
            logging.error(f"{ERROR} Failed to retrieve RPM packages: {e}")
            return False
            
    
    # Check the status of PSMP and SSHD services.
    def check_services_status():
        sleep(2)

        service_statuses = {
            "psmpsrv": Utility.get_service_status("psmpsrv"),
            "sshd": Utility.get_service_status("sshd"),
        }

        # Check PSMP communication with the Vault
        if service_statuses["psmpsrv"] == f"{SUCCESS} Running":
            # Default case, not communicating
            service_statuses["psmpsrv"] = f"{ERROR} Running but not communicating with Vault"
            log_content = Utility.read_file("/var/opt/CARKpsmp/logs/PSMPConsole.log")
            if log_content:
                log_content = "".join(log_content)
                if "is up and working with Vault" in log_content and \
                "Sockets server is down" not in log_content and \
                "PSM SSH Proxy has been terminated" not in log_content:
                    service_statuses["psmpsrv"] = f"{SUCCESS} Running and communicating with Vault"
                else:
                    service_statuses["psmpsrv"] = f"{ERROR} Running but not communicating with Vault"
                    

        return service_statuses


    # Function to check if 'nc' is installed
    def is_nc_installed():
        try:
            subprocess.run(["nc", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def get_vault_address(file_path):
        # Fetch the vault address from the file_name
        vault_address = ""
        try:
            with open(file_path, "r") as file:
                for line in file:
                    if line.startswith("ADDRESS="):
                        vault_address = line.split("=")[1].strip()
                        break
        except FileNotFoundError:
            logging.error(f"{ERROR} Vault.ini file not found.")
            sys.exit(1)

        if not vault_address:
            logging.error(f"{ERROR} Vault address is empty.")
            sys.exit(1)

        return vault_address.split(",")[0].strip()  # Return the first (Primary) address

    # Verify correct vault address
    def verify_vault_address(vault_address,file_path):
        user_ip = input(f"Is the Vault address {vault_address} correct? (y/n): ").strip().lower()
        if user_ip.lower() != 'y' and user_ip.lower() != "yes":
            logging.info(f"{ERROR} Wrong Vault address, Kindly edit the address under '{file_path}'.")
            sys.exit(1)

    # Check the communication between PSMP and Vault server
    def check_vault_comm(service_status):
        vault_ini_path = "/etc/opt/CARKpsmp/vault/vault.ini"
        if service_status["psmpsrv"] == f"{ERROR} Inactive" or service_status["psmpsrv"] == f"{ERROR} Running but not communicating with Vault":
            logging.info(f"{ERROR} The PSMP service is inactive.")
            # Communication check with vault server
            if not SystemConfiguration.is_nc_installed():
                logging.info(f"{WARNING} Netcat (nc) is not installed. Please install it to proceed with the communication check.")
                sys.exit(1)

            # Fetch the vault address from the /opt/CARKpsmp/vault.ini file
            vault_address = SystemConfiguration.get_vault_address(vault_ini_path)
            
            # Ask client for confirmation on the fetched Vault IP address
            print(f"Fetched Vault IP: {vault_address}")
            SystemConfiguration.verify_vault_address(vault_address,vault_ini_path)

            # Perform the communication check to the Vault IP
            logging.info("Checking communication to the vault...")
            sleep(2)
            try:
                subprocess.run(["nc", "-z", vault_address, "1858"], check=True)
                logging.info(f"{SUCCESS} Communication to the vault is successful.")
                sleep(1)
                logging.info(f"{WARNING} Restarting PSMP service...")
                try:
                    subprocess.run(["systemctl", "restart", "psmpsrv"], check=True, timeout=30)
                    service_status = SystemConfiguration.check_services_status()
                    if service_status["psmpsrv"] == "[-] Inactive" or service_status["psmpsrv"] == "[-] Running but not communicating with Vault":
                        logging.info(f"{ERROR} PSMP service issue.")
                    else:
                        return True
                except subprocess.CalledProcessError as e:
                    logging.info(f"{WARNING} Unable to restart service: {e}")
                except subprocess.TimeoutExpired as e:
                    logging.error(f"{WARNING} Timeout reached.")
                    # Read the last line in the PSMPConsole.log
                    try:
                        with open('/var/opt/CARKpsmp/logs/PSMPConsole.log', 'r') as log_file:
                            lines = log_file.readlines()
                            if lines:
                                logging.error(f"{WARNING} {lines[-1].strip()}")
                            else:
                                logging.error(f"{WARNING} Log file is empty.")
                    except Exception as log_err:
                        logging.error(f"{WARNING} Failed to read log file: {log_err}")
            except subprocess.CalledProcessError as e:
                logging.info(f"{ERROR} No communication with the vault.")
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
            ssh_version = SystemConfiguration.get_openssh_version()
            if ssh_version is not None:
                sleep(2)
                if ssh_version >= 7.7:
                    return True, "", ssh_version
                else:
                    return False, f"{WARNING} OpenSSH version is: {ssh_version}, required version 7.7 and above.", ssh_version
            else:
                return False, f"{ERROR} Failed to determine OpenSSH version.", None
        except subprocess.CalledProcessError as e:
            return False, f"Error: {e}", None
        
    # Check the sshd_config file for misconfigurations
    def check_sshd_config(psmp_version,REPAIR_REQUIRED):
        logging.info("\nSSHD Configuration Check:")
        sleep(2)
        integrated_psmp = SystemConfiguration.is_integrated(psmp_version)
        sshd_config_path = "/etc/ssh/sshd_config"
        
        # Flags for issues found in the configuration
        found_psmp_auth_block = False  
        found_allow_user = False  
        found_pubkey_accepted_algorithms = False  
        permit_empty_pass = False  
        pubkey_auth = False  
        
        # Compile the regex patterns for checking
        psmp_auth_pattern = re.compile(r"# PSMP Authentication Configuration Block Start")
        allow_user_pattern = re.compile(r"^\s*AllowUser")
        pubkey_algorithms_pattern = re.compile(r"^\s*PubkeyAcceptedAlgorithms")
        empty_pass_pattern = re.compile(r"^\s*PermitEmptyPasswords\s+yes")
        pubkey_auth_pattern = re.compile(r"^\s*PubkeyAuthentication\s+yes")
        managed_pattern = re.compile(r"(Ansible|Puppet|Chef)\s")

        try:
            with open(sshd_config_path, "r") as file:
                for line in file:
                    # Check if the file is managed by a configuration tool
                    if managed_pattern.search(line):
                        logging.info(f"{WARNING} The sshd_config is managed by a configuration tool: {line.strip()}\n  Make sure to update the latest version if change were made.")

                    # Check for PSMP Authentication Configuration Block Start
                    if psmp_auth_pattern.match(line):
                        found_psmp_auth_block = True

                    # Check for AllowUser line
                    if allow_user_pattern.match(line) and not line.lstrip().startswith("#"):
                        found_allow_user = True

                    # Check for PubkeyAcceptedAlgorithms and ensure it is uncommented
                    if pubkey_algorithms_pattern.search(line) and not line.lstrip().startswith("#"):
                        found_pubkey_accepted_algorithms = True

                    # Check for PermitEmptyPasswords yes and ensure it is uncommented
                    if empty_pass_pattern.match(line) and not line.lstrip().startswith("#"):
                        permit_empty_pass = True

                    # Check for PubkeyAuthentication yes and ensure it is uncommented
                    if pubkey_auth_pattern.match(line) and not line.lstrip().startswith("#"):
                        pubkey_auth = True

                    # Early exit if all checks are complete
                    if (found_psmp_auth_block and found_allow_user and found_pubkey_accepted_algorithms and 
                        permit_empty_pass and pubkey_auth):
                        break

        except FileNotFoundError:
            logging.info("sshd_config file not found.")
            sleep(2)
            return

        # Evaluate if repair is required based on the conditions
        if not found_psmp_auth_block and integrated_psmp:
            logging.info(f"{ERROR} PSMP authentication block not found.")
            REPAIR_REQUIRED = True
        
        if not permit_empty_pass and not integrated_psmp:
            logging.info(f"{WARNING} PermitEmptyPasswords missing.")
            REPAIR_REQUIRED = True

        if found_allow_user:
            logging.info(f"{WARNING} AllowUser mentioned in sshd_config and should not be present.")

        if not pubkey_auth:
            logging.info(f"{WARNING} PubkeyAuthentication is not enabled, which could interfere with MFA caching.")

        if not found_pubkey_accepted_algorithms:
            logging.info(f"{WARNING} RSA is the default MFA-Caching Key encryption type but deprecated by OpenSSH. \nTo use it, add 'PubkeyAcceptedAlgorithms +ssh-rsa' to sshd_config.")

        if not REPAIR_REQUIRED: 
            logging.info(f"{SUCCESS} No misconfiguration found related to sshd_config.")
        else:
            logging.info(f"{ERROR} SSHD misconfiguration found.")

        return REPAIR_REQUIRED

        
    # Debug level verification on sshd_config and TraceLevel on PSMPTrace
    def check_debug_level():
        psmp_confxml_path = "/var/opt/CARKpsmp/temp/PVConfiguration.xml"
        desired_log_level = "DEBUG3"

        # Run `sshd -T` to get the active SSHD configuration
        try:
            result = subprocess.run(["sshd", "-T"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,check=True)
            sshd_config_output = dict(line.split(None, 1) for line in result.stdout.splitlines() if " " in line)
        except (FileNotFoundError, subprocess.CalledProcessError):
            logging.info(f"{ERROR} Failed to retrieve sshd configuration with 'sshd -T'. Ensure OpenSSH is installed and running.")
            return False

        # Validate LogLevel
        log_level = sshd_config_output.get("loglevel", "").upper()
        if not log_level:
            logging.info(f"{ERROR} LogLevel not found in sshd configuration.")
            return False

        if log_level == desired_log_level:
            logging.info(f"{SUCCESS} Correct SSHD LogLevel ({log_level}) found.")
        elif log_level == "INFO":
            logging.info(f"{WARNING} LogLevel found as INFO; required {desired_log_level}.")
            return False
        else:
            logging.info(f"{WARNING} LogLevel is set to {log_level}; recommended {desired_log_level}.")

        # Read PVConfiguration.xml content efficiently
        try:
            with open(psmp_confxml_path, 'r') as file:
                xml_content = file.read()
        except FileNotFoundError:
            logging.info(f"{ERROR} PVConfiguration.xml file not found at {psmp_confxml_path}.")
            return False

        # Use regex to find the required lines
        server_trace_match = re.search(r'<ServerSettings\b[^>]*TraceLevels="1,2,3,4,5,6,7"\s*>', xml_content)
        client_trace_match = re.search(r'<ConnectionClientSettings\b[^>]*TraceLevels="1,2"\s*>', xml_content)

        # Print results
        if server_trace_match:
            logging.info(f"{SUCCESS} Correct ServerSettings TraceLevels found in PVConfiguration.xml.")
        else:
            logging.info(f"{ERROR} Missing or incorrect <ServerSettings ... TraceLevels=\"1,2,3,4,5,6,7\"> in PVConfiguration.xml.")

        if client_trace_match:
            logging.info(f"{SUCCESS} Correct ConnectionClientSettings TraceLevels found in PVConfiguration.xml.")
        else:
            logging.info(f"{ERROR} Missing or incorrect <ConnectionClientSettings ... TraceLevels=\"1,2\"> in PVConfiguration.xml.")

        # Provide fix instructions if necessary
        if not (server_trace_match and client_trace_match):
            logging.info("\nTo fix this, update the PVWA settings:")
            logging.info("1. Go to Administration → Options → Privileged Session Management → General Settings.")
            logging.info("2. Under Server Settings, set TraceLevels=1,2,3,4,5,6,7")
            logging.info("3. Under Connection Client Settings, set TraceLevels=1,2")
            logging.info("* Make sure to Save and Restart psmpsrv service.")

        return server_trace_match and client_trace_match
    
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
                        cpu_info = f"{WARNING} High CPU Load: {load_percentage:.2f}%"
                    else:
                        cpu_info = f"{SUCCESS} CPU Load within the normal limits."
                else:
                    cpu_info = f"{WARNING} Unable to determine CPU core count."
            else:
                cpu_info = f"{WARNING} Error retrieving CPU load: {cpu_result.stderr.strip()}"

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
                    disk_info = f"{WARNING} High Disk Usage:\n" + "\n".join(high_usage_partitions)
                else:
                    disk_info = f"{SUCCESS} Sufficient disk space."
            else:
                disk_info = f"{WARNING} Error retrieving disk space: {disk_result.stderr.strip()}"

            # Combine Results
            return f"{cpu_info}\n{disk_info}"
        
        except Exception as e:
            return f"{WARNING} Error retrieving system status: {e}"

    # Search the secure amd messages log file for known patterns
    def search_logs_patterns(distro_name):
        logging.info("\nSearching patterns in the secure logs...")
        sleep(1)

        config = Utility.load_config("src/logs_pattern_config.json")
        found_entries = {"secure_logs": deque(maxlen=10), "psmp_logs": deque(maxlen=10)}

        # Determine the security log file based on the OS distribution
        log_file = next((config["log_files"][key] for key in config["log_files"] if distro_name.startswith(key)), None)

        # Compile regex patterns
        secure_logs_patterns = [re.compile(pattern) for pattern in config["secure_logs_patterns"]]
        psmp_trace_patterns = config["psmp_trace_patterns"]

        # Search in security logs
        if log_file:
            try:
                with open(log_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        if any(regex.search(line) for regex in secure_logs_patterns):
                            found_entries["secure_logs"].append(line.strip())
            except FileNotFoundError:
                logging.warning(f"{WARNING} Log file {log_file} not found.")
            except Exception as e:
                logging.error(f"{WARNING} Error reading log file {log_file}: {e}")

        # Search in PSMPTrace logs
        psmp_log_file = config["log_files"].get("PSMPTrace")
        if psmp_log_file:
            try:
                with open(psmp_log_file, 'r', encoding='utf-8') as file:
                    for line in reversed(file.readlines()):  # Read from bottom to top
                        if any(pattern in line for pattern in psmp_trace_patterns):
                            found_entries["psmp_logs"].append(line.strip()) 
            except FileNotFoundError:
                logging.info(f"{WARNING} PSMPTrace log file {psmp_log_file} not found.")
            except Exception as e:
                logging.info(f"{WARNING} Error reading PSMPTrace log file {psmp_log_file}: {e}")

        # Print results
        logging.info("\n=== Secure Log ===")
        logging.info("\n".join(found_entries["secure_logs"]) if found_entries["secure_logs"] else "No matches found.")

        logging.info("\n=== Trace Logs ===")
        logging.info("\n".join(found_entries["psmp_logs"]) if found_entries["psmp_logs"] else "No matches found.")


    # Verify unique hostname
    def hostname_check():
        hostname = socket.gethostname()
        # Check if the hostname includes 'localhost'
        sleep(2)
        if 'localhost' in hostname.lower():
            logging.info(f"\n{WARNING} Hostname: '{hostname}' as default value, Change it to unique hostname to eliminate future issues.")
        return hostname

    #Checks SELinux current status
    def check_selinux():
        logging.info("\nChecking SELinux...")
        sleep(2)
        
        try:
            # Check the current SELinux mode
            mode_result = subprocess.run(["getenforce"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            selinux_mode = mode_result.stdout.strip()
            logging.info(f"Current SELinux mode: {selinux_mode.lower()}")

            # Search for SELinux denials related to PSMP
            result = subprocess.run(
                ["ausearch", "-m", "AVC,USER_AVC", "-ts", "recent", "-f", "CARK"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
            )
            
            if result.stdout.strip():  # If denials exist
                # Filter lines to include only those containing "CARKpsmp"
                filtered_lines = [
                    line for line in result.stdout.splitlines() if "CARKpsmp" in line
                ]

                if filtered_lines:  # If there are relevant denials
                    for line in filtered_lines:
                        logging.info(line)
                    
                    if selinux_mode.lower() == "enforcing":
                        user_input = input("Do you want to temporarily disable SELinux? (y/n): ")
                        if user_input.lower() in ["yes", "y"]:
                            subprocess.run(["setenforce", "0"])
                            logging.info(f"{WARNING} SELinux enforcement disabled temporarily. (setenforce 0)")
                            return True
                        else:
                            logging.info(f"{WARNING} SELinux remains enforced.")
                else:
                    logging.info(f"{SUCCESS} No relevant SELinux denials found for 'CARKpsmp'.")

            else:
                logging.info(f"{SUCCESS} No SELinux denials found for PSMP component.")

        except Exception as e:
            logging.error(f"{SUCCESS} SELinux not installed on the macahine.")

    # SUSE Post-installation steps validation
    def suse_post_installation_steps():
        logging.info("\nVerifying SUSE post-installation steps:")
        try:
            sshd_config_path = '/etc/ssh/sshd_config'
            if os.path.exists(sshd_config_path):
                with open(sshd_config_path, 'r') as file:
                    config_lines = file.readlines()

                permit_empty_passwords_set = False
                for line in config_lines:
                    stripped = line.strip()
                    # Ignore commented or empty lines
                    if stripped.startswith('#') or not stripped:
                        continue
                    if stripped.lower().startswith('permitemptypasswords'):
                        permit_empty_passwords_set = True
                        parts = stripped.split()
                        if len(parts) >= 2 and parts[1].lower() == 'no':
                            logging.info(f"{SUCCESS} PermitEmptyPasswords is correctly set to 'no'.")
                        else:
                            logging.info(f"{ERROR} PermitEmptyPasswords is set incorrectly. Please change it to 'PermitEmptyPasswords no'.")
                        break

                if not permit_empty_passwords_set:
                    logging.info(f"{ERROR} PermitEmptyPasswords is missing in /etc/ssh/sshd_config. Please add 'PermitEmptyPasswords no'.")

            else:
                logging.info(f"{sshd_config_path} not found. Please ensure the file exists and is configured correctly.")

        except Exception as e:
            logging.info(f"An unexpected error occurred: {e}")

    # Restoring SELinux status, if changed.
    def restore_selinux_status():
        user_input = input("\nDo you want to restore SELinux status to enforcing? (y/n): ")
        
        if user_input.lower() in ["yes", "y"]:
            subprocess.run(["setenforce", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info(f"{WARNING} SELinux enforcement restored. (setenforce 1)")
            return True
        else:
            logging.info(f"{WARNING} SELinux remains permissive.")


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
                    logging.info(f"{WARNING} NSCD Stopped and Disabled.")
            else:
                logging.info(f"NSCD Service Status: {SUCCESS} Not running, as expected.")
        except subprocess.CalledProcessError as e:
            logging.info(f"Error: {e}")

    # Verify nsswitch configuration
    def verify_nsswitch_conf(psmp_version):
        nsswitch_path = "/etc/nsswitch.conf"
        logging.info("\nConfiguration Check for nsswitch.conf:")
        sleep(2)

        try:
            psmp_version = float(psmp_version)
        except ValueError:
            logging.info("Invalid PSMP version.")
            return False

        if not SystemConfiguration.is_integrated(psmp_version):
            logging.info(f"{SUCCESS} nsswitch.conf is correctly configured.")
            return False

        required_services = ["passwd", "group"]
        misconfigurations = []

        try:
            with open(nsswitch_path, "r") as f:
                content = f.readlines()
        except FileNotFoundError:
            logging.info(f"{nsswitch_path} not found.")
            return False

        for line in content:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ':' not in line:
                continue

            key, value = map(str.strip, line.split(":", 1))
            if key in required_services:
                methods = value.split()
                if len(methods) < 2 or methods[1] != "psmp":
                    misconfigurations.append((key, value))

        if misconfigurations:
            logging.info(f"{ERROR} Misconfigurations found in /etc/nsswitch.conf:")
            for key, value in misconfigurations:
                logging.info(f" - {key}: expected 'psmp' as the second source, found: '{value}'")
            return True
        else:
            logging.info(f"{SUCCESS} The nsswitch.conf is correctly configured.")
            return False
        
    # Validating machine configuration

    def machine_conf_valid(psmp_versions,psmp_version,REPAIR_REQUIRED):
        # Check if PSMP installed.
        if not psmp_version:
            logging.info(f"\n{ERROR} No PSMP version found.")
            logging.info(f"\n{WARNING} Kindly proceed with PSMP RPM repair by executing: 'python3 PSMPAssistant.py repair'")
            sys.exit(1)
            
        # Get the Linux distribution and version
        logging.info("\nPSMP Compatibility Check:")
        sleep(2)
        distro_name, distro_version = SystemConfiguration.get_linux_distribution()
        # Check compatibility
        if SystemConfiguration.is_supported(psmp_versions, psmp_version, distro_name, distro_version):
            logging.info(f"{SUCCESS} PSMP Version {psmp_version} Supports {distro_name} {distro_version}")
        else:
            logging.info(f"{ERROR} PSMP Version {psmp_version} Does Not Support {distro_name} {distro_version}")
            # Fixes typo in the version numeric value
            logging.info(f"Please refer to the PSMP documentation for supported versions.\n https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/Content/PAS%20SysReq/System%20Requirements%20-%20PSMP.htm")
            
        # Check if the hostname changed from default value
        SystemConfiguration.hostname_check() 

        # Check OpenSSH version
        success, message, ssh_version = SystemConfiguration.check_openssh_version()
        if not success:
            logging.info("\n"+message)

        # Check nsswitch configuration
        if SystemConfiguration.is_integrated(psmp_version):
            nsswitch_changes=SystemConfiguration.verify_nsswitch_conf(psmp_version)

        # Check system resources load.
        logging.info(SystemConfiguration.check_system_resources())

        # Check SSHD configuration
        REPAIR_REQUIRED = SystemConfiguration.check_sshd_config(psmp_version,REPAIR_REQUIRED)

        #Check SELinux
        temp_disable = SystemConfiguration.check_selinux()

        #Certain point to Check for REPAIR_REQUIRED flag
        if REPAIR_REQUIRED or nsswitch_changes:
            logging.info(f"\n{WARNING} RPM Repair required, for repair automation execute ' python3 PSMPAssistant.py repair '")
            sleep(2)
            return
        
        # SUSE Post-installation steps validation
        if distro_name == "SLES":
            SystemConfiguration.suse_post_installation_steps()

        # Search for failed connection attempts in the secure log
        SystemConfiguration.search_logs_patterns(distro_name)

        # Check service status
        logging.info("\nServices Availability Check:")
        service_status = SystemConfiguration.check_services_status()

        # Check if service status is Inactive
        if SystemConfiguration.check_vault_comm(service_status):
            service_status = SystemConfiguration.check_services_status()
        sleep(2)
        logging.info(f"PSMP Service Status: {service_status.get('psmpsrv', 'Unavailable')}")
        logging.info(f"SSHD Service Status: {service_status.get('sshd', 'Unavailable')}")
        
        # NSCD service check and disable. 
        SystemConfiguration.disable_nscd_service()

        # Offer the customer to repair the PSMP Installation RPM
        if service_status.get('psmpsrv', 'Unavailable') != f"{SUCCESS} Running and communicating with Vault" or nsswitch_changes:
                logging.info(f"\n{WARNING} Recommended to proceed with a RPM installation repair, for repair automation execute ' python3 PSMPAssistant.py repair '")

        # Restoring SELinux status, if changed.
        if temp_disable:
            SystemConfiguration.restore_selinux_status()


class RPMAutomation:

    # Verify installation files existing
    def verify_installation_files(install_folder):
        required_files = [
            f"{install_folder}/CreateCredFile",
            "/etc/opt/CARKpsmp/vault/vault.ini",
            f"{install_folder}/psmpparms.sample"
        ]
        
        missing_files = [file for file in required_files if not os.path.exists(file)]

        if missing_files:
            logging.info(f"{WARNING} Missing installation files: %s", ", ".join(missing_files))
            return False

        logging.info(f"{SUCCESS} All required installation files are present.")
        return True
        
    # Imports the revelant RPM key
    def import_gpg_key(installation_folder):
        try:
            key_path = f"{installation_folder}/RPM-GPG-KEY-CyberArk"
            subprocess.run(
                ["rpm", "--import", key_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True
            )
            logging.info(f"{SUCCESS} GPG key imported from: {key_path}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"{ERROR} Failed to import GPG key:\n{e.output}")
            return False

    # Check if the given RPM file is signed and all integrity checks pass.
    def is_rpm_signed(rpm_path):
        try:
            result = subprocess.run(
                ["rpm", "-K", "-v", rpm_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                check=True
            )

            output = result.stdout.strip()
            signature_keywords = [
                "RSA/SHA256 Signature",
                "Header SHA256 digest",
                "Payload SHA256 digest",
                "MD5 digest"
            ]

            has_valid_signature = False

            for line in output.splitlines():
                if any(keyword in line for keyword in signature_keywords):
                    if "OK" not in line:
                        logging.error(f"{ERROR} RPM verification failed:\n{line}")
                        return False
                    if "Signature" in line:
                        has_valid_signature = True

            if not has_valid_signature:
                logging.error(f"{ERROR} Main RPM {rpm_path} is not signed. Exiting.")
                return False

            logging.info(f"{SUCCESS} RPM verification passed for: {rpm_path}")
            return True

        except subprocess.CalledProcessError as e:
            logging.error(f"{ERROR} Error executing rpm -K -v:\n{e.output}")
            return False

    # Automates RPM repair for the specified PSMP version.
    def rpm_repair(psmp_version):
        logging.info(f"\nPSMP documentation for installation steps.\n https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/content/pas%20inst/installing-the-privileged-session-manager-ssh-proxy.htm?tocpath=Installation%7CInstall%20PAM%20-%20Self-Hosted%7CInstall%20PSM%20for%20SSH%7C_____0")
        logging.info("\nPSMP RPM Installation Repair:")
        logging.info(f"PSMP Version Detected: {psmp_version}")
        logging.info("Searching the machine for version matching installation files...")
        sleep(2)
        try:
            # Step 1: Search for RPM files and filter by PSMP version in one loop
            rpm_files = [
                os.path.join(root, file)
                for root, _, files in os.walk('/')
                for file in files if file.startswith('CARK') and file.endswith('.rpm') and '/Trash/files/' not in os.path.join(root, file)
            ]

            # Manual mapping 12.X version to 12.0X
            parts = psmp_version.split('.')
            if len(parts) == 2 and parts[0] == "12" and parts[1].isdigit():
                psmp_version = f"12.0{parts[1]}"

            matching_rpms = [rpm for rpm in rpm_files if psmp_version in rpm and "infra" not in rpm]

            if not matching_rpms:
                logging.info(f"{ERROR} No RPM file found matching version {psmp_version}. Please ensure the correct version is installed.")
                return

            # Step 2: Select first matching RPM and validate installation folder
            rpm_location = matching_rpms[0]
            install_folder = os.path.dirname(rpm_location)
            logging.info(f"Installation folder found at: {install_folder}")

            if input(f"Is the installation folder {install_folder} correct? (y/n): ").strip().lower() not in ['y', 'yes']:
                logging.info("Installation folder not confirmed by user. Exiting.")
                return
            # Verifing existance of all installation files.
            if not RPMAutomation.verify_installation_files(install_folder):
                return

            # Step 3: Fetch and verify vault.ini file
            vault_address = SystemConfiguration.get_vault_address("/etc/opt/CARKpsmp/vault/vault.ini")

            SystemConfiguration.verify_vault_address(vault_address, "/etc/opt/CARKpsmp/vault/vault.ini")

            # Step 4: Modify psmpparms.sample file based on user input
            psmpparms_sample_path = os.path.join(install_folder, "psmpparms.sample")
            if os.path.exists(psmpparms_sample_path):
                logging.info("Found psmpparms.sample file.")
                with open(psmpparms_sample_path, "r") as f:
                    psmpparms_content = f.readlines()

                psmpparms_content = [
                    f"InstallationFolder={install_folder}\n" if line.startswith("InstallationFolder=") else line
                    for line in psmpparms_content
                ]

                logging.info(f"Installation folder updated to {install_folder} in psmpparms.")
                
                # Accept EULA
                if input("Do you accept the CyberArk EULA? (y/n): ").strip().lower() in ['y', 'yes']:
                    psmpparms_content = [
                        "AcceptCyberArkEULA=Yes\n" if line.startswith("AcceptCyberArkEULA=") else line
                        for line in psmpparms_content
                    ]
                    logging.info("CyberArk EULA accepted.")
                else:
                    logging.info("CyberArk EULA not accepted.")
                    sys.exit(1)

                # Update CreateVaultEnvironment and EnableADBridge in one loop
                psmpparms_content = [
                    ("CreateVaultEnvironment=No\n" if input("Do you want to create Vault environment? (y/n): ").strip().lower() in ['n', 'no'] else "CreateVaultEnvironment=Yes\n") 
                    if line.startswith("#CreateVaultEnvironment=") else line
                    for line in psmpparms_content
                ]

                psmpparms_content = [
                    ("EnableADBridge=No\n" if input("Do you want to disable ADBridge? (y/n): ").strip().lower() in ['y', 'yes'] else "EnableADBridge=Yes\n")
                    if line.startswith("#EnableADBridge=") else line
                    for line in psmpparms_content
                ]

                # Save changes to psmpparms.sample file
                with open("/var/tmp/psmpparms", "w") as f:
                    f.writelines(psmpparms_content)
                logging.info("psmpparms file updated and copied to /var/tmp/psmpparms.")

            else:
                logging.info(f"psmpparms.sample not found in {install_folder}")

            # Step 5: Execute CreateCredFile and follow instructions
            create_cred_file_path = os.path.join(install_folder, "CreateCredFile")
            if os.path.exists(create_cred_file_path):
                os.chmod(create_cred_file_path, 0o755)
                logging.info("\nCreateCredFile executed.\n\033[91m[!] Make sure to set Entropy File by entering 'yes'\033[0m")
                sleep(1)
                subprocess.run([create_cred_file_path, "user.cred"])

                try:
                    subprocess.run(["mv", "-f", "user.cred", "user.cred.entropy", install_folder], check=True)
                    logging.info(f"\n{SUCCESS} user.cred and user.cred.entropy copied to installation folder.")
                except Exception as e:
                    logging.error(f"Error moving cred files: {e}")
                    return
            else:
                logging.info(f"\n{ERROR} CreateCredFile not found in {install_folder}")

            # Step 6: Repair RPM
            rpm_file_path = os.path.join(install_folder, matching_rpms[0])
            
            # Importing the GPG Key
            if not RPMAutomation.import_gpg_key(install_folder):
                return

            # Handle IntegratedMode RPM repair in one block
            if SystemConfiguration.is_integrated(psmp_version) and float(psmp_version) <= 13.2:
                integrated_rpm_dir = os.path.join(install_folder, "IntegratedMode")
                integrated_rpm_files = [
                    os.path.join(integrated_rpm_dir, rpm)
                    for rpm in os.listdir(integrated_rpm_dir) if rpm.endswith(".rpm")
                ]

                if integrated_rpm_files and RPMAutomation.is_rpm_signed(integrated_rpm_files[0]):
                    integrated_rpm_path = integrated_rpm_files[0]
                    logging.info(f"\nRepairing IntegratedMode RPM from: {integrated_rpm_path}")
                    subprocess.run(["rpm", "-Uvh", "--force", integrated_rpm_path], )
                else:
                    logging.info(f"{ERROR} IntegratedMode RPM not found or not signed.")
                    return

            # Main RPM repair
            logging.info(f"\nRepairing main RPM from: {rpm_file_path}")
            if not RPMAutomation.is_rpm_signed(rpm_file_path):
                logging.info(f"{ERROR} Main RPM {rpm_file_path} is not signed. Exiting.")
                return
            # Execute the RPM installation command
            process = subprocess.Popen(["rpm", "-Uvh", "--force", rpm_file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            for line in process.stdout:
                logging.info(line.strip())  # Display the output live
                if "completed with errors" in line or "[ERROR]" in line:
                    logging.info(f"{ERROR} Main RPM {rpm_file_path} Installation completed with errors.")
                    break
            else:
                logging.info(f"\n{SUCCESS} Main RPM {rpm_file_path} installed successfully.")

        except Exception as e:
            logging.error(f"An error occurred during the RPM repair process: {e}")


class SideFeatures:

    # Generate PSMP connection string based on user inputs
    def generate_psmp_connection_string():
        print("PSMP Connection String Generator")
        print("Example: [vaultuser]@[targetuser]#[domainaddress]@[targetaddress]#[targetport]@[PSM for SSH address]")
        print("More information: https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet")
        print("Please provide the following details to generate the connection string:\n")
        # Collect inputs from the user
        print(f"{WARNING} MFA Caching requires FQDN of the Domain-Vault user.\n")
        print(f"{WARNING} Target user and target FQDN are case sensitive.\n")
        vault_user = input("Enter vault user: ").strip()
        target_user = input("Enter target user: ").strip()
        target_user_domain = input("Enter target user domain address (leave empty if local): ").strip()
        target_address = input("Enter target address: ").strip()
        target_port = input("Enter target port (leave empty if default port 22): ").strip()
        psm_for_ssh_address = input("Enter PSM for SSH address: ").strip()

        # Construct the connection string
        connection_string = f"{vault_user}@{target_user}"
        
        if target_user_domain:
            connection_string += f"#{target_user_domain}"
        
        connection_string += f"@{target_address}"
        
        if target_port and target_port != '22':
            connection_string += f"#{target_port}"
        
        connection_string += f"@{psm_for_ssh_address}"

        return f"{SUCCESS} The connection string is: "+connection_string
    
    # Log collection function
    def logs_collect(skip_debug):
        logging.info("PSMP Logs Collection:\n")

        if not skip_debug:
            if not SystemConfiguration.check_debug_level():
                return
        sleep(2)
        # Clean the current assistant log file.
        Utility.clean_log_file(Utility.log_filename)
        # Define time threshold (3 days ago)
        three_days_ago = datetime.now() - timedelta(days=3)

        def is_recent_file(file_path):
            """Returns True if the file was modified in the last 3 days."""
            return os.path.isfile(file_path) and (
                datetime.fromtimestamp(os.path.getmtime(file_path)) >= three_days_ago
            )

        config = Utility.load_config("src/logs_config.json")
        log_folders = config["log_folders"]
        log_categories = config["log_categories"]
        commands = config["commands"]

        script_directory = os.path.dirname(os.path.abspath(__file__))
        log_file_pattern = os.path.join(script_directory, "PSMPAssistant-*.log")
        log_files_to_collect = [f for f in glob.glob(log_file_pattern) if is_recent_file(f)]

        logging.info("\nThe following log files will be collected:\n")
        for folder in log_folders:
            logging.info(folder)
        for log_file in log_files_to_collect:
            logging.info(log_file)

        logging.info("\nAs well as the outputs from these commands:")
        for command in commands:
            logging.info(command)

        logging.info("\nDocs Link: https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PAS%20INST/The-PSMP-Environment.htm")
        logging.info("Do you wish to continue? (y/n): ")
        choice = input().lower()
        if choice not in ['y', 'yes']:
            logging.info("Logs collection aborted.")
            return

        psmp_logs_directory = os.path.join(script_directory, "PSMPAssistant-Logs")
        os.makedirs(psmp_logs_directory, exist_ok=True)

        for category in log_categories.keys():
            os.makedirs(os.path.join(psmp_logs_directory, category), exist_ok=True)

        def get_log_category(log_path):
            for category, patterns in log_categories.items():
                if any(pattern in log_path for pattern in patterns):
                    return category
            return None

        try:
            for folder in log_folders:
                if os.path.exists(folder):
                    category = get_log_category(folder)
                    dest_path = os.path.join(psmp_logs_directory, category) if category else psmp_logs_directory
                    os.makedirs(dest_path, exist_ok=True)

                    if folder.startswith("/var/opt/CARKpsmp/logs"):
                        # Apply is_recent_file() only in this folder
                        psmp_dest_path = os.path.join(psmp_logs_directory, "PSMP")
                        os.makedirs(psmp_dest_path, exist_ok=True)

                        for root, _, files in os.walk(folder):
                            relative_root = os.path.relpath(root, folder)
                            dest_subdir = os.path.join(psmp_dest_path, relative_root)
                            os.makedirs(dest_subdir, exist_ok=True)

                            for file in files:
                                src_file = os.path.join(root, file)
                                if is_recent_file(src_file):  # Filter by recent files
                                    shutil.copy2(src_file, os.path.join(dest_subdir, file))
                    else:
                        # Collect ALL other files without checking modification time
                        if os.path.isdir(folder):
                            for root, _, files in os.walk(folder):
                                for file in files:
                                    src_file = os.path.join(root, file)
                                    if not src_file.endswith(".bak"):  # Exclude .bak files
                                        shutil.copy2(src_file, os.path.join(dest_path, file))
                        else:
                            shutil.copy2(folder, dest_path)

            for log_file in log_files_to_collect:
                shutil.copy(log_file, psmp_logs_directory)

            command_output_dir = os.path.join(psmp_logs_directory, "command_output")
            os.makedirs(command_output_dir, exist_ok=True)

            for command in commands:
                try:
                    command_output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
                    command_filename = command.replace(" ", "_").replace("-", "_").replace("/", "_") + ".txt"
                    command_file_path = os.path.join(command_output_dir, command_filename)
                    with open(command_file_path, 'w') as f:
                        f.write(command_output)
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to execute command: {command} with error: {e}")
            
            current_date = datetime.now().strftime("%m-%d-%y_%H-%M")
            zip_filename = f"PSMPAssistant_Logs-{current_date}.zip"
            with zipfile.ZipFile(zip_filename, "w") as zipf:
                for root, _, files in os.walk(psmp_logs_directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, os.path.relpath(file_path, psmp_logs_directory))

            logging.info(f"Logs copied and zip file created: {zip_filename}")

        except Exception as e:
            logging.info(f"An error occurred: {e}")

        finally:
            shutil.rmtree(psmp_logs_directory, ignore_errors=True)


class CommandHandler:

    # Checking for command-line argument
    def command_line_args(psmp_version):
        skip_debug = False
        for arg in sys.argv:
            if "--skip-debug" in sys.argv:
                skip_debug = True
            if arg == "logs":
                SideFeatures.logs_collect(skip_debug)
                return
            elif arg == "string":
                logging.info(SideFeatures.generate_psmp_connection_string())
                Utility.delete_file(Utility.log_filename)
                return
            elif arg == "repair":
                RPMAutomation.rpm_repair(psmp_version)
                return
        
        print(f"{ERROR} Invalid agrument.")
       

class PSMPAssistant:
    def __init__(self):
        self.psmp_versions = SystemConfiguration.load_psmp_versions_json("src/psmp_versions.json")
        self.psmp_version = SystemConfiguration.get_installed_psmp_version()
        self.REPAIR_REQUIRED = False
    
    def run_diagnostics(self):
        logging.info("Starting PSMP System Diagnostics...")
        SystemConfiguration.machine_conf_valid(self.psmp_versions,self.psmp_version,self.REPAIR_REQUIRED)
        logging.info("\nDiagnostics completed.")
    
    def execute_command(self):
        CommandHandler.command_line_args(self.psmp_version)
    

def main():
    Utility.print_logo()

    Utility.check_privileges()

    psmp_assistant = PSMPAssistant()
    
    if len(sys.argv) > 1:
        psmp_assistant.execute_command()
    else:
        psmp_assistant.run_diagnostics()

    Utility.clean_log_file(Utility.log_filename)
    
if __name__ == "__main__":
    main()
