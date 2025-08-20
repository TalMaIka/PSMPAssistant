# Copyright: © 2025 CyberArk Community, Developed By Tal.M
# Version: 1.2 (Ubuntu DEB Support 14.6+)
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
import argparse
import hashlib
import tempfile
from pathlib import Path
from functools import lru_cache
from typing import Optional, Tuple, List, Dict, Any

# Logging colors and constants
WARNING = '\033[38;5;214m[!]\033[0m'
ERROR = '\033[0;31m[-]\033[0m'
SUCCESS = '\033[0;32m[+]\033[0m'

VAULT_INI_PATH = "/etc/opt/CARKpsmp/vault/vault.ini"

# Enforce minimum Python version
MIN_PYTHON = (3, 6)
if sys.version_info < MIN_PYTHON:
    sys.exit(
        f"\n{ERROR} PSMPAssistant requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or higher. "
        f"Current version: {sys.version_info.major}.{sys.version_info.minor}\n"
    )

# Security: Compile regex patterns once at module level for efficiency
ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
VERSION_PATTERN = re.compile(r'(\d+)\.(\d+)')
RPM_VERSION_PATTERN = re.compile(r'(CARKpsmp)-(\d+\.\d+\.\d+)[-.](\d+)')
DEB_VERSION_PATTERN = re.compile(r'^(CARKpsmp)-((?:\d+\.)*\d+)\.amd64\.deb$')
VAULT_ADDRESS_PATTERN = re.compile(r'^ADDRESS=(.+)$', re.MULTILINE)

# Command line arguments handler
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PSMPAssistant - CyberArk PSMP Diagnostic and Repair Tool"
    )

    parser.add_argument(
        "action",
        nargs="?",
        choices=["logs", "string", "repair", "diagnose"],
        default="diagnose",
        help="Action to perform: logs, string, repair, or diagnose (default)"
    )

    parser.add_argument(
        "--skip-debug",
        action="store_true",
        help="Skip debug level check during log collection"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="PSMPAssistant v1.2 (Ubuntu DEB Support 14.6+) by Tal.M",
        help="Show program version and exit"
    )

    return parser.parse_args()

# Define the signal handler
def handle_signal(signal, frame):
    print("\n\nTerminating tool...")
    if hasattr(Utility, 'log_filename') and os.path.exists(Utility.log_filename):
        Utility.delete_file(Utility.log_filename)
    sleep(2)
    sys.exit(0)

# Set up the signal handler for SIGINT (Ctrl+C)
signal.signal(signal.SIGINT, handle_signal)


class SecurityUtils:
    """Security utilities for input validation and safe operations"""
    
    @staticmethod
    def sanitize_path(path: str) -> str:
        """Sanitize file paths to prevent directory traversal attacks"""
        # Resolve to absolute path and ensure it doesn't contain dangerous patterns
        safe_path = os.path.abspath(os.path.normpath(path))
        if ".." in safe_path or safe_path.startswith("/proc") and "/proc/loadavg" not in safe_path:
            raise ValueError(f"Potentially unsafe path: {path}")
        return safe_path
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def sanitize_input(user_input: str, max_length: int = 256) -> str:
        """Sanitize user input to prevent injection attacks"""
        # Remove control characters and limit length
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', user_input)
        return sanitized[:max_length].strip()
    
    @staticmethod
    def safe_subprocess_run(cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Execute subprocess commands safely without shell=True"""
        # Never use shell=True for security
        kwargs['shell'] = False
        # Python 3.6 compatibility: use stdout/stderr instead of capture_output
        if 'capture_output' in kwargs:
            if kwargs.pop('capture_output'):
                kwargs['stdout'] = subprocess.PIPE
                kwargs['stderr'] = subprocess.PIPE
        else:
            # Default to capturing output
            kwargs.setdefault('stdout', subprocess.PIPE)
            kwargs.setdefault('stderr', subprocess.PIPE)
        
        # Python 3.6 compatibility: only use universal_newlines, not text
        # Remove 'text' if it exists (Python 3.7+) and use universal_newlines instead
        if 'text' in kwargs:
            kwargs.pop('text')
        kwargs.setdefault('universal_newlines', True)  # This is the Python 3.6 way
        kwargs.setdefault('timeout', 30)  # Add timeout to prevent hanging
        
        try:
            return subprocess.run(cmd, **kwargs)
        except subprocess.TimeoutExpired:
            logging.error(f"{ERROR} Command timed out: {' '.join(cmd)}")
            raise
        except Exception as e:
            logging.error(f"{ERROR} Command failed: {' '.join(cmd)} - {e}")
            raise


class Utility:
    # Cache for frequently accessed files
    _file_cache: Dict[str, Any] = {}
    _cache_ttl: Dict[str, datetime] = {}
    CACHE_DURATION = timedelta(seconds=60)
    
    # Logging to write to the dynamically named file and the console
    log_filename = datetime.now().strftime("PSMPAssistant-%m-%d-%y__%H-%M-%S.log")
    
    # Keep log file in script directory (maintaining original behavior)
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )

    @staticmethod
    def clean_log_file(log_file_path: str):
        """Clean ANSI escape codes from log file"""
        try:
            safe_path = SecurityUtils.sanitize_path(log_file_path)

            # Skip silently if file does not exist
            if not os.path.exists(safe_path):
                return

            # Read the log file
            with open(safe_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()

            # Remove ANSI escape codes efficiently
            cleaned_content = ANSI_ESCAPE_PATTERN.sub('', content)

            # Write back
            with open(safe_path, 'w', encoding='utf-8') as file:
                file.write(cleaned_content)

        except Exception as e:
            logging.error(f"{ERROR} Failed to clean log file: {e}")

    @staticmethod
    def delete_file(file_path: str):
        """Safely delete a file"""
        try:
            safe_path = SecurityUtils.sanitize_path(file_path)
            if os.path.exists(safe_path):
                os.remove(safe_path)
        except ValueError as e:
            logging.error(f"{ERROR} Invalid file path: {e}")
        except FileNotFoundError:
            logging.warning(f"{WARNING} File '{file_path}' not found.")
        except PermissionError:
            logging.error(f"{WARNING} Permission denied: Unable to delete '{file_path}'.")
        except Exception as e:
            logging.error(f"{ERROR} An error occurred: {e}")

    @staticmethod
    def check_privileges():
        """Verify the script is running with root privileges"""
        if os.geteuid() != 0:
            print(f"{ERROR} PSMPAssistant tool must be run as root!")
            sleep(2)
            sys.exit(1)

    @staticmethod
    def print_logo():
        """Display the PSMPAssistant logo"""
        logo = r"""
     ____  ____  __  __ ____   _            _     _              _   
    |  _ \/ ___||  \/  |  _ \ / \   ___ ___(_)___| |_ __ _ _ __ | |_ 
    | |_) \___ \| |\/| | |_) / _ \ / __/ __| / __| __/ _` | '_ \| __|
    |  __/ ___) | |  | |  __/ ___ \\__ \__ \ \__ \ || (_| | | | | |_ 
    |_|   |____/|_|  |_|_| /_/   \_\___/___/_|___/\__\__,_|_| |_|\__|
                      © 2025 CyberArk Community"""
        logging.info(f"{logo}\n\n")

    @staticmethod
    def truncate_logs(file_path: str, max_lines: int = 3000) -> Optional[str]:
        """Efficiently truncate log files to last N lines"""
        try:
            safe_path = SecurityUtils.sanitize_path(file_path)
            
            # Use deque for efficient line limiting
            with open(safe_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = deque(file, maxlen=max_lines)
                return ''.join(lines)
        except Exception as e:
            logging.error(f"{ERROR} Error truncating {file_path}: {e}")
            return None

    @staticmethod
    @lru_cache(maxsize=32)
    def load_config(file_name: str) -> Dict:
        """Load and cache configuration from JSON file"""
        try:
            safe_path = SecurityUtils.sanitize_path(file_name)
            with open(safe_path, "r", encoding='utf-8') as file:
                return json.load(file)
        except Exception as e:
            logging.error(f"{ERROR} Failed to load config {file_name}: {e}")
            return {}
    
    @staticmethod
    def get_service_status(service_name: str) -> str:
        """Check systemd service status securely"""
        try:
            # Security: Use list command without shell
            result = SecurityUtils.safe_subprocess_run(
                ["systemctl", "is-active", service_name]
            )
            return f"{SUCCESS} Running" if result.stdout.strip() == "active" else f"{ERROR} Inactive"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return f"{ERROR} Inactive"
    
    @staticmethod
    def read_file(file_path: str, mode: str = "r", use_cache: bool = False) -> Optional[Any]:
        """Read file with optional caching and security checks"""
        try:
            safe_path = SecurityUtils.sanitize_path(file_path)
            
            # Check cache if enabled
            if use_cache and safe_path in Utility._file_cache:
                cache_time = Utility._cache_ttl.get(safe_path, datetime.min)
                if datetime.now() - cache_time < Utility.CACHE_DURATION:
                    return Utility._file_cache[safe_path]
            
            # Read file
            with open(safe_path, mode, encoding='utf-8' if 'b' not in mode else None) as file:
                content = file.readlines() if "b" not in mode else file.read()
            
            # Update cache if enabled
            if use_cache:
                Utility._file_cache[safe_path] = content
                Utility._cache_ttl[safe_path] = datetime.now()
            
            return content
            
        except ValueError as e:
            logging.error(f"{ERROR} Invalid file path: {e}")
        except FileNotFoundError:
            logging.error(f"{WARNING} File not found: {file_path}")
        except PermissionError:
            logging.error(f"{WARNING} Permission denied: {file_path}")
        except Exception as e:
            logging.error(f"{ERROR} Error reading {file_path}: {e}")
        return None
    
    @staticmethod
    @lru_cache(maxsize=32)
    def load_psmp_versions_json(file_path: str) -> Dict:
        """Load and cache PSMP versions from JSON file"""
        return Utility.load_config(file_path)


class SystemConfiguration:
    # Cache for expensive operations
    _version_cache: Optional[Tuple[str, str]] = None
    _distro_cache: Optional[Tuple[str, str]] = None
    
    def __init__(self):
        self.psmp_version = self.get_installed_psmp_version()[0]

    @staticmethod
    @lru_cache(maxsize=1)
    def get_installed_psmp_version() -> Tuple[str, str]:
        """Get installed PSMP version with caching"""
        if SystemConfiguration._version_cache:
            return SystemConfiguration._version_cache
        
        distro = SystemConfiguration.get_linux_distribution()[0]
        
        try:
            if distro.lower() == "ubuntu":
                result = SecurityUtils.safe_subprocess_run(
                    ["dpkg", "-l"]
                )
                
                # Process output more efficiently
                for line in result.stdout.splitlines():
                    if "cark" in line.lower() and line.startswith("ii"):
                        parts = line.split()
                        if len(parts) >= 3:
                            full_version = parts[2]
                            match = VERSION_PATTERN.search(full_version)
                            if match:
                                major, minor = match.groups()
                                main_version = f"{major}.{minor}"
                                
                                if main_version.startswith("12.0"):
                                    main_version = main_version.replace("12.0", "12.")
                                
                                SystemConfiguration._version_cache = (main_version, full_version)
                                return SystemConfiguration._version_cache
            else:
                result = SecurityUtils.safe_subprocess_run(
                    ["rpm", "-qa"]
                )
                
                for line in result.stdout.splitlines():
                    if "cark" in line.lower() and "infra" not in line.lower():
                        full_version = line.strip()
                        match = VERSION_PATTERN.search(full_version)
                        if match:
                            major, minor = match.groups()
                            main_version = f"{major}.{minor}"
                            
                            if main_version.startswith("12.0"):
                                main_version = main_version.replace("12.0", "12.")
                            
                            SystemConfiguration._version_cache = (main_version, full_version)
                            return SystemConfiguration._version_cache
            
            logging.error(f"{ERROR} No valid PSMP version found. Exiting.")
            sys.exit(1)
            
        except Exception as e:
            logging.error(f"{ERROR} Failed to detect PSMP version: {e}")
            sys.exit(1)

    @staticmethod
    @lru_cache(maxsize=1)
    def get_linux_distribution() -> Tuple[str, str]:
        """Get Linux distribution with caching"""
        if SystemConfiguration._distro_cache:
            return SystemConfiguration._distro_cache
        
        distro_name = "Unknown"
        version = "Unknown"
        
        try:
            # Read /etc/os-release efficiently
            os_release_path = SecurityUtils.sanitize_path("/etc/os-release")
            with open(os_release_path, "r") as f:
                distro_info = {}
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        distro_info[key] = value.strip('"')
                
                os_name = distro_info.get("NAME", "")
                os_version = distro_info.get("VERSION_ID", "")
                
                if "CentOS" in os_name:
                    distro_name = "CentOS Linux"
                    file_path = "/etc/centos-release"
                elif "Red Hat" in os_name:
                    distro_name = "Red Hat Enterprise Linux"
                    file_path = "/etc/redhat-release"
                elif "Rocky" in os_name:
                    SystemConfiguration._distro_cache = (os_name, os_version)
                    return SystemConfiguration._distro_cache
                else:
                    SystemConfiguration._distro_cache = (os_name, os_version)
                    return SystemConfiguration._distro_cache
                
                # Parse release file for CentOS/RHEL
                with open(SecurityUtils.sanitize_path(file_path), "r") as f:
                    content = f.read()
                    match = re.search(r"release\s+([\d\.]+)", content)
                    if match:
                        version = match.group(1)
                
                SystemConfiguration._distro_cache = (distro_name, version)
                return SystemConfiguration._distro_cache
                
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(f"{ERROR} Error detecting distribution: {e}")
        
        # Fallback to uname
        try:
            result = SecurityUtils.safe_subprocess_run(["uname", "-r"])
            SystemConfiguration._distro_cache = ("Linux Kernel", result.stdout.strip())
            return SystemConfiguration._distro_cache
        except:
            SystemConfiguration._distro_cache = (distro_name, version)
            return SystemConfiguration._distro_cache

    @staticmethod
    def is_supported(psmp_versions: Dict, psmp_version: str, distro_name: str, distro_version: str) -> bool:
        """Check if PSMP version is supported for the given Linux distribution"""
        # Sort versions for finding nearest fallback
        sorted_versions = sorted(
            psmp_versions.keys(),
            key=lambda v: tuple(map(int, v.split('.')))
        )
        
        # Find the closest previous version
        fallback_version = None
        psmp_tuple = tuple(map(int, psmp_version.split('.')))
        
        for version in sorted_versions:
            if tuple(map(int, version.split('.'))) <= psmp_tuple:
                fallback_version = version
            else:
                break
        
        if fallback_version is None:
            return False
        
        # Check distribution and version support
        for distro_info in psmp_versions[fallback_version]['supported_distributions']:
            if distro_info['name'].lower() == distro_name.lower():
                for supported_version in distro_info.get('versions', []):
                    if distro_version.startswith(supported_version):
                        return True
        
        return False

    @staticmethod
    @lru_cache(maxsize=1)
    def is_integrated(psmp_version: str) -> bool:
        """Check if PSMP is in integrated mode with caching"""
        try:
            # Check version first (more efficient)
            if float(psmp_version) > 13.2:
                return True
            
            # Check for infra package
            result = SecurityUtils.safe_subprocess_run(["rpm", "-qa"])
            return any(
                package.startswith("CARKpsmp-infra")
                for package in result.stdout.splitlines()
            )
            
        except (subprocess.CalledProcessError, ValueError) as e:
            logging.error(f"{ERROR} Failed to check integration mode: {e}")
            return False

    @staticmethod
    def check_services_status() -> Dict[str, str]:
        """Check the status of PSMP and SSHD services"""
        sleep(2)
        
        service_statuses = {
            "psmpsrv": Utility.get_service_status("psmpsrv"),
            "sshd": Utility.get_service_status("sshd"),
        }
        
        # Check PSMP communication with Vault
        if service_statuses["psmpsrv"] == f"{SUCCESS} Running":
            service_statuses["psmpsrv"] = f"{ERROR} Running but not communicating with Vault"
            
            log_path = "/var/opt/CARKpsmp/logs/PSMPConsole.log"
            log_content = Utility.read_file(log_path, use_cache=True)
            
            if log_content:
                log_text = "".join(log_content[-100:])  # Check only last 100 lines for efficiency
                
                if ("is up and working with Vault" in log_text and
                    "Sockets server is down" not in log_text and
                    "PSM SSH Proxy has been terminated" not in log_text):
                    service_statuses["psmpsrv"] = f"{SUCCESS} Running and communicating with Vault"
        
        return service_statuses

    @staticmethod
    def is_nc_installed() -> bool:
        """Check if netcat is installed"""
        return shutil.which("nc") is not None

    @staticmethod
    def get_vault_address(file_path: str) -> str:
        """Fetch vault address from configuration file"""
        try:
            safe_path = SecurityUtils.sanitize_path(file_path)
            content = Utility.read_file(safe_path, use_cache=True)
            
            if content:
                match = VAULT_ADDRESS_PATTERN.search("".join(content))
                if match:
                    vault_address = match.group(1).strip()
                    if vault_address:
                        return vault_address.split(",")[0].strip()
            
            logging.error(f"{ERROR} Vault address not found in configuration.")
            sys.exit(1)
            
        except Exception as e:
            logging.error(f"{ERROR} Failed to read vault configuration: {e}")
            sys.exit(1)

    @staticmethod
    def verify_vault_address(vault_address: str, file_path: str):
        """Verify vault address with user confirmation"""
        # Validate IP address format
        ip_part = vault_address.split(":")[0] if ":" in vault_address else vault_address
        if not SecurityUtils.validate_ip_address(ip_part):
            logging.error(f"{ERROR} Invalid IP address format: {vault_address}")
            sys.exit(1)
        
        user_input = SecurityUtils.sanitize_input(
            input(f"Is the Vault address {vault_address} correct? (y/n): ")
        ).lower()
        
        if user_input not in ['y', 'yes']:
            logging.info(f"{ERROR} Wrong Vault address. Please edit the address in '{file_path}'.")
            sys.exit(1)

    @staticmethod
    def check_vault_comm(service_status: Dict[str, str]) -> bool:
        """Check communication between PSMP and Vault server"""
        if (service_status["psmpsrv"] == f"{ERROR} Inactive" or 
            service_status["psmpsrv"] == f"{ERROR} Running but not communicating with Vault"):
            
            logging.info(f"{ERROR} The PSMP service is inactive.")
            
            if not SystemConfiguration.is_nc_installed():
                logging.info(f"{WARNING} Netcat (nc) is not installed. Skipping communication check.")
            
            vault_address = SystemConfiguration.get_vault_address(VAULT_INI_PATH)
            
            print(f"Fetched Vault IP: {vault_address}")
            SystemConfiguration.verify_vault_address(vault_address, VAULT_INI_PATH)
            
            try:
                if SystemConfiguration.is_nc_installed():
                    logging.info("Checking communication to the vault...")
                    sleep(2)
                    
                    # Security: Use subprocess without shell
                    result = SecurityUtils.safe_subprocess_run(
                        ["nc", "-z", "-w", "5", vault_address, "1858"]
                    )
                    
                    if result.returncode == 0:
                        logging.info(f"{SUCCESS} Communication to the vault is successful.")
                
                sleep(1)
                logging.info(f"{WARNING} Restarting PSMP service...")
                
                try:
                    SecurityUtils.safe_subprocess_run(
                        ["systemctl", "restart", "psmpsrv"],
                        timeout=30
                    )
                    
                    service_status = SystemConfiguration.check_services_status()
                    if (service_status["psmpsrv"] != f"{ERROR} Inactive" and 
                        service_status["psmpsrv"] != f"{ERROR} Running but not communicating with Vault"):
                        return True
                        
                except subprocess.TimeoutExpired:
                    logging.error(f"{WARNING} Timeout reached.")
                    # Read last line from log
                    log_path = '/var/opt/CARKpsmp/logs/PSMPConsole.log'
                    log_content = Utility.read_file(log_path)
                    if log_content and log_content[-1]:
                        logging.error(f"{WARNING} {log_content[-1].strip()}")
                        
            except subprocess.CalledProcessError:
                logging.info(f"{ERROR} No communication with the vault.")
                sys.exit(1)
                
        return False

    @staticmethod
    @lru_cache(maxsize=1)
    def get_openssh_version() -> Optional[float]:
        """Get OpenSSH version with caching"""
        try:
            result = SecurityUtils.safe_subprocess_run(["ssh", "-V"], stderr=subprocess.STDOUT)
            match = re.search(r"OpenSSH_(\d+\.\d+)", result.stdout)
            if match:
                return float(match.group(1))
        except Exception:
            pass
        return None

    @staticmethod
    def check_openssh_version() -> Tuple[bool, str, Optional[float]]:
        """Check OpenSSH version for PSMP compatibility"""
        try:
            ssh_version = SystemConfiguration.get_openssh_version()
            if ssh_version is not None:
                sleep(2)
                if ssh_version >= 7.7:
                    return True, "", ssh_version
                else:
                    return False, f"{WARNING} OpenSSH version is: {ssh_version}, required version 7.7 and above.", ssh_version
            else:
                return False, f"{ERROR} Failed to determine OpenSSH version.", None
        except Exception as e:
            return False, f"Error: {e}", None

    @staticmethod
    def check_sshd_config(psmp_version: str, repair_required: bool) -> bool:
        """Check sshd_config for misconfigurations with improved efficiency"""
        logging.info("\nSSHD Configuration Check:")
        sleep(2)
        
        integrated_psmp = SystemConfiguration.is_integrated(psmp_version)
        sshd_config_path = "/etc/ssh/sshd_config"
        
        # Compile patterns once
        patterns = {
            'psmp_auth': re.compile(r"# PSMP Authentication Configuration Block Start"),
            'allow_user': re.compile(r"^\s*AllowUser"),
            'empty_pass': re.compile(r"^\s*PermitEmptyPasswords\s+yes"),
            'pubkey_auth': re.compile(r"^\s*PubkeyAuthentication\s+yes"),
            'include': re.compile(r"^\s*Include\s+(.*)"),
            'managed': re.compile(r"(Ansible|Puppet|Chef)\s")
        }
        
        found_flags = {
            'psmp_auth_block': False,
            'allow_user': False,
            'pubkey_accepted_algorithms': False,
            'permit_empty_pass': False,
            'pubkey_auth': False
        }
        
        def collect_all_config_lines(main_path: str) -> List[Tuple[str, str]]:
            """Recursively collect all configuration lines"""
            all_lines = []
            processed_files = set()  # Prevent infinite loops
            
            def process_file(file_path: str):
                if file_path in processed_files:
                    return
                processed_files.add(file_path)
                
                try:
                    safe_path = SecurityUtils.sanitize_path(file_path)
                    with open(safe_path, "r") as f:
                        for line in f:
                            all_lines.append((file_path, line))
                            match = patterns['include'].match(line)
                            if match:
                                include_path = match.group(1).strip()
                                for inc_file in glob.glob(include_path):
                                    if os.path.isfile(inc_file):
                                        process_file(inc_file)
                except (FileNotFoundError, ValueError) as e:
                    logging.warning(f"{WARNING} Could not read SSH config file: {file_path} - {e}")
            
            process_file(main_path)
            return all_lines
        
        config_lines = collect_all_config_lines(sshd_config_path)
        
        # Process lines efficiently
        for path, line in config_lines:
            if patterns['managed'].search(line):
                logging.info(f"{WARNING} {path} is managed by: {line.strip()}")

            # ✅ Check PSMP block regardless of comment
            if patterns['psmp_auth'].search(line):
                found_flags['psmp_auth_block'] = True

            # ✅ Only check directives if not commented out
            if not line.lstrip().startswith("#"):
                if patterns['allow_user'].match(line):
                    found_flags['allow_user'] = True
                if patterns['empty_pass'].match(line):
                    found_flags['permit_empty_pass'] = True
                if patterns['pubkey_auth'].match(line):
                    found_flags['pubkey_auth'] = True

            # Early exit if all flags found
            if all(found_flags.values()):
                break
        
        # Evaluate repair requirements
        if not found_flags['psmp_auth_block'] and integrated_psmp:
            logging.info(f"{ERROR} PSMP authentication block not found.")
            repair_required = True
        
        if not found_flags['permit_empty_pass'] and not integrated_psmp:
            logging.info(f"{WARNING} PermitEmptyPasswords missing.")
            repair_required = True
        
        if found_flags['allow_user']:
            logging.info(f"{WARNING} AllowUser mentioned in SSH config and should not be present.")
        
        if not found_flags['pubkey_auth']:
            logging.info(f"{WARNING} PubkeyAuthentication is not enabled, which could interfere with MFA caching.")
        
        if not repair_required:
            logging.info(f"{SUCCESS} No misconfiguration found related to sshd_config.")
        else:
            logging.info(f"{ERROR} SSHD misconfiguration found.")
        
        return repair_required


    @staticmethod
    def check_debug_level() -> bool:
        """Check debug level configuration"""
        psmp_confxml_path = "/var/opt/CARKpsmp/temp/PVConfiguration.xml"
        desired_log_level = "DEBUG3"
        
        try:
            # Get active SSHD configuration
            result = SecurityUtils.safe_subprocess_run(["sshd", "-T"])
            
            if result.returncode != 0:
                logging.error(f"{ERROR} sshd -T failed with return code {result.returncode}")
                if result.stderr:
                    logging.error(f"{ERROR} sshd -T stderr: {result.stderr.strip()}")
                if result.stdout:
                    logging.error(f"{ERROR} sshd -T stdout: {result.stdout.strip()}")
                return False

            sshd_config_output = {}
            for line in result.stdout.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    sshd_config_output[parts[0]] = parts[1]
        
        except FileNotFoundError:
            logging.info(f"{ERROR} 'sshd' command not found. Is OpenSSH installed?")
            return False
        except Exception as e:
            logging.info(f"{ERROR} Unexpected failure running sshd -T: {e}")
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
        
        # Check PVConfiguration.xml
        try:
            xml_content = Utility.read_file(psmp_confxml_path, use_cache=True)
            if not xml_content:
                logging.info(f"{ERROR} PVConfiguration.xml file not found.")
                return False
            
            xml_text = "".join(xml_content)
            
            # Use compiled regex for efficiency
            server_trace_match = re.search(
                r'<ServerSettings\b[^>]*TraceLevels="1,2,3,4,5,6,7"\s*>',
                xml_text
            )
            client_trace_match = re.search(
                r'<ConnectionClientSettings\b[^>]*TraceLevels="1,2"\s*>',
                xml_text
            )
            
            if server_trace_match:
                logging.info(f"{SUCCESS} Correct ServerSettings TraceLevels found.")
            else:
                logging.info(f"{ERROR} Missing ServerSettings TraceLevels.")
            
            if client_trace_match:
                logging.info(f"{SUCCESS} Correct ConnectionClientSettings TraceLevels found.")
            else:
                logging.info(f"{ERROR} Missing ConnectionClientSettings TraceLevels.")
            
            if not (server_trace_match and client_trace_match):
                logging.info("\nTo fix this, update the PVWA settings:")
                logging.info("1. Go to Administration → Options → Privileged Session Management → General Settings.")
                logging.info("2. Under Server Settings, set TraceLevels=1,2,3,4,5,6,7")
                logging.info("3. Under Connection Client Settings, set TraceLevels=1,2")
                logging.info("* Make sure to Save and Restart psmpsrv service.")
            
            return bool(server_trace_match and client_trace_match)
            
        except Exception as e:
            logging.error(f"{ERROR} Error checking PVConfiguration.xml: {e}")
            return False


    @staticmethod
    def check_system_resources() -> str:
        """Check system resource utilization"""
        logging.info("\nChecking system resources load:")
        sleep(2)
        
        try:
            # CPU Load check
            with open("/proc/loadavg", "r") as f:
                load_avg = float(f.readline().split()[0])
            
            # Count CPU cores efficiently
            with open("/proc/cpuinfo") as f:
                cores = sum(1 for line in f if line.startswith("processor"))
            
            if cores > 0:
                load_percentage = (load_avg / cores) * 100
                cpu_info = (f"{WARNING} High CPU Load: {load_percentage:.2f}%"
                           if load_percentage > 100
                           else f"{SUCCESS} CPU Load within normal limits.")
            else:
                cpu_info = f"{WARNING} Unable to determine CPU core count."
            
            # Disk space check
            result = SecurityUtils.safe_subprocess_run(["df", "-h"])
            high_usage_partitions = []
            
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    usage_str = parts[4].rstrip('%')
                    if usage_str.isdigit():
                        usage_percent = int(usage_str)
                        if usage_percent > 85:
                            high_usage_partitions.append(
                                f"{parts[0]}: {usage_percent}% used (Mounted on {parts[5]})"
                            )
            
            disk_info = (f"{WARNING} High Disk Usage:\n" + "\n".join(high_usage_partitions)
                        if high_usage_partitions
                        else f"{SUCCESS} Sufficient disk space.")
            
            return f"{cpu_info}\n{disk_info}"
            
        except Exception as e:
            return f"{WARNING} Error retrieving system status: {e}"

    @staticmethod
    def search_logs_patterns(distro_name: str):
        """Search log files for known error patterns"""
        sleep(1)
        
        config = Utility.load_config("src/logs_pattern_config.json")
        if not config:
            return
        
        found_entries = {
            "secure_logs": deque(maxlen=10),
            "psmp_logs": deque(maxlen=10)
        }
        
        # Determine log file based on distribution
        log_file = None
        for key in config.get("log_files", {}):
            if distro_name.startswith(key):
                log_file = config["log_files"][key]
                break
        
        # Compile patterns once for efficiency
        secure_patterns = [
            re.compile(pattern)
            for pattern in config.get("secure_logs_patterns", [])
        ]
        psmp_patterns = config.get("psmp_trace_patterns", [])
        
        # Search security logs
        if log_file:
            try:
                safe_path = SecurityUtils.sanitize_path(log_file)
                with open(safe_path, 'r', encoding='utf-8', errors='ignore') as file:
                    # Use deque to limit memory usage for large files
                    for line in deque(file, maxlen=10000):
                        if any(regex.search(line) for regex in secure_patterns):
                            found_entries["secure_logs"].append(line.strip())
            except (FileNotFoundError, ValueError) as e:
                logging.warning(f"{WARNING} Log file {log_file} not accessible: {e}")
        
        # Search PSMPTrace logs
        psmp_log_file = config.get("log_files", {}).get("PSMPTrace")
        if psmp_log_file:
            try:
                safe_path = SecurityUtils.sanitize_path(psmp_log_file)
                with open(safe_path, 'r', encoding='utf-8', errors='ignore') as file:
                    # Read last 1000 lines efficiently
                    lines = deque(file, maxlen=1000)
                    for line in reversed(list(lines)):
                        if any(pattern in line for pattern in psmp_patterns):
                            found_entries["psmp_logs"].append(line.strip())
            except (FileNotFoundError, ValueError) as e:
                logging.info(f"{WARNING} PSMPTrace log file not accessible: {e}")
        
        # Print results
        logging.info("\n=== Secure Log ===")
        logging.info("\n".join(found_entries["secure_logs"]) if found_entries["secure_logs"] else "No matches found.")
        
        logging.info("\n=== Trace Logs ===")
        logging.info("\n".join(found_entries["psmp_logs"]) if found_entries["psmp_logs"] else "No matches found.")

    @staticmethod
    def hostname_check() -> str:
        """Verify hostname is not default"""
        hostname = socket.gethostname()
        sleep(2)
        
        if 'localhost' in hostname.lower():
            logging.info(f"\n{WARNING} Hostname: '{hostname}' is default. Change to unique hostname to avoid issues.")
        
        return hostname

    @staticmethod
    def check_selinux() -> bool:
        """Check SELinux status and handle denials"""
        logging.info("\nChecking SELinux...")
        sleep(2)
        
        if not shutil.which("getenforce"):
            logging.info(f"{WARNING} SELinux not installed on this system.")
            return False
        
        try:
            result = SecurityUtils.safe_subprocess_run(["getenforce"])
            selinux_mode = result.stdout.strip()
            logging.info(f"Current SELinux mode: {selinux_mode.lower()}")
            
            if selinux_mode.lower() == "enforcing":
                logging.info("Restarting PSMP service to check for denials...")
                
                try:
                    SecurityUtils.safe_subprocess_run(
                        ["systemctl", "restart", "psmpsrv"],
                        timeout=30
                    )
                except:
                    logging.warning("Unable to restart service.")
                
                if not shutil.which("ausearch"):
                    logging.warning("'ausearch' not found. Cannot check SELinux denials.")
                    return False
                
                sleep(2)
                result = SecurityUtils.safe_subprocess_run(
                    ["ausearch", "-m", "AVC,USER_AVC", "-ts", "recent", "-f", "psmp"]
                )
                
                if result.stdout.strip():
                    filtered_lines = [
                        line for line in result.stdout.splitlines()
                        if "psmp" in line and "syntaxparser" not in line
                    ]
                    
                    if filtered_lines:
                        for line in filtered_lines[-5:]:
                            logging.info(line)
                        
                        user_input = SecurityUtils.sanitize_input(
                            input("Do you want to temporarily disable SELinux? (y/n): ")
                        ).lower()
                        
                        if user_input in ["yes", "y"]:
                            SecurityUtils.safe_subprocess_run(["setenforce", "0"])
                            logging.info(f"{WARNING} SELinux enforcement disabled temporarily.")
                            return True
                    else:
                        logging.info(f"{SUCCESS} No relevant SELinux denials found.")
                else:
                    logging.info(f"{SUCCESS} No SELinux denials found for PSMP.")
            else:
                logging.info(f"{WARNING} SELinux not enforcing.")
                
        except Exception as e:
            logging.error(f"Error checking SELinux: {e}")
        
        return False

    @staticmethod
    def suse_post_installation_steps():
        """Verify SUSE post-installation configuration"""
        logging.info("\nVerifying SUSE post-installation steps:")
        
        try:
            sshd_config_path = SecurityUtils.sanitize_path('/etc/ssh/sshd_config')
            
            if os.path.exists(sshd_config_path):
                with open(sshd_config_path, 'r') as file:
                    permit_empty_found = False
                    
                    for line in file:
                        stripped = line.strip()
                        if stripped.startswith('#') or not stripped:
                            continue
                        
                        if stripped.lower().startswith('permitemptypasswords'):
                            permit_empty_found = True
                            parts = stripped.split()
                            
                            if len(parts) >= 2 and parts[1].lower() == 'no':
                                logging.info(f"{SUCCESS} PermitEmptyPasswords is correctly set to 'no'.")
                            else:
                                logging.info(f"{ERROR} PermitEmptyPasswords incorrectly set. Change to 'no'.")
                            break
                    
                    if not permit_empty_found:
                        logging.info(f"{ERROR} PermitEmptyPasswords missing. Add 'PermitEmptyPasswords no'.")
            else:
                logging.info(f"{ERROR} {sshd_config_path} not found.")
                
        except Exception as e:
            logging.info(f"Error verifying SUSE configuration: {e}")

    @staticmethod
    def restore_selinux_status() -> bool:
        """Restore SELinux to enforcing mode"""
        user_input = SecurityUtils.sanitize_input(
            input("\nRestore SELinux to enforcing? (y/n): ")
        ).lower()
        
        if user_input in ["yes", "y"]:
            try:
                SecurityUtils.safe_subprocess_run(["setenforce", "1"])
                logging.info(f"{WARNING} SELinux enforcement restored.")
                return True
            except:
                logging.error(f"{ERROR} Failed to restore SELinux.")
        else:
            logging.info(f"{WARNING} SELinux remains permissive.")
        
        return False

    @staticmethod
    def disable_nscd_service():
        """Disable NSCD service if running"""
        try:
            result = SecurityUtils.safe_subprocess_run(["systemctl", "is-active", "nscd"])
            
            if result.stdout.strip() == "active":
                logging.info("\nNSCD service is active and should be disabled")
                logging.info("https://docs.cyberark.com/pam-self-hosted/latest/en/content/pas%20inst/before-installing-psmp.htm")
                
                confirmation = SecurityUtils.sanitize_input(
                    input("\nDisable NSCD? (y/n): ")
                ).lower()
                
                if confirmation in ["y", "yes"]:
                    SecurityUtils.safe_subprocess_run(["systemctl", "stop", "nscd"])
                    SecurityUtils.safe_subprocess_run(["systemctl", "disable", "nscd"])
                    logging.info(f"{SUCCESS} NSCD stopped and disabled.")
            else:
                logging.info(f"NSCD Service Status: {SUCCESS} Not running.")
                
        except subprocess.CalledProcessError as e:
            logging.info(f"Error checking NSCD: {e}")

    @staticmethod
    def verify_nsswitch_conf(psmp_version: str) -> bool:
        """Verify nsswitch.conf configuration"""
        nsswitch_path = "/etc/nsswitch.conf"
        logging.info("\nConfiguration Check for nsswitch.conf:")
        sleep(2)
        
        try:
            psmp_ver = float(psmp_version)
        except ValueError:
            logging.info("Invalid PSMP version.")
            return False
        
        if not SystemConfiguration.is_integrated(str(psmp_ver)):
            logging.info(f"{SUCCESS} nsswitch.conf is correctly configured.")
            return False
        
        required_services = ["passwd", "group"]
        misconfigurations = []
        
        try:
            safe_path = SecurityUtils.sanitize_path(nsswitch_path)
            with open(safe_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or ':' not in line:
                        continue
                    
                    key, value = map(str.strip, line.split(":", 1))
                    if key in required_services:
                        methods = value.split()
                        if "psmp" not in methods:
                            misconfigurations.append((key, value))
            
            if misconfigurations:
                logging.info(f"{ERROR} Misconfigurations found in /etc/nsswitch.conf:")
                for key, value in misconfigurations:
                    logging.info(f" - {key}: missing 'psmp', found: '{value}'")
                return True
            else:
                logging.info(f"{SUCCESS} nsswitch.conf is correctly configured.")
                return False
                
        except (FileNotFoundError, ValueError) as e:
            logging.info(f"{nsswitch_path} not accessible: {e}")
            return False

    @staticmethod
    def machine_conf_valid(psmp_versions: Dict, psmp_version: str, repair_required: bool):
        """Validate machine configuration"""
        if not psmp_version:
            logging.info(f"\n{ERROR} No PSMP version found.")
            logging.info(f"\n{WARNING} Proceed with repair: 'python3 PSMPAssistant.py repair'")
            return
        
        # Check compatibility
        logging.info("\nPSMP Compatibility Check:")
        sleep(2)
        
        distro_name, distro_version = SystemConfiguration.get_linux_distribution()
        
        if SystemConfiguration.is_supported(psmp_versions, psmp_version, distro_name, distro_version):
            logging.info(f"{SUCCESS} PSMP {psmp_version} supports {distro_name} {distro_version}")
        else:
            logging.info(f"{ERROR} PSMP {psmp_version} does not support {distro_name} {distro_version}")
            logging.info(f"See: https://docs.cyberark.com/pam-self-hosted/{psmp_version}/en/Content/PAS%20SysReq/System%20Requirements%20-%20PSMP.htm")
        
        # Run checks
        SystemConfiguration.hostname_check()
        
        success, message, ssh_version = SystemConfiguration.check_openssh_version()
        if not success:
            logging.info("\n" + message)
        
        nsswitch_changes = False
        if SystemConfiguration.is_integrated(psmp_version):
            nsswitch_changes = SystemConfiguration.verify_nsswitch_conf(psmp_version)
        
        logging.info(SystemConfiguration.check_system_resources())
        
        repair_required = SystemConfiguration.check_sshd_config(psmp_version, repair_required)
        
        temp_disable = False
        if distro_name.lower() != "ubuntu":
            temp_disable = SystemConfiguration.check_selinux()
        
        if repair_required or nsswitch_changes:
            logging.info(f"\n{WARNING} Repair required: 'python3 PSMPAssistant.py repair'")
            sleep(2)
            return
        
        if distro_name == "SLES":
            SystemConfiguration.suse_post_installation_steps()
        
        logging.info("\nLog Analyzer:")
        SystemConfiguration.search_logs_patterns(distro_name)
        
        logging.info("\nServices Availability Check:")
        service_status = SystemConfiguration.check_services_status()
        
        if SystemConfiguration.check_vault_comm(service_status):
            service_status = SystemConfiguration.check_services_status()
        
        sleep(2)
        logging.info(f"PSMP Service Status: {service_status.get('psmpsrv', 'Unavailable')}")
        logging.info(f"SSHD Service Status: {service_status.get('sshd', 'Unavailable')}")
        
        SystemConfiguration.disable_nscd_service()
        
        if (service_status.get('psmpsrv') != f"{SUCCESS} Running and communicating with Vault" or
            nsswitch_changes):
            logging.info(f"\n{WARNING} Recommended: 'python3 PSMPAssistant.py repair'")
        
        if temp_disable:
            SystemConfiguration.restore_selinux_status()


class RPMAutomation:
    @staticmethod
    def verify_installation_files(install_folder: str, psmp_short_version: str) -> bool:
        """Verify required installation files exist"""
        try:
            safe_folder = SecurityUtils.sanitize_path(install_folder)
            
            if float(psmp_short_version) < 14.6:
                required_files = [
                    f"{safe_folder}/CreateCredFile",
                    VAULT_INI_PATH,
                    f"{safe_folder}/psmpparms.sample"
                ]
            else:
                required_files = [f"{safe_folder}/psmpparms.sample"]
            
            missing_files = []
            for file in required_files:
                try:
                    safe_file = SecurityUtils.sanitize_path(file)
                    if not os.path.exists(safe_file):
                        missing_files.append(file)
                except ValueError:
                    missing_files.append(file)
            
            if missing_files:
                logging.info(f"{WARNING} Missing files: {', '.join(missing_files)}")
                return False
            
            logging.info(f"{SUCCESS} All required installation files present.")
            return True
            
        except ValueError as e:
            logging.error(f"{ERROR} Invalid installation folder: {e}")
            return False

    @staticmethod
    def import_gpg_key(installation_folder: str) -> bool:
        """Import RPM GPG key"""
        try:
            safe_folder = SecurityUtils.sanitize_path(installation_folder)
            key_path = f"{safe_folder}/RPM-GPG-KEY-CyberArk"
            
            result = SecurityUtils.safe_subprocess_run(
                ["rpm", "--import", key_path]
            )
            
            if result.returncode == 0:
                logging.info(f"{SUCCESS} GPG key imported from: {key_path}")
                return True
            else:
                logging.error(f"{ERROR} Failed to import GPG key")
                return False
                
        except Exception as e:
            logging.error(f"{ERROR} Failed to import GPG key: {e}")
            return False

    @staticmethod
    def is_rpm_signed(rpm_path: str) -> bool:
        """Check if RPM is properly signed"""
        try:
            safe_path = SecurityUtils.sanitize_path(rpm_path)
            
            result = SecurityUtils.safe_subprocess_run(
                ["rpm", "-K", "-v", safe_path]
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
                        logging.error(f"{ERROR} RPM verification failed: {line}")
                        return False
                    if "Signature" in line:
                        has_valid_signature = True
            
            if not has_valid_signature:
                logging.error(f"{ERROR} RPM is not signed: {rpm_path}")
                return False
            
            logging.info(f"{SUCCESS} RPM verification passed: {rpm_path}")
            return True
            
        except Exception as e:
            logging.error(f"{ERROR} Error verifying RPM: {e}")
            return False

    @staticmethod
    def create_cred_file(psmp_short_version: str, install_folder: str) -> bool:
        """Execute CreateCredFile utility"""
        try:
            safe_folder = SecurityUtils.sanitize_path(install_folder)
            
            if float(psmp_short_version) < 14.6:
                create_cred_file_path = os.path.join(safe_folder, "CreateCredFile")
            else:
                create_cred_file_path = "/opt/CARKpsmp/bin/createcredfile"
            
            safe_cred_path = SecurityUtils.sanitize_path(create_cred_file_path)
            
            if os.path.exists(safe_cred_path):
                os.chmod(safe_cred_path, 0o755)
                logging.info("\nFinalize PSMP installation.")
                logging.info("\033[91m[!] Set 'Restrict to Entropy File' to 'yes'\033[0m")
                sleep(1)
                
                subprocess.run([safe_cred_path, "user.cred"])
                
                # Move credential files (overwrite if already exist)
                for file in ["user.cred", "user.cred.entropy"]:
                    if os.path.exists(file):
                        dest_file = os.path.join(safe_folder, file)
                        if os.path.exists(dest_file):
                            os.remove(dest_file)  # remove existing file before overwrite
                        shutil.move(file, dest_file)
                
                logging.info(f"\n{SUCCESS} Credential files moved to installation folder (overwritten if existed).")
                return True
            else:
                logging.info(f"\n{ERROR} CreateCredFile not found in {install_folder}")
                return False
                
        except Exception as e:
            logging.error(f"Error creating credential file: {e}")
            return False


    @staticmethod
    def vault_env_recreate(psmp_short_version: str, install_folder: str):
        """Recreate vault environment"""
        choice = SecurityUtils.sanitize_input(
            input(f"\n{WARNING} Re-create Vault environment? (y/n): ")
        ).lower()
        
        if choice not in ['y', 'yes']:
            logging.info(f"{WARNING} Vault environment creation skipped.")
            return
        
        logging.info(f"{WARNING} Re-creating Vault environment.")
        
        if RPMAutomation.create_cred_file(psmp_short_version, install_folder):
            psmp_setup = "/opt/CARKpsmp/bin/psmp_setup.sh"
            
            try:
                safe_setup = SecurityUtils.sanitize_path(psmp_setup)
                safe_folder = SecurityUtils.sanitize_path(install_folder)
                
                if os.path.exists(safe_setup):
                    os.chmod(safe_setup, 0o755)
                    sleep(1)
                    
                    process = subprocess.Popen(
                        [safe_setup, "--finalize", "--credfile", f"{safe_folder}/user.cred"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    stdout, stderr = process.communicate(timeout=60)
                    
                    for line in stdout.strip().splitlines():
                        logging.info(line)
                    for line in stderr.strip().splitlines():
                        logging.error(line)
                    
                    if "completed with errors" in stdout or "[ERROR]" in stdout or "[ERROR]" in stderr:
                        logging.error(f"{ERROR} Vault environment creation failed.")
                    else:
                        logging.info(f"{SUCCESS} Vault environment creation succeeded.")
                        
            except Exception as e:
                logging.error(f"{ERROR} Failed to recreate vault environment: {e}")

    @staticmethod
    
    def deb_repair(psmp_version: str, psmp_short_version: str):
        """Automates the repair process for PSMP installations."""
        logging.info("\nPSMP DEB Installation Repair (Ubuntu 14.6+):")
        logging.info(f"PSMP Version Detected: {psmp_version}")
        logging.info(f"Integrated mode: True")
        logging.info("Searching the machine for version-matching installation files...")

        def parse_version(s):
            print(f"Parsing version from: {s}")
            m = re.search(r'^(CARKpsmp)-((?:\d+\.)*\d+)\.amd64\.deb$', s)
            if not m:
                return (None, None, None)
            name = m.group(1)
            full_version = m.group(2)
            parts = full_version.split(".")
            if len(parts) < 2:
                return (None, None, None)
            build = parts[-1]
            version = ".".join(parts[:-1])
            return (name, version, build)

        def check_debconf_and_prompt(deb_file_path):
            result = subprocess.run(["debconf-show", "carkpsmp"], capture_output=True, text=True)
            return bool(result.stdout.strip())

        try:
            deb_files = [
                os.path.join(root, file)
                for root, _, files in os.walk('/')
                for file in files
                if file.startswith('CARK') and file.endswith('.deb') and '/Trash/files/' not in os.path.join(root, file)
            ]

            name, ver, build = parse_version(psmp_version)
            matching_debs = []
            for deb in deb_files:
                parsed = parse_version(deb)
                if parsed:
                    deb_name, deb_ver, deb_build = parsed
                    if deb_name == name and deb_ver == ver and deb_build == build and "infra" not in deb:
                        matching_debs.append(deb)

            if not matching_debs:
                logging.info(f"{ERROR} No DEB file found matching version {psmp_version}.")
                return

            deb_location = matching_debs[0]
            install_folder = os.path.dirname(deb_location)
            logging.info(f"Installation folder found at: {install_folder}")

            if input(f"Is the installation folder {install_folder} correct? (y/n): ").strip().lower() not in ['y', 'yes']:
                logging.info("Installation folder not confirmed. Exiting.")
                return

            if not RPMAutomation.verify_installation_files(install_folder, psmp_short_version):
                return

            vault_address = SystemConfiguration.get_vault_address(VAULT_INI_PATH)
            SystemConfiguration.verify_vault_address(vault_address, VAULT_INI_PATH)

            deb_file_path = os.path.join(install_folder, os.path.basename(deb_location))
            if not check_debconf_and_prompt(deb_file_path):
                logging.info(f"\n{ERROR} Preconfiguration file not found or not cached. Please run:\n  dpkg-preconfigure {deb_file_path}\n")
                logging.info("Exiting the repair process. Please ensure to preconfigure the package before repairing.")
                return

            logging.info(f"\n{SUCCESS} Preconfiguration file found, Proceeding with repairing.")
            logging.info(f"\nInstalling DEB from: {deb_file_path}")

            install_cmd = ["dpkg", "-i", "--force-all", deb_file_path]
            process = subprocess.Popen(install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            out, err = process.communicate()
            for line in out.strip().splitlines():
                logging.info(line)
            for line in err.strip().splitlines():
                logging.error(line)

        except Exception as e:
            logging.error(f"An error occurred during the DEB repair process: {e}")
            return
        
        # Step 7 New approach Vault env creation - Finalize PSMP installation
        RPMAutomation.vault_env_recreate(psmp_short_version, install_folder)


    @staticmethod
    def rpm_repair(psmp_version: str, psmp_short_version: str):
        """Repair RPM installation"""
        logging.info("\nPSMP RPM Installation Repair:")
        logging.info(f"PSMP Version Detected: {psmp_version}")
        integration_mode = SystemConfiguration.is_integrated(psmp_short_version)
        logging.info(f"Integrated mode: {integration_mode}")
        logging.info("Searching for installation files...")
        sleep(2)
        
        try:
            # Find RPM files efficiently
            rpm_files = []
            for root, _, files in os.walk('/'):
                # Skip trash and temp directories
                if '/Trash/' in root or '/tmp/' in root:
                    continue
                
                for file in files:
                    if file.startswith('CARK') and file.endswith('.rpm'):
                        rpm_files.append(os.path.join(root, file))
            
            # Handle version mapping for 12.x
            parts = psmp_version.split('.')
            if len(parts) == 2 and parts[0] == "12" and parts[1].isdigit():
                psmp_version = f"12.0{parts[1]}"
            
            # Parse and find matching RPMs
            name, ver, build = RPM_VERSION_PATTERN.search(psmp_version).groups() if RPM_VERSION_PATTERN.search(psmp_version) else (None, None, None)
            
            matching_rpms = []
            for rpm in rpm_files:
                parsed = RPM_VERSION_PATTERN.search(os.path.basename(rpm))
                if parsed:
                    rpm_name, rpm_ver, rpm_build = parsed.groups()
                    if (rpm_name == name and rpm_ver == ver and 
                        rpm_build == build and "infra" not in rpm):
                        matching_rpms.append(rpm)
            
            if not matching_rpms:
                logging.info(f"{ERROR} No RPM file found matching version {psmp_version}.")
                return
            
            rpm_location = matching_rpms[0]
            install_folder = os.path.dirname(rpm_location)
            logging.info(f"Installation folder found at: {install_folder}")
            
            user_confirm = SecurityUtils.sanitize_input(
                input(f"Is the installation folder {install_folder} correct? (y/n): ")
            ).lower()
            
            if user_confirm not in ['y', 'yes']:
                logging.info("Installation folder not confirmed. Exiting.")
                return
            
            if not RPMAutomation.verify_installation_files(install_folder, psmp_short_version):
                return
            
            vault_address = SystemConfiguration.get_vault_address(VAULT_INI_PATH)
            SystemConfiguration.verify_vault_address(vault_address, VAULT_INI_PATH)
            
            # Process psmpparms.sample
            psmpparms_sample_path = os.path.join(install_folder, "psmpparms.sample")
            if os.path.exists(psmpparms_sample_path):
                logging.info("Found psmpparms.sample file.")
                
                with open(psmpparms_sample_path, "r") as f:
                    psmpparms_content = f.readlines()
                
                # Accept EULA
                eula_accept = SecurityUtils.sanitize_input(
                    input("Accept CyberArk EULA? (y/n): ")
                ).lower()
                
                if eula_accept in ['y', 'yes']:
                    psmpparms_content = [
                        "AcceptCyberArkEULA=Yes\n" if line.startswith("AcceptCyberArkEULA=") 
                        else line for line in psmpparms_content
                    ]
                    logging.info("CyberArk EULA accepted.")
                else:
                    logging.info("CyberArk EULA not accepted.")
                    sys.exit(1)
                
                # Additional configuration for older versions
                if float(psmp_short_version) < 14.6:
                    psmpparms_content = [
                        f"InstallationFolder={install_folder}\n" 
                        if line.startswith("InstallationFolder=") 
                        else line for line in psmpparms_content
                    ]
                    
                    # Vault environment
                    create_vault = SecurityUtils.sanitize_input(
                        input("Create Vault environment? (y/n): ")
                    ).lower()
                    
                    psmpparms_content = [
                        ("CreateVaultEnvironment=No\n" if create_vault in ['n', 'no'] 
                         else "CreateVaultEnvironment=Yes\n")
                        if line.startswith("#CreateVaultEnvironment=") 
                        else line for line in psmpparms_content
                    ]
                    
                    # ADBridge
                    disable_adbridge = SecurityUtils.sanitize_input(
                        input("Disable ADBridge? (y/n): ")
                    ).lower()
                    
                    psmpparms_content = [
                        ("EnableADBridge=No\n" if disable_adbridge in ['y', 'yes'] 
                         else "EnableADBridge=Yes\n")
                        if line.startswith("#EnableADBridge=") 
                        else line for line in psmpparms_content
                    ]
                    
                    # SSHD Integration mode
                    if float(psmp_short_version) <= 13.2 and not integration_mode:
                        psmpparms_content = [
                            ("InstallCyberArkSSHD=Yes\n" if not integration_mode 
                             else "InstallCyberArkSSHD=Integrated\n")
                            if line.startswith("InstallCyberArkSSHD=") 
                            else line for line in psmpparms_content
                        ]
                
                # Save psmpparms
                temp_parms_path = "/var/tmp/psmpparms"
                with open(temp_parms_path, "w") as f:
                    f.writelines(psmpparms_content)
                logging.info("psmpparms file updated.")
            
            # Create credential file for older versions
            if float(psmp_short_version) < 14.6:
                if not RPMAutomation.create_cred_file(psmp_short_version, install_folder):
                    return
            
            # Import GPG key
            if not RPMAutomation.import_gpg_key(install_folder):
                return
            
            # Handle integrated mode RPMs
            if integration_mode and float(psmp_short_version) <= 13.2:
                integrated_rpm_dir = os.path.join(install_folder, "IntegratedMode")
                if os.path.exists(integrated_rpm_dir):
                    integrated_rpms = [
                        os.path.join(integrated_rpm_dir, f)
                        for f in os.listdir(integrated_rpm_dir)
                        if f.endswith(".rpm")
                    ]
                    
                    if integrated_rpms:
                        integrated_rpm = integrated_rpms[0]
                        if RPMAutomation.is_rpm_signed(integrated_rpm):
                            logging.info(f"\nRepairing IntegratedMode RPM: {integrated_rpm}")
                            subprocess.run(["rpm", "-Uvh", "--force", integrated_rpm])
                        else:
                            logging.info(f"{ERROR} IntegratedMode RPM not signed.")
                            return
            
            # Install main RPM
            rpm_file_path = os.path.join(install_folder, os.path.basename(rpm_location))
            logging.info(f"\nRepairing main RPM: {rpm_file_path}")
            
            if not RPMAutomation.is_rpm_signed(rpm_file_path):
                logging.info(f"{ERROR} Main RPM not signed. Exiting.")
                return
            
            # Execute RPM installation
            process = subprocess.Popen(
                ["rpm", "-Uvh", "--force", rpm_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            successful_installation = True
            for line in process.stdout:
                logging.info(line.strip())
                if "completed with errors" in line or "[ERROR]" in line:
                    logging.info(f"{ERROR} Installation completed with errors.")
                    successful_installation = False
                    break
            else:
                logging.info(f"\n{SUCCESS} Main RPM installed successfully.")
            
            # Recreate vault environment for newer versions
            if float(psmp_short_version) >= 14.6 and successful_installation:
                RPMAutomation.vault_env_recreate(psmp_short_version, install_folder)
                
        except Exception as e:
            logging.error(f"Error during RPM repair: {e}")


class SideFeatures:
    @staticmethod
    def generate_psmp_connection_string() -> str:
        """Generate PSMP connection string"""
        print("PSMP Connection String Generator")
        print("More info: https://cyberark.my.site.com/s/article/PSM-for-SSH-Syntax-Cheat-Sheet")
        print("\nProvide the following details:\n")
        
        print(f"{WARNING} MFA Caching requires FQDN of the Domain-Vault user.\n")
        print(f"{WARNING} Target user and target FQDN are case sensitive.\n")
        
        # Collect and sanitize inputs
        vault_user = SecurityUtils.sanitize_input(input("Enter vault user: "))
        target_user = SecurityUtils.sanitize_input(input("Enter target user: "))
        target_user_domain = SecurityUtils.sanitize_input(
            input("Enter target user domain (leave empty if local): ")
        )
        target_address = SecurityUtils.sanitize_input(input("Enter target address: "))
        target_port = SecurityUtils.sanitize_input(
            input("Enter target port (leave empty for default 22): ")
        )
        psm_address = SecurityUtils.sanitize_input(input("Enter PSM for SSH address: "))
        
        # Construct connection string
        connection_string = f"{vault_user}@{target_user}"
        
        if target_user_domain:
            connection_string += f"#{target_user_domain}"
        
        connection_string += f"@{target_address}"
        
        if target_port and target_port != '22':
            connection_string += f"#{target_port}"
        
        connection_string += f"@{psm_address}"
        
        print(f"\n{SUCCESS} Generated PSMP Connection String:")
        return connection_string

    @staticmethod
    def logs_collect(skip_debug: bool):
        """Collect PSMP logs efficiently"""
        logging.info("PSMP Logs Collection:\n")
        
        if not skip_debug:
            if not SystemConfiguration.check_debug_level():
                return
        
        sleep(2)
        
        # Clean assistant log
        Utility.clean_log_file(Utility.log_filename)
        
        # Time threshold
        three_days_ago = datetime.now() - timedelta(days=3)
        
        def is_recent_file(file_path: str) -> bool:
            """Check if file was modified in last 3 days"""
            try:
                safe_path = SecurityUtils.sanitize_path(file_path)
                if os.path.isfile(safe_path):
                    mtime = os.path.getmtime(safe_path)
                    return datetime.fromtimestamp(mtime) >= three_days_ago
            except:
                pass
            return False
        
        # Load configuration
        config = Utility.load_config("src/logs_config.json")
        if not config:
            logging.error(f"{ERROR} Failed to load logs configuration.")
            return
        
        log_folders = config.get("log_folders", [])
        log_categories = config.get("log_categories", {})
        commands = config.get("commands", [])
        
        # Find recent log files
        script_directory = os.path.dirname(os.path.abspath(__file__))
        log_pattern = os.path.join(script_directory, "PSMPAssistant-*.log")
        log_files_to_collect = [f for f in glob.glob(log_pattern) if is_recent_file(f)]
        
        # Display what will be collected
        logging.info("\nThe following will be collected:\n")
        for folder in log_folders:
            logging.info(folder)
        for log_file in log_files_to_collect:
            logging.info(log_file)
        
        logging.info("\nCommand outputs:")
        for command in commands:
            logging.info(command)
        
        logging.info("\nDocs: https://docs.cyberark.com/pam-self-hosted/latest/en/Content/PAS%20INST/The-PSMP-Environment.htm")
        
        choice = SecurityUtils.sanitize_input(input("Continue? (y/n): ")).lower()
        if choice not in ['y', 'yes']:
            logging.info("Logs collection aborted.")
            return
        
        # Create temporary directory for logs
        with tempfile.TemporaryDirectory() as temp_dir:
            psmp_logs_directory = os.path.join(temp_dir, "PSMPAssistant-Logs")
            os.makedirs(psmp_logs_directory, exist_ok=True)
            
            # Create category directories
            for category in log_categories.keys():
                os.makedirs(os.path.join(psmp_logs_directory, category), exist_ok=True)
            
            def get_log_category(log_path: str) -> Optional[str]:
                """Determine log category"""
                for category, patterns in log_categories.items():
                    if any(pattern in log_path for pattern in patterns):
                        return category
                return None
            
            try:
                # Collect log files
                for folder in log_folders:
                    if not os.path.exists(folder):
                        continue
                    
                    category = get_log_category(folder)
                    dest_path = os.path.join(psmp_logs_directory, category) if category else psmp_logs_directory
                    os.makedirs(dest_path, exist_ok=True)
                    
                    if folder.startswith("/var/opt/CARKpsmp/logs"):
                        # Filter by recent files
                        psmp_dest = os.path.join(psmp_logs_directory, "PSMP")
                        os.makedirs(psmp_dest, exist_ok=True)
                        
                        for root, _, files in os.walk(folder):
                            for file in files:
                                src_file = os.path.join(root, file)
                                if is_recent_file(src_file):
                                    rel_path = os.path.relpath(root, folder)
                                    dest_subdir = os.path.join(psmp_dest, rel_path)
                                    os.makedirs(dest_subdir, exist_ok=True)
                                    shutil.copy2(src_file, os.path.join(dest_subdir, file))
                    else:
                        # Collect all files
                        if os.path.isdir(folder):
                            for root, _, files in os.walk(folder):
                                for file in files:
                                    if not file.endswith(".bak"):
                                        src_file = os.path.join(root, file)
                                        shutil.copy2(src_file, os.path.join(dest_path, file))
                        else:
                            shutil.copy2(folder, dest_path)
                
                # Collect assistant logs
                for log_file in log_files_to_collect:
                    shutil.copy(log_file, psmp_logs_directory)
                
                # Collect command outputs
                command_output_dir = os.path.join(psmp_logs_directory, "command_output")
                os.makedirs(command_output_dir, exist_ok=True)
                
                for command in commands:
                    try:
                        # Security: Parse command safely
                        cmd_parts = command.split()
                        result = SecurityUtils.safe_subprocess_run(cmd_parts)
                        
                        command_filename = command.replace(" ", "_").replace("-", "_").replace("/", "_") + ".txt"
                        command_file_path = os.path.join(command_output_dir, command_filename)
                        
                        with open(command_file_path, 'w') as f:
                            f.write(result.stdout)
                            
                    except Exception as e:
                        logging.error(f"Failed to execute: {command} - {e}")
                
                # Create zip file
                current_date = datetime.now().strftime("%m-%d-%y_%H-%M")
                zip_filename = f"PSMPAssistant_Logs-{current_date}.zip"
                
                with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
                    for root, _, files in os.walk(psmp_logs_directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, temp_dir)
                            zipf.write(file_path, arcname)
                
                logging.info(f"Logs collected: {zip_filename}")
                
            except Exception as e:
                logging.error(f"Error collecting logs: {e}")


class PSMPAssistant:
    def __init__(self):
        self.psmp_versions = Utility.load_psmp_versions_json("src/psmp_versions.json")
        self.psmp_short_version, self.psmp_version = SystemConfiguration.get_installed_psmp_version()
        self.REPAIR_REQUIRED = False
        self.distro = SystemConfiguration.get_linux_distribution()[0].lower()
    
    def run_diagnostics(self):
        """Run system diagnostics"""
        logging.info("Starting PSMP System Diagnostics...")
        SystemConfiguration.machine_conf_valid(
            self.psmp_versions,
            self.psmp_short_version,
            self.REPAIR_REQUIRED
        )
        logging.info("\nDiagnostics completed.")
    
    def execute_command(self):
        """Execute the requested command"""
        args = parse_arguments()
        
        if args.action == "logs":
            SideFeatures.logs_collect(args.skip_debug)
        elif args.action == "string":
            logging.info(SideFeatures.generate_psmp_connection_string())
            Utility.delete_file(Utility.log_filename)
        elif args.action == "repair":
            if self.distro == "ubuntu":
                RPMAutomation.deb_repair(self.psmp_version, self.psmp_short_version)
            else:
                RPMAutomation.rpm_repair(self.psmp_version, self.psmp_short_version)
        elif args.action == "diagnose":
            self.run_diagnostics()
        else:
            logging.info(f"{ERROR} No valid action provided. Use --help for usage info.")


def main():
    """Main entry point"""
    Utility.print_logo()
    Utility.check_privileges()
    
    psmp_assistant = PSMPAssistant()
    psmp_assistant.execute_command()
    
    Utility.clean_log_file(Utility.log_filename)


if __name__ == "__main__":
    main()