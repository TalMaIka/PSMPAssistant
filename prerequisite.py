import subprocess
import sys

# Dependencies to install
dependencies = {
    'distro': 'src/prerequisites/distro-1.9.0-py3-none-any.whl',
    'psutil': 'src/prerequisites/psutil-5.9.8.tar.gz'
}

def check_python_version():
    """
    Check if the Python version is 3.6 or above.
    """
    if sys.version_info < (3, 6):
        print("Python 3.6 or above is required. Current version:", sys.version)
        sys.exit(1)
    print(f"Python version {sys.version} is sufficient.")

def check_package(package_name, install_command):
    """
    Check if a system package is installed. If not, offer to install it.
    """
    try:
        subprocess.run(['rpm', '-q', package_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{package_name} is installed.")
    except FileNotFoundError:
        print("The 'rpm' command is not available on this system. Ensure required packages are installed manually.")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print(f"{package_name} is not installed.")
        user_input = input(f"Would you like to install {package_name}? (yes/no): ").strip().lower()
        if user_input in ['yes', 'y']:
            try:
                subprocess.check_call(install_command, shell=True)
                print(f"{package_name} installed successfully.")
            except subprocess.CalledProcessError:
                print(f"Failed to install {package_name}. Please install it manually.")
                sys.exit(1)
        else:
            print(f"{package_name} is required. Please install it and rerun the script.")
            sys.exit(1)

def check_dependency(package):
    """
    Check if a Python package is installed.
    """
    try:
        subprocess.run(['pip3', 'show', package], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{package} is already installed.")
        return True
    except subprocess.CalledProcessError:
        print(f"{package} not found.")
        return False

def install_dependency(package, path):
    """
    Install a Python package from the given path.
    """
    subprocess.check_call(['pip3', 'install', '--upgrade', '--user', path])

def main():
    # Check Python version
    check_python_version()

    # Check and offer to install system dependencies
    check_package('python3-devel', 'sudo yum install gcc python3-devel -y')
    check_package('gcc', 'sudo yum install gcc python3-devel -y')

    # Install Python dependencies
    for package, filepath in dependencies.items():
        if not check_dependency(package):
            install_dependency(package, filepath)

if __name__ == "__main__":
    main()
