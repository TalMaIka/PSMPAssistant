import subprocess

dependencies = {
    'distro': 'src/prerequisites/distro-1.9.0-py3-none-any.whl',
    'psutil': 'src/prerequisites/psutil-5.9.8.tar.gz'
}

def check_dependency(package):
    try:
        subprocess.run(['pip3', 'show', package], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{package} is already installed.")
        return True
    except subprocess.CalledProcessError:
        print(f"{package} not found.")
        return False

def install_dependency(package, path):
    subprocess.check_call(['pip3', 'install', '--upgrade', '--user', path])

def main():
    for package, filepath in dependencies.items():
        if not check_dependency(package):
            install_dependency(package, filepath)

if __name__ == "__main__":
    main()
