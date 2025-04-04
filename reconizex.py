import argparse
import subprocess
import os
import sys
import threading
import webbrowser
import http.server
import socketserver
import socket
import signal

PORT = 4309

def print_banner():
    banner = """
\033[1;31m==============================================================================\033[0m
\033[1;31m   ██▀███  ▓█████ ▄████▄  ▒█████   ███▄    █  ██▓▒███████▒▓█████ ▒██   ██▒    \033[0m
\033[1;31m   ▓██ ▒ ██▒▓█   ▀▒██▀ ▀█ ▒██▒  ██▒ ██ ▀█   █ ▓██▒▒ ▒ ▒ ▄▀░▓█   ▀ ▒▒ █ █ ▒░   \033[0m
\033[1;31m   ▓██ ░▄█ ▒▒███  ▒▓█    ▄▒██░  ██▒▓██  ▀█ ██▒▒██▒░ ▒ ▄▀▒░ ▒███   ░░  █   ░   \033[0m
\033[1;31m   ▒██▀▀█▄  ▒▓█  ▄▒▓▓▄ ▄██▒██   ██░▓██▒  ▐▌██▒░██░  ▄▀▒   ░▒▓█  ▄  ░ █ █ ▒    \033[0m
\033[1;31m   ░██▓ ▒██▒░▒████▒ ▓███▀ ░ ████▓▒░▒██░   ▓██░░██░▒███████▒░▒████▒▒██▒ ▒██▒   \033[0m
\033[1;31m   ░ ▒▓ ░▒▓░░░ ▒░ ░ ░▒ ▒  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░▓  ░▒▒ ▓░▒░▒░░ ▒░ ░▒▒ ░ ░▓ ░   \033[0m
\033[1;31m     ░▒ ░ ▒░ ░ ░  ░ ░  ▒    ░ ▒ ▒░ ░ ░░   ░ ▒░ ▒ ░░░▒ ▒ ░ ▒ ░ ░  ░░░   ░▒ ░   \033[0m
\033[1;31m     ░░   ░    ░  ░       ░ ░ ░ ▒     ░   ░ ░  ▒ ░░ ░ ░ ░ ░   ░    ░    ░     \033[0m
\033[1;31m      ░        ░  ░ ░         ░ ░           ░  ░    ░ ░       ░  ░ ░    ░     \033[0m
\033[1;31m      ░                               ░                                       \033[0m
\033[1;31m  ♥ Unveiling Hidden Vulnerabilities in Android Apps - CoE CNDS Lab Project ♥ \033[0m
\033[1;31m                                                     - Mohammad10100 ☠ ☠ 🔥 ☠ ☠  \033[0m
\033[1;31m==============================================================================\033[0m
    """
    print(banner)

def print_status(message, status="*"):
    colors = {"+": "\033[1;32m", "-": "\033[1;31m", "*": "\033[1;34m"}
    print(f"{colors.get(status, '\033[1;33m')}[{status}]\033[0m {message}")


def run_command(command, capture_output=False):
    """Run a shell command and capture output (if specified)"""
    try:
        result = subprocess.run(
            command, shell=True, capture_output=capture_output, text=True, check=True
        )
        return result.stdout if capture_output else ""
    except subprocess.CalledProcessError as e:
        print_status(f"Error running command: {command}\n{e.stderr}", "-")
        sys.exit(1)

def decompile_apk(target):
    """Decompile the APK using apktool"""
    decompile_dir = f"{target}_decompile"
    print_status("Decompiling APK...")
    run_command(f"apktool d \"{target}\" -f -o \"{decompile_dir}\"")
    print_status(f"APK decompiled and saved in {decompile_dir}")
    return decompile_dir

def restricted_scan(decompile_dir, package_name):
    """Perform scan for specified package name in restricted mode"""
    print_status("Performing Restricted Scan...", "*")
    smali_dirs = package_name.split('.')
    
    # Dynamically find all smali* directories
    smali_base_dirs = [d for d in os.listdir(decompile_dir) if d.startswith("smali")]
    smali_target_dirs = [os.path.join(decompile_dir, d, *smali_dirs) for d in smali_base_dirs]
    
    existing_dirs = [d for d in smali_target_dirs if os.path.exists(d)]
    if not existing_dirs:
        print_status("No smali directories found for the specified package.", "-")
        sys.exit(1)
    return existing_dirs

def resolve_output_path(output_path, default_ext):
    """Ensure the output path has a proper extension and is correctly placed one directory back"""
    if not os.path.isabs(output_path):
        parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        output_path = os.path.join(parent_dir, output_path)
    
    if not os.path.splitext(output_path)[1]:  # If no extension provided, append default
        output_path += default_ext
    
    return output_path

def run_nuclei(decompile_dir, templates_path, output_file, json_export, smali_dirs=None):
    print_status("Running Nuclei Templates...", "*")
    scan_target = decompile_dir if not smali_dirs else ' '.join(smali_dirs)
    
    output_file = resolve_output_path(output_file, ".txt")
    if json_export:
        json_export = resolve_output_path(json_export, ".json")
    
    nuclei_cmd = f"echo {scan_target} | nuclei --silent -file -t {templates_path} -o {output_file}"
    if json_export:
        nuclei_cmd += f" -je {json_export}"
    nuclei_cmd += f" --json-export report.json"
    run_command(nuclei_cmd)


def kill_process_on_port(port):
    """Kill any process using the specified port."""
    try:
        result = subprocess.run(
            f"lsof -ti:{port}", shell=True, capture_output=True, text=True
        )
        pids = result.stdout.strip().split("\n")
        for pid in pids:
            if pid:
                os.kill(int(pid), signal.SIGKILL)
                print(f"Killed process {pid} using port {port}")
    except Exception as e:
        print(f"Failed to kill process on port {port}: {e}")

def is_port_in_use(port):
    """Check if the port is already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("localhost", port)) == 0


def start_server():
    """Start an HTTP server using subprocess."""
    kill_process_on_port(PORT)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    try:
        subprocess.run(["python3", "-m", "http.server", str(PORT)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to start server: {e}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(usage="python3 reconizex0.py [-h] [-r RESTRICTED] [-o OUTPUT] [-je JSON_EXPORT] apk", description="APK Vulnerability Scanner using Nuclei")
    parser.add_argument("apk", help="Path to the target APK file")
    parser.add_argument("-r", "--restricted", help="Restricted mode with package name (e.g., com.example.app)")
    parser.add_argument("-o", "--output", default="output.txt", help="Path to the txt output file")
    parser.add_argument("-je", "--json-export", help="Path to export results in JSON format")
    args = parser.parse_args()
    
    PATH_TO_NUCLEI_TEMPLATES = "./mobile-nuclei-templates-i/"
    decompiled_folder = decompile_apk(args.apk)
    
    if args.restricted:
        smali_dirs = restricted_scan(decompiled_folder, args.restricted)
        run_nuclei(decompiled_folder, PATH_TO_NUCLEI_TEMPLATES, args.output, args.json_export, smali_dirs)
    else:
        run_nuclei(decompiled_folder, PATH_TO_NUCLEI_TEMPLATES, args.output, args.json_export)
    
    print_status(f"Scan complete. Results saved in {resolve_output_path(args.output, '.txt')}","+")
    if args.json_export:
        print_status(f"JSON results saved in {resolve_output_path(args.json_export, '.json')}","+")
    
     # Start server in a separate thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Wait for server to start, then open browser
    webbrowser.open(f"http://localhost:{PORT}/report.html")


if __name__ == "__main__":
    main()