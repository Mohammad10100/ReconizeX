#!/usr/bin/env python3
import subprocess
import os
import sys
import shutil
import xml.etree.ElementTree as ET

# Ensure apktool is installed
if not shutil.which("apktool"):
    print("[ERROR] apktool is not installed. Install it first: `apt install apktool` or `brew install apktool`")
    sys.exit(1)

def run_command(command, capture_output=False):
    """Run a shell command and capture output (if specified)"""
    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=capture_output, text=True, check=True
        )
        return result.stdout if capture_output else ""
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\n{e.stderr}")
        sys.exit(1)

def decompile_apk(target):
    """Decompile the APK using apktool"""
    decompile_dir = f"{target}_decompile"
    print("\n[+] Decompiling APK...")
    run_command(f"apktool d \"{target}\" -f -o \"{decompile_dir}\"")
    print(f"[+] APK decompiled and saved in {decompile_dir}")
    return decompile_dir

def get_smali_dirs(decompile_dir, package_name):
    """Generate and return smali directories from package name"""
    smali_path = os.path.join(decompile_dir, "smali")
    smali_dirs = package_name.split('.')
    
    # Check for additional smali_classes* directories (smali_classes2, smali_classes3, etc.)
    smali_target_dirs = [os.path.join(smali_path, *smali_dirs)]
    for i in range(2, 10):  # Check for smali_classes2, smali_classes3, etc.
        smali_classes_dir = os.path.join(decompile_dir, f"smali_classes{i}")
        if os.path.exists(smali_classes_dir):
            smali_target_dirs.append(os.path.join(smali_classes_dir, *smali_dirs))
    
    return smali_target_dirs

def restricted_scan(decompile_dir, package_names):
    """Perform scan for specified package names in restricted mode"""
    print("\n[+] Performing Restricted Scan...")

    smali_target_dirs = []
    for package_name in package_names:
        smali_dirs = package_name.split('.')  # Split the package name into parts
        smali_target_dirs += [
            os.path.join(decompile_dir, "smali", *smali_dirs),
            os.path.join(decompile_dir, "smali_classes2", *smali_dirs),
            os.path.join(decompile_dir, "smali_classes3", *smali_dirs)
        ]

    # Filter out non-existing directories
    existing_dirs = [dir for dir in smali_target_dirs if os.path.exists(dir)]
    if not existing_dirs:
        print("[ERROR] No smali directories found for the specified package names.")
        sys.exit(1)

    return existing_dirs

def run_nuclei(decompile_dir, templates_path, output_dir, mode, smali_dirs):
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "nuk.txt")
    print("\n[+] Running Nuclei Templates...")


    # Build the Nuclei command and execute it
    if mode == '1':
        nuclei_cmd = f"echo {decompile_dir} | nuclei --silent -file -t {templates_path} -o {output_file}"
        run_command(nuclei_cmd)
    if mode == '2':
        # Prepare files and directories to scan
        files_and_dirs_to_scan = [
            os.path.join(decompile_dir, "AndroidManifest.xml"),
            os.path.join(decompile_dir, "res/values/strings.xml")
        ] + smali_dirs  # Include smali directories for scanning

        # Ensure all files and directories exist
        for file in files_and_dirs_to_scan:
            if not os.path.exists(file):
                print(f"[ERROR] {file} does not exist.")
                sys.exit(1)

        # Create the 'restricted/' folder
        restricted_dir = os.path.join(decompile_dir, "restricted")
        if not os.path.exists(restricted_dir):
            os.makedirs(restricted_dir)

        # Copy files and directories to the 'restricted/' folder
        for item in files_and_dirs_to_scan:
            if os.path.isfile(item):  # If it's a file
                shutil.copy(item, restricted_dir)
            elif os.path.isdir(item):  # If it's a directory
                dest_dir = os.path.join(restricted_dir, os.path.basename(item))
                # Check if the destination directory exists and delete it if necessary
                if os.path.exists(dest_dir):
                    shutil.rmtree(dest_dir)  # Remove the existing directory
                shutil.copytree(item, dest_dir)

        # Run the Nuclei scan using the 'restricted/' folder
        print(f"[+] Scanning the restricted folder: {restricted_dir}")
        nuclei_cmd = f"echo {restricted_dir} | nuclei --silent -file -t {templates_path} -o {output_file}"
        run_command(nuclei_cmd)

    return output_file


def process_results(output_file, output_dir):
    """Process the Nuclei results and categorize them based on severity"""
    if not os.path.exists(output_file) or os.stat(output_file).st_size == 0:
        print("\n[+] No results ... Better Luck Next time")
        return
    else:
        print(f"\n[+] Results saved in {output_dir}")
        
        # Create separate files based on severity or keywords
        severities = ['info', 'low', 'medium', 'high']
        for sev in severities:
            with open(os.path.join(output_dir, f"{sev}.txt"), 'w') as f_out:
                cmd = f"grep '{sev}' {output_file} 2>/dev/null | sort -u"
                output = run_command(cmd, capture_output=True)
                f_out.write(output)
        
        # Filter out non-info results and search for specific keywords
        with open(os.path.join(output_dir, "non-info.txt"), 'w') as f_out:
            cmd = f"grep -v 'info' {output_file} | sort -u"
            non_info = run_command(cmd, capture_output=True)
            firebase_output = run_command(f"grep 'firebase-database' {output_file} | sort -u", capture_output=True)
            f_out.write(non_info + "\n" + firebase_output)
        
        # Optionally remove the original Nuclei output file
        os.remove(output_file)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <target.apk>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Set paths (update them as needed)
    PATH_TO_NUCLEI_TEMPLATES = "./mobile-nuclei-templates-i/"
    OUTPUT_DIR = f"{target}_nuclei_output"
    
    # Step 1: Decompile APK
    decompiled_folder = decompile_apk(target)
    
    # Step 2: Choose scan mode (Intense vs Restricted)
    scan_mode = input("\nChoose scan mode:\n1. Intense Scan\n2. Restricted Scan\nEnter choice (1 or 2): ").strip()

    if scan_mode == "1":
        # Intense Scan: Scan all smali directories
        print("[+] Performing Intense Scan...")
        # Step 3.1: Run Nuclei scan on the selected directories
        nuclei_output = run_nuclei(decompiled_folder, PATH_TO_NUCLEI_TEMPLATES, OUTPUT_DIR, scan_mode, smali_dirs=[])
        # Step 4.1: Process and categorize the scan results
        process_results(nuclei_output, OUTPUT_DIR)
    elif scan_mode == "2":
        # Restricted Scan: User provides package names
        print("[+] Performing Restricted Scan...")
        package_names = input("Enter package names (e.g., com.example.myapp, android.support.annotation): ").strip().split(',')
        # Clean up any leading/trailing spaces from the input
        package_names = [pkg.strip() for pkg in package_names]
        smali_dirs = restricted_scan(decompiled_folder, package_names)
        # Step 3.2: Run Nuclei scan on the selected directories
        nuclei_output = run_nuclei(decompiled_folder, PATH_TO_NUCLEI_TEMPLATES, OUTPUT_DIR, scan_mode, smali_dirs)
        # Step 4.2: Process and categorize the scan results
        process_results(nuclei_output, OUTPUT_DIR)
    else:
        print("[ERROR] Invalid choice. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    main()