#!/usr/bin/env python3
import subprocess
import os
import sys
import shutil

if not shutil.which("apktool"):
    print("[ERROR] apktool is not installed. Install it first: `apt install apktool` or `brew install apktool`")
    sys.exit(1)


def run_command(command, capture_output=False):
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
    decompile_dir = f"{target}_decompile"
    print("\n[+] Decompiling APK...")
    run_command(f"apktool d {target} -f -o {decompile_dir}")
    print(f"[+] APK decompiled and saved in {decompile_dir}")
    return decompile_dir

def run_nuclei(decompile_dir, templates_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "nuk.txt")
    print("\n[+] Running Nuclei Templates...")
    
    # Build and run the nuclei command
    print(templates_path)
    nuclei_cmd = (
        f"echo {decompile_dir} | nuclei --silent -file -t {templates_path} -o {output_file}"
    )

    # if not os.path.exists(templates_path) or not os.listdir(templates_path):
    #     print("[ERROR] Nuclei templates not found or empty! Check your template path.")
    #     sys.exit(1)


    # nuclei_cmd = f"nuclei -target {decompile_dir} -t {templates_path} --silent -debug -o {output_file}"


    run_command(nuclei_cmd)
    return output_file

def process_results(output_file, output_dir):
    # Check if the output file has content
    if not os.path.exists(output_file) or os.stat(output_file).st_size == 0:
        print("\n[+] No results ... Better Luck Next time")
        return
    else:
        print(f"\n[+] Results saved in {output_dir}")
        
        # Create separate files based on severity or keywords
        severities = ['info', 'low', 'medium', 'high']
        for sev in severities:
            with open(os.path.join(output_dir, f"{sev}.txt"), 'w') as f_out:
                # cmd = f"grep '{sev}' {output_file} | sort -u"
                cmd = f"grep '{sev}' {output_file} 2>/dev/null | sort -u"
                output = run_command(cmd, capture_output=True)
                f_out.write(output)
        
        # Additional filtering example: results containing 'firebase-database'
        with open(os.path.join(output_dir, "non-info.txt"), 'w') as f_out:
            cmd = f"grep -v 'info' {output_file} | sort -u"
            non_info = run_command(cmd, capture_output=True)
            # Append any firebase-database related results if needed
            firebase_output = run_command(f"grep 'firebase-database' {output_file} | sort -u", capture_output=True)
            f_out.write(non_info + "\n" + firebase_output)
        
        # Optionally remove the original nuclei output file
        os.remove(output_file)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <target_apk>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Set your paths here (update these paths as needed)
    # PATH_TO_NUCLEI_TEMPLATES = "/Users/mohammad/nuclei-templates/mobile-nuclei-templates/Extended"
    PATH_TO_NUCLEI_TEMPLATES = "./mobile-nuclei-templates-i/"
    OUTPUT_DIR = f"{target}_nuclei_output"
    
    # Step 1: Decompile APK
    decompiled_folder = decompile_apk(target)
    
    # Step 2: Run Nuclei scan on the decompiled folder
    nuclei_output = run_nuclei(decompiled_folder, PATH_TO_NUCLEI_TEMPLATES, OUTPUT_DIR)
    
    # Step 3: Process and categorize the scan results
    process_results(nuclei_output, OUTPUT_DIR)

if __name__ == "__main__":
    main()

