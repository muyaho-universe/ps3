import re
import os
import subprocess
import hashlib
import re
import psutil
import resource
import multiprocessing
from tqdm import tqdm
import shutil
import time

LLC_PATH = "/root/HashEnabledLLVM/build/bin/llc"
MAX_OUTPUT_FILE_SIZE = 300 * 1024 * 1024  # 300MB
MAX_MEMORY = 8 * 1024 * 1024 * 1024  # 8GB
TIMEOUT = 300  # 5 minutes
MAX_RETRIES = 3  # Maximum number of retries for No_left_device error
MIN_FILE_SIZE = 1024  # 1KB, minimum file size to consider
BINARIES_CREATED_FILE = "binaries_created.txt"

def process_llc_command(cmd, source_dir, output_dir, bc_file):
    llc_path = cmd.split()[0]
    if llc_path.endswith('llc'):
        llc_path = LLC_PATH

    input_file = os.path.join(source_dir, bc_file)
    # output_file = os.path.splitext(input_file)[0] + '.o'
    output_file = os.path.splitext(input_file)[0] + '.elf'

    keep_patterns = [
        r'^-march=',
        r'^--mcpu=',
        r'^--target-abi=',
        r'^--float-abi=',
        r'^--mattr=',
        r'^--relocation-model=',
        r'^--code-model=',
        r'^--enable-machine-outliner',
        r'^--filetype=',
        r'^--function-sections',
        r'^--data-sections',
        r'^--frame-pointer=',
        r'^--stack-alignment=',
        r'^--mtriple=',
        r'^--position-independent',
        r'^--use-ctors',
        r'^--dwarf-version=',
        r'^--exception-model=',
        r'^--tailcallopt',
    ]

    options = re.findall(r'(?<=\s)(-{1,2}[\w-]+=?(?:\S+)?)', cmd)
    filtered_options = [opt for opt in options if any(re.match(pattern, opt) for pattern in keep_patterns)]

    new_cmd = [llc_path, '--relocation-model=pic', '-filetype=obj'] + filtered_options + [input_file, '-o', output_file]

    return ' '.join(new_cmd)

def sanitize_directory_name(name):
    return re.sub(r'[^\w\-_\.]', '_', name)

def set_memory_limit():
    resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY, MAX_MEMORY))

def fix_paths(cmd, source_dir, output_dir, bc_file):
    cmd = re.sub(r'/root//afl_sources//(.+?)\.bc', os.path.join(source_dir, r'\1.bc'), cmd)
    cmd = re.sub(r'-o\s+/root//assembly_folder/function_hash_iter//.*\.s', '', cmd)
    # print(f"Fixed paths: {cmd}")
    return cmd

def compile_to_object(cmd, output_dir, bc_file, source_dir, cve_dir_name):
    cmd_parts = cmd.split()
    if cmd_parts[0] == "timeout":
        cmd_parts = cmd_parts[2:]
    if cmd_parts[0].endswith("llc"):
        cmd_parts = cmd_parts[1:]

    cmd_parts = [part for part in cmd_parts if not part.endswith('.bc')]

    options_hash = hashlib.md5(' '.join(cmd_parts).encode()).hexdigest()[:8]
    cve_output_dir = os.path.join(output_dir, sanitize_directory_name(cve_dir_name))
    os.makedirs(cve_output_dir, exist_ok=True)
    # obj_output_filepath = os.path.join(cve_output_dir, f"{os.path.splitext(bc_file)[0]}_{options_hash}.o")
    obj_output_filepath = os.path.join(cve_output_dir, f"{os.path.splitext(bc_file)[0]}_{options_hash}.elf")

    llc_cmd = [LLC_PATH, '--relocation-model=pic', '-filetype=obj', os.path.join(source_dir, bc_file), '-o', obj_output_filepath] + cmd_parts
    # print(f"LLC command: {' '.join(llc_cmd)}")
    # time.sleep(10)
    try:
        process = psutil.Popen(llc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=set_memory_limit)
        start_time = time.time()

        while True:
            if process.poll() is not None:
                break

            if os.path.exists(obj_output_filepath):
                file_size = os.path.getsize(obj_output_filepath)
                if file_size > MAX_OUTPUT_FILE_SIZE:
                    process.kill()
                    os.remove(obj_output_filepath)
                    return None, "File Too Large"

            if time.time() - start_time > TIMEOUT:
                process.kill()
                return None, "Timeout"

            time.sleep(1)

        if process.returncode == 0:
            return obj_output_filepath, "Success"
        else:
            stderr_output = process.stderr.read().decode()
            if "No space left on device" in stderr_output:
                raise OSError("No space left on device")
            return None, f"LLC Error: {stderr_output}"

    except OSError as e:
        if "No space left on device" in str(e):
            raise
        return None, str(e)
    except Exception as e:
        return None, str(e)

def process_bc_file(args):
    bc_file, options_dir, output_dir, source_dir, cve_dir_name = args
    successful_objects = []
    total_options = 0
    processed_options = 0
    error_options = 0

    options_files = [f for f in os.listdir(options_dir) if f.endswith(".txt")]
    total_options = len(options_files)

    try:
        with tqdm(total=total_options, desc=f"Processing {bc_file}", leave=False, position=1) as pbar:
            for options_file in options_files:
                with open(os.path.join(options_dir, options_file), "r") as f:
                    cmd = f.read().strip()

                cmd = fix_paths(cmd, source_dir, output_dir, bc_file)
                obj_file, status = compile_to_object(cmd, output_dir, bc_file, source_dir, cve_dir_name)

                if obj_file:
                    successful_objects.append(obj_file)
                    processed_options += 1
                else:
                    error_options += 1

                pbar.update(1)
                pbar.set_postfix({"Processed": processed_options, "Errors": error_options})

    except OSError as e:
        if "No space left on device" in str(e):
            return bc_file, successful_objects, total_options, processed_options, error_options, "Disk Full"
        else:
            raise
    except Exception as e:
        return bc_file, successful_objects, total_options, processed_options, error_options, "Error"

    return bc_file, successful_objects, total_options, processed_options, error_options, "Completed"

def main():
    source_dir = "/root/source"
    output_dir = "/root/output/binaries"
    options_base_dir = "/root/output/outputs/function_hash_iter"

    os.makedirs(output_dir, exist_ok=True)

    error_logs = sorted([f for f in os.listdir() if f.endswith("_No_left_device.txt")])

    bc_files_to_process = []
    if error_logs:
        print("No_left_device.txt files found. Processing only these files.")
        for error_log in error_logs:
            cve_name = error_log.replace("_No_left_device.txt", "")
            bc_file = f"{cve_name}.bc"
            options_dir = os.path.join(options_base_dir, cve_name, "LLC_SUCCESS")
            if os.path.exists(options_dir) and os.path.exists(os.path.join(source_dir, bc_file)):
                bc_files_to_process.append((bc_file, options_dir, output_dir, source_dir, cve_name))
                cve_output_dir = os.path.join(output_dir, sanitize_directory_name(cve_name))
                if os.path.exists(cve_output_dir):
                    shutil.rmtree(cve_output_dir)
    else:
        print("No No_left_device.txt files found. Processing all BC files.")
        # print(f"Source dir: {source_dir}")
        bc_files = sorted([f for f in os.listdir(source_dir) if f.endswith('.bc')])
        print(f"Total BC files found: {len(bc_files)}, {bc_files[:5]}")
        for bc_file in bc_files:
            cve_dir_name = os.path.splitext(bc_file)[0]  # Remove .bc extension
            # print(f"Processing {cve_dir_name}")
            options_dir = os.path.join(options_base_dir, cve_dir_name, "LLC_SUCCESS")

            # print(f"Checking {options_dir}")
            if os.path.exists(options_dir):
                bc_files_to_process.append((bc_file, options_dir, output_dir, source_dir, cve_dir_name))
                for i in range(2, 5):
                    cve_dir_name2 = cve_dir_name + f"{i}"
                    # print(f"Processing {cve_dir_name2}")
                    options_dir = os.path.join(options_base_dir, cve_dir_name2, "LLC_SUCCESS")
                    if os.path.exists(options_dir):
                        # make a copy of the bc file
                        shutil.copyfile(os.path.join(source_dir, bc_file), os.path.join(source_dir, f"{cve_dir_name2}.bc"))

                        bc_files_to_process.append((bc_file, options_dir, output_dir, source_dir, cve_dir_name2))
                    else:
                        break

    all_successful_objects = {}
    completed_folders = set()
    total_bc_files = len(bc_files_to_process)
    total_options = 0
    total_processed = 0
    total_errors = 0
    # print(f'bc_files_to_process: {bc_files_to_process}')
    print(f"Total BC files to process: {total_bc_files}")

    with multiprocessing.Pool() as pool:
        with tqdm(total=total_bc_files, desc="Overall Progress", position=0) as pbar:
            for result in pool.imap_unordered(process_bc_file, bc_files_to_process):
                bc_file, successful_objects, bc_total, bc_processed, bc_errors, status = result
                all_successful_objects[bc_file] = successful_objects
                total_options += bc_total
                total_processed += bc_processed
                total_errors += bc_errors

                pbar.update(1)
                pbar.set_postfix({
                    "Processed": f"{total_processed}/{total_options}",
                    "Errors": total_errors
                })

                cve_name = os.path.splitext(bc_file)[0]
                if status == "Completed":
                    completed_folders.add(cve_name)

                if status == "Disk Full":
                    print(f"\nDisk full error occurred while processing {bc_file}")
                    error_file = f"{sanitize_directory_name(cve_name)}_No_left_device.txt"
                    with open(error_file, "w") as f:
                        f.write(f"Disk space error occurred while processing {bc_file}")
                    print(f"Created error file: {error_file}")
                    cve_output_dir = os.path.join(output_dir, sanitize_directory_name(cve_name))
                    if os.path.exists(cve_output_dir):
                        shutil.rmtree(cve_output_dir)
                    break

    # Write completed folders to binaries_created.txt
    with open(BINARIES_CREATED_FILE, "w") as f:
        for folder in completed_folders:
            f.write(f"{folder}\n")

    # incomplete_folders = set(os.path.splitext(bc)[0] for bc in bc_files_to_process) - completed_folders

    print("\nProcessing summary:")
    print(f"Total BC files: {total_bc_files}")
    print(f"Total options: {total_options}")
    print(f"Processed options: {total_processed}")
    print(f"Error options: {total_errors}")
    print(f"Completed folders: {len(completed_folders)}")
    # print(f"Incomplete folders: {len(incomplete_folders)}")
    # print(f"Incomplete folders: {', '.join(incomplete_folders) if incomplete_folders else 'None'}")

    print(f"\nSuccessfully completed CVEs are listed in {BINARIES_CREATED_FILE}")

if __name__ == "__main__":
    main()
