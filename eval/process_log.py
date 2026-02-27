import os
import sys
import csv
from concurrent.futures import ProcessPoolExecutor, as_completed
import pandas as pd

def normalize_brand(brand):
    """Normalize brand names to handle variations"""
    brand = brand.lower()
    if brand in ['tp-link', 'tplink']:
        return 'tplink'
    return brand

def process_firmae_log(log_file_path, rehost_type='http'):
    """FirmAE log processing logic"""
    brand, path_val, name, sha256sum = "", "", "", ""
    extracted = canrun = curlpassed = webpassed = False
    time_taken = 0

    if not os.path.exists(log_file_path):
        print(f"{log_file_path} doesn't exist")
        return None

    try:
        with open(log_file_path, "rb") as bFile:
            for line in bFile:
                try:
                    line = line.decode('utf-8', errors='ignore')
                    if "b'[*] get architecture done!!!" in line:
                        extracted = True
                    if "TARGET HASH" in line:
                        sha256sum = line.split(":", 1)[1].strip()
                    if not curlpassed and "failed to parse trace_path" in line:
                        canrun = False
                    if "Network reachable on" in line:
                        canrun = True
                    if "[http_connected] True" in line:
                        curlpassed = True
                    if rehost_type == 'http' and "[http_wellformed] True" in line:
                        webpassed = True
                    elif rehost_type == 'upnp' and "[upnp_wellformed] True" in line:
                        webpassed = True
                    elif rehost_type == 'dns' and "[dns_wellformed] True" in line:
                        webpassed = True
                    if line.startswith("copying "):
                        path_val = line.split()[1]
                        name = path_val.split("/")[-1]
                        name = name.replace("(", "_").replace(")", "_").replace("-", "_")
                        dirpath = os.path.dirname(path_val)
                    if line.startswith("BRAND: "):
                        brand = normalize_brand(line.split("BRAND: ")[1].strip())
                    if "firmae_duration:" in line:
                        time_str = line.split("firmae_duration:")[1].strip()
                        time_taken = round(float(time_str) / 60)  # Convert seconds to minutes
                except Exception as e:
                    print(f"Error processing line in {log_file_path}: {e}")
                    continue
    except Exception as e:
        print(f"Error opening file {log_file_path}: {e}")
        return None

    return {
        "BRAND": brand,
        "HASH": sha256sum,
        "NAME": name,
        "Unpack": extracted,
        "Execute": canrun,
        "Connect": curlpassed,
        "Web": webpassed,
        "Time": time_taken
    }

def process_gh_log(log_file_path):
    """GreenHouse log processing logic"""
    brand, path_val, name, sha256sum = "", "", "", ""
    extracted = canrun = curlpassed = webpassed = False
    time_taken = 0

    if not os.path.exists(log_file_path):
        print(f"{log_file_path} doesn't exist")
        return None

    try:
        with open(log_file_path, "rb") as bFile:
            for line in bFile:
                try:
                    line = line.decode('utf-8', errors='ignore')
                    if "PATCH LOOP [0]" in line:
                        extracted = True
                    if "TARGET HASH" in line:
                        sha256sum = line.split(":", 1)[1].strip()
                    if "sha256sum:" in line:
                        sha256sum = line.split("sha256sum:")[1].strip()
                    if not curlpassed and "failed to parse trace_path" in line:
                        canrun = False
                    if "parse completed!" in line or "[GreenHouseQEMU] IP" in line or curlpassed:
                        canrun = True
                    if "[connected]: True" in line:
                        curlpassed = True
                    if "[wellformed]: True" in line:
                        webpassed = True
                    if line.startswith("copying "):
                        path_val = line.split()[1]
                        name = path_val.split("/")[-1]
                        name = name.replace("(", "_").replace(")", "_").replace("-", "_")
                        dirpath = os.path.dirname(path_val)
                    if line.startswith("BRAND: "):
                        brand = normalize_brand(line.split("BRAND: ")[1].strip())
                    if "[GREENHOUSE] TIME TAKEN =" in line:
                        time_str = line.split("=")[1].strip().split()[0]
                        time_taken = round(float(time_str))
                    if "! REHOST TIMEDOUT !" in line:
                        time_taken = 720  # 12 hours in minutes
                except Exception as e:
                    print(f"Error processing line in {log_file_path}: {e}")
                    continue
    except Exception as e:
        print(f"Error opening file {log_file_path}: {e}")
        return None

    return {
        "BRAND": brand,
        "HASH": sha256sum,
        "NAME": name,
        "Unpack": extracted,
        "Execute": canrun,
        "Connect": curlpassed,
        "Web": webpassed,
        "Time": time_taken
    }

def process_fw_log(log_file_path, rehost_type='http'):
    """Firmware log processing logic"""
    brand, name, sha256sum = "", "", ""
    extracted = canrun = curlpassed = webpassed = False
    time_taken = 0

    if not os.path.exists(log_file_path):
        print(f"{log_file_path} doesn't exist")
        return None

    try:
        with open(log_file_path, "rb") as bFile:
            for line in bFile:
                try:
                    line = line.decode('utf-8', errors='ignore')
                    # if "[UNPACK SUCCESS]" in line:
                    #     extracted = True
                    if "[FIRNWELL] RUNNING" in line:
                        extracted = True
                    if "TARGET HASH" in line:
                        sha256sum = line.split(":", 1)[1].strip()
                    if not curlpassed and "failed to parse trace_path" in line:
                        canrun = False
                    if "parse completed!" in line or "[GreenHouseQEMU] IP" in line or curlpassed:
                        canrun = True
                    if "[connected]: True" in line:
                        curlpassed = True
                    if rehost_type == 'http' and "[wellformed]: True" in line:
                        webpassed = True
                    if rehost_type == 'upnp' and "upnp_wellformed True" in line:
                        webpassed = True
                    if rehost_type == 'dns' and "dns_wellformed True" in line:
                        webpassed = True
                    if line.startswith("[FIRMWARE NAME]"):
                        name = line.replace("[FIRMWARE NAME]", "").strip()
                    if line.startswith("    - target firmware brand:"):
                        brand = normalize_brand(line.split("    - target firmware brand:")[1].strip())
                    if "[FIRMWELL] TIME TAKEN =" in line:
                        time_str = line.split("=")[1].strip().split()[0]
                        time_taken = round(float(time_str))
                except Exception as e:
                    print(f"Error processing line in {log_file_path}: {e}")
                    continue
    except Exception as e:
        print(f"Error opening file {log_file_path}: {e}")
        return None

    return {
        "BRAND": brand,
        "HASH": sha256sum,
        "NAME": name,
        "Unpack": extracted,
        "Execute": canrun,
        "Connect": curlpassed,
        "Web": webpassed,
        "Time": time_taken
    }

def process_pandawan_log(log_file_path, rehost_type='http'):
    """Pandawan log processing logic"""
    brand, name, sha256sum = "", "", ""
    extracted = canrun = curlpassed = webpassed = False
    time_taken = 0

    if not os.path.exists(log_file_path):
        print(f"{log_file_path} doesn't exist")
        return None

    # Get the base directory and filename
    base_dir = os.path.dirname(os.path.dirname(log_file_path))
    base_name = os.path.basename(log_file_path)
    
    probe_log_path = log_file_path
    time_log_path = os.path.join(base_dir, 'logs', base_name)

    try:
        with open(probe_log_path, "rb") as bFile:
            for line in bFile:
                try:
                    if b"[\033[32m+\033[0m] Network reachable on" in line:
                        canrun = True
                    
                    line = line.decode('utf-8', errors='ignore')
                    if "[*] get architecture done!!!" in line:
                        extracted = True
                    # if not curlpassed and "failed to parse trace_path" in line:
                    #     canrun = False
                    if " Network reachable on " in line:
                        canrun = True
                    if "[http_connected] True" in line:
                        curlpassed = True
                    if rehost_type == 'http' and "[http_wellformed] True" in line:
                        webpassed = True
                    elif rehost_type == 'upnp' and "[upnp_wellformed] True" in line:
                        webpassed = True
                    elif rehost_type == 'dns' and "[dns_wellformed] True" in line:
                        webpassed = True
                    if line.startswith("BRAND: "):
                        brand = normalize_brand(line.split("BRAND: ")[1].strip())
                    if line.startswith("NAME: "):
                        name = line.split("NAME: ")[1].strip()
                    if line.startswith("SHA256 "):
                        sha256sum = line.split("SHA256 ")[1].strip()
                except Exception as e:
                    print(f"Error processing line in {probe_log_path}: {e}")
                    continue

        # Process logs for time information
        if os.path.exists(time_log_path):
            with open(time_log_path, "rb") as bFile:
                for line in bFile:
                    try:
                        line = line.decode('utf-8', errors='ignore')
                        if "PANDAWAN COMPLETE: 130" in line:
                            time_taken = 720
                            break
                        elif "Running Pandawan preprocess:" in line:
                            time_str = line.split(":")[1].strip()
                            time_taken = round(float(time_str) / 60)
                            break
                    except Exception as e:
                        print(f"Error processing line in {time_log_path}: {e}")
                        continue
    except Exception as e:
        print(f"Error processing logs: {e}")
        return None

    return {
        "BRAND": brand,
        "HASH": sha256sum,
        "NAME": name,
        "Unpack": extracted,
        "Execute": canrun,
        "Connect": curlpassed,
        "Web": webpassed,
        "Time": time_taken
    }

def process_file(log_file, processor_type, rehost_type):
    """Process a single log file based on processor type"""
    if processor_type == 'firmae':
        return process_firmae_log(log_file, rehost_type)
    elif processor_type == 'gh':
        return process_gh_log(log_file)
    elif processor_type == 'fw':
        return process_fw_log(log_file, rehost_type)
    elif processor_type == 'pd':
        return process_pandawan_log(log_file, rehost_type)
    return None

def process_logs(logs_directory, output_csv_path, processor_type, rehost_type):
    """Process logs based on the specified processor type"""
    if processor_type not in ['firmae', 'gh', 'fw', 'pd']:
        print(f"Invalid processor type: {processor_type}")
        return

    log_files = [os.path.join(logs_directory, f)
                 for f in os.listdir(logs_directory)
                 if os.path.isfile(os.path.join(logs_directory, f))]

    results = []
    with ProcessPoolExecutor() as executor:
    # Create futures with process_file function and necessary arguments
        futures = [executor.submit(process_file, log_file, processor_type, rehost_type) 
                  for log_file in log_files]
        
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    # Write results to CSV
    fieldnames = ["BRAND", "HASH", "NAME", "Unpack", "Execute", "Connect", "Web", "Time"]
    with open(output_csv_path, mode='w', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for res in results:
            writer.writerow(res)

    print(f"Results have been written to {output_csv_path}")

    # Calculate and print statistics
    stats = {key: sum(1 for res in results if res[key] == True)
            for key in ['Unpack', 'Execute', 'Connect', 'Web']}
    
    for key, value in stats.items():
        print(f"Total {key}: {value}")

def read_targets_list(targets_file_path='/shared/targets.list'):
    """Read targets.list file and return list of SHA256 hashes"""
    targets_data = []
    try:
        with open(targets_file_path, 'r') as f:
            csv_reader = csv.reader(f)
            for row in csv_reader:
                if row:  # Ensure row is not empty
                    sha256sum = row[-1]  # Assume SHA256 is in the last column
                    targets_data.append(sha256sum)
    except Exception as e:
        print(f"Error reading targets file: {e}")
        return []
    return targets_data

def write_results_in_order(output_file, results_dict, target_hashes):
    """
    Write results to CSV file in the order specified by targets.list
    
    Args:
        output_file: Path to output CSV file
        results_dict: Dictionary of results keyed by hash
        target_hashes: List of hashes in desired order
    """
    if not results_dict:
        print("No results to write")
        return

    fieldnames = ["BRAND", "HASH", "NAME", "Unpack", "Execute", "Connect", "Web", "Time"]
    missing_count = 0
    
    try:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for index, hash_value in enumerate(target_hashes):
                if hash_value in results_dict:
                    writer.writerow(results_dict[hash_value])
                else:
                    # Write empty row with hash value
                    # print(f"Hash {hash_value} not found in results, line index: {index}")
                    missing_count += 1
                    empty_row = {field: '' for field in fieldnames}
                    empty_row['HASH'] = hash_value
                    writer.writerow(empty_row)
            
            print(f"Total missing hashes: {missing_count}")
    except Exception as e:
        print(f"Error writing results: {e}")

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: python http_log_process.py <path-to-log-folder> <processor-type> --rehost_type <type> [--output <output-path>]")
        print("Processor types: firmae, gh, fw, pd")
        print("Rehost types: http, upnp, dns") 
        sys.exit(1)

    logs_directory = sys.argv[1]
    processor_type = sys.argv[2].lower().replace('--', '')
    
    if sys.argv[3] != '--rehost_type':
        print("Error: Missing --rehost_type argument")
        sys.exit(1)

    rehost_type = sys.argv[4].lower()
    if rehost_type not in ['http', 'upnp', 'dns']:
        print("Error: Invalid rehost type. Must be one of: http, upnp, dns")
        sys.exit(1)

    if not os.path.exists(logs_directory):
        print(f"{logs_directory} doesn't exist")
        sys.exit(1)

    # Create default output directory
    default_path = "rehost_res"
    os.makedirs(default_path, exist_ok=True)

    # Check for optional output path
    output_csv_path = None
    for i in range(5, len(sys.argv)-1):
        if sys.argv[i] == '--output':
            output_csv_path = sys.argv[i+1]
            # Create output directory if needed
            os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
            break
    
    # Use default path if no custom path specified
    if output_csv_path is None:
        output_csv_path = os.path.join(default_path, f"{processor_type}_{rehost_type}_rehost.csv")

    # Process logs and get results
    process_logs(logs_directory, output_csv_path, processor_type, rehost_type)

    # Read targets list
    target_hashes = read_targets_list()
    
    # Read the generated CSV file
    results_dict = {}
    try:
        with open(output_csv_path, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                results_dict[row['HASH']] = row
    except Exception as e:
        print(f"Error reading results CSV: {e}")
        sys.exit(1)

    
    print(len(results_dict))
    print(len(target_hashes))
    
    # Find results that are not in target_hashes
    missing_results = set(results_dict.keys()) - set(target_hashes)
    print(f"Results not in target_hashes: {len(missing_results)}")
    for hash_id in missing_results:
        print(f"Missing hash: {hash_id}")
    
    # Rewrite the CSV file in order
    write_results_in_order(output_csv_path, results_dict, target_hashes)

