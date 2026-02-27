#!/usr/bin/env python3
import os
import csv
import re
import argparse
from collections import Counter

def get_exp_type(exp):
    """Categorize exploit based on its name."""
    if "rce" in exp:
        return "CI"
    if "password_disclosure" in exp:
        return "PD"
    if "disclosure" in exp:
        return "LEAK"
    if "auth" in exp:
        return "AUTH"
    return "UNKNOWN"

def parse_targets_list(targets_list_path):
    """Parse the targets.list file to extract BRAND and NAME information."""
    hash_to_info = {}
    try:
        with open(targets_list_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parse the CSV-like format
                parts = line.split(",", 3)
                if len(parts) < 4:
                    continue
                    
                brand = parts[0].strip('"')
                name = parts[1].strip('"')
                hash_value = parts[3].strip()
                
                hash_to_info[hash_value] = {
                    'BRAND': brand,
                    'NAME': name
                }
                
                # Also add the SHA256 directory name as a key if it's numeric
                # This helps with some formats where the directory name is a numeric ID
                if hash_value.isdigit():
                    hash_to_info[hash_value] = {
                        'BRAND': brand,
                        'NAME': name
                    }
    except Exception as e:
        print(f"Warning: Error parsing targets list at {targets_list_path}: {e}")
    
    return hash_to_info

def map_directory_to_brand(dir_name, hash_to_info, source_name):
    """
    Map a directory name to a brand based on source-specific logic.
    Returns brand and name if found, otherwise (UNKNOWN, None).
    """
    # For directories that are numeric IDs (like in fw_res)
    if dir_name.isdigit():
        if dir_name in hash_to_info:
            return hash_to_info[dir_name]['BRAND'], hash_to_info[dir_name]['NAME']
        return "UNKNOWN", None
    
    # For directories that are SHA256 hashes
    if len(dir_name) == 64 and all(c in "0123456789abcdef" for c in dir_name):
        if dir_name in hash_to_info:
            return hash_to_info[dir_name]['BRAND'], hash_to_info[dir_name]['NAME']
    
    # If no mapping is found
    return "UNKNOWN", None

def get_brand_from_exploit(exploit_name):
    """Extract brand information from exploit path if possible."""
    exploit_path = exploit_name.lower()
    
    # Common brand patterns in exploit paths
    brand_patterns = {
        'dlink': ['dlink', 'dir_', 'dcs_'],
        'netgear': ['netgear', 'dgn2200', 'wdr740'],
        'tp-link': ['tp-link', 'tplink'],
        'asus': ['asus', 'asuswrt'],
        'belkin': ['belkin'],
        'zyxel': ['zyxel'],
        'linksys': ['linksys'],
        'trendnet': ['trendnet'],
        'draytek': ['draytek'],
        'miele': ['miele'],
        'xiongmai': ['xiongmai']
    }
    
    for brand, patterns in brand_patterns.items():
        for pattern in patterns:
            if pattern in exploit_path:
                return brand
    
    return "UNKNOWN"

def collect_vulnerabilities(rsf_path, targets_list_path, source_name):
    """Collect vulnerability information from all SHA256 directories."""
    # Parse targets list to get brand and name information
    hash_to_info = parse_targets_list(targets_list_path)
    print(f"Loaded {len(hash_to_info)} entries from targets list")
    
    # Initialize list to store vulnerability data
    vulnerabilities = []
    
    # Initialize counters
    vuln_type_counter = Counter()
    brand_counter = Counter()
    exploit_counter = Counter()
    
    # Check if the rsf_path exists
    if not os.path.exists(rsf_path):
        print(f"Error: RSF path {rsf_path} does not exist")
        return vulnerabilities, vuln_type_counter, brand_counter, exploit_counter
    
    # Iterate through all directories in the RSF_PATH
    dir_count = 0
    vuln_file_count = 0
    
    for sha256_dir in os.listdir(rsf_path):
        dir_path = os.path.join(rsf_path, sha256_dir)
        if not os.path.isdir(dir_path):
            continue
        
        dir_count += 1
        
        # Path to vulnerable.csv file
        vulnerable_csv = os.path.join(dir_path, "vulnerable.csv")
        if not os.path.exists(vulnerable_csv):
            continue
        
        vuln_file_count += 1
        
        # Get brand and name from directory mapping
        dir_brand, dir_name = map_directory_to_brand(sha256_dir, hash_to_info, source_name)
        
        # Read vulnerable.csv file
        try:
            with open(vulnerable_csv, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                # Skip header
                next(reader, None)
                
                for row in reader:
                    if not row or len(row) < 5:
                        continue
                    
                    # Extract information from the row
                    firmware_id = row[0]
                    name = row[1] if row[1] else dir_name
                    exploit_name = row[4]
                    
                    # Extract just the exploit part (after the last slash)
                    exploit_short = exploit_name.split('/')[-1] if '/' in exploit_name else exploit_name
                    exploit_counter[exploit_short] += 1
                    
                    # Try different ways to get the hash
                    hash_value = None
                    
                    # Method 1: Extract hash from firmware_id (format like ID_HASH)
                    hash_match = re.search(r'_([a-f0-9]{64})', firmware_id)
                    if hash_match:
                        hash_value = hash_match.group(1)
                    
                    # Method 2: Use directory name if it's a hash
                    if not hash_value and len(sha256_dir) == 64 and all(c in "0123456789abcdef" for c in sha256_dir):
                        hash_value = sha256_dir
                    
                    # Method 3: Use directory name if it's a numeric ID
                    if not hash_value and sha256_dir.isdigit():
                        hash_value = sha256_dir
                    
                    # Default if all methods fail
                    if not hash_value:
                        hash_value = sha256_dir
                    
                    # Get vulnerability type
                    vuln_type = get_exp_type(exploit_name.lower())
                    if vuln_type != "UNKNOWN":
                        vuln_type_counter[vuln_type] += 1
                    
                    # Try to get brand information in different ways
                    brand = dir_brand
                    product_name = name
                    
                    # If brand is still UNKNOWN, try to extract from hash lookup
                    if brand == "UNKNOWN" and hash_value in hash_to_info:
                        brand = hash_to_info[hash_value]['BRAND']
                        product_name = hash_to_info[hash_value]['NAME'] or product_name
                    
                    # If brand is still UNKNOWN, try to infer from exploit name
                    if brand == "UNKNOWN":
                        brand = get_brand_from_exploit(exploit_name)
                    
                    brand_counter[brand] += 1
                    
                    # Add to vulnerabilities list
                    vulnerabilities.append({
                        'SHA256': sha256_dir,
                        'BRAND': brand,
                        'NAME': product_name if product_name else "",
                        'HASH': hash_value,
                        'EXPLOIT_NAME': exploit_name,
                        'EXPLOIT_SHORT': exploit_short,
                        'VULNERABILITY_TYPE': vuln_type
                    })
        except Exception as e:
            print(f"Error processing {vulnerable_csv}: {e}")
    
    print(f"Processed {dir_count} directories, found {vuln_file_count} vulnerability files")
    return vulnerabilities, vuln_type_counter, brand_counter, exploit_counter

def write_statistics(output_stats, vuln_type_counter, brand_counter, exploit_counter, total_vulns):
    """Write detailed statistics to a file."""
    with open(output_stats, 'w', encoding='utf-8') as f:
        # Write vulnerability type statistics
        f.write("======= VULNERABILITY TYPE STATISTICS =======\n")
        for vuln_type, count in sorted(vuln_type_counter.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_vulns) * 100 if total_vulns > 0 else 0
            f.write(f"{vuln_type}: {count} ({percentage:.1f}%)\n")
        
        # Write brand statistics
        f.write("\n======= BRAND STATISTICS =======\n")
        for brand, count in sorted(brand_counter.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_vulns) * 100 if total_vulns > 0 else 0
            f.write(f"{brand}: {count} ({percentage:.1f}%)\n")
        
        # Write top 20 exploit statistics
        f.write("\n======= TOP 20 EXPLOITS =======\n")
        for exploit, count in sorted(exploit_counter.items(), key=lambda x: x[1], reverse=True)[:20]:
            percentage = (count / total_vulns) * 100 if total_vulns > 0 else 0
            f.write(f"{exploit}: {count} ({percentage:.1f}%)\n")

def main():
    """Main function to execute the collection and reporting process."""
    parser = argparse.ArgumentParser(description='Collect 1-day vulnerability data from different sources')
    parser.add_argument('--rsf_path', required=True, help='Path to the RSF directory containing SHA256 subdirectories')
    parser.add_argument('--targets_list', required=True, help='Path to the targets.list file for brand and name info')
    parser.add_argument('--output_dir', required=True, help='Directory to store output files')
    parser.add_argument('--source_name', required=True, help='Name of the source (e.g., firmae, fw, gh, pandawan)')
    
    args = parser.parse_args()
    
    # Make sure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Define output file paths
    output_csv = os.path.join(args.output_dir, f"{args.source_name}_1day_vulnerabilities.csv")
    output_stats = os.path.join(args.output_dir, f"{args.source_name}_1day_statistics.txt")
    
    print(f"Starting vulnerability data collection for {args.source_name}...")
    print(f"RSF Path: {args.rsf_path}")
    print(f"Targets List: {args.targets_list}")
    print(f"Output Directory: {args.output_dir}")
    
    # Collect vulnerability data
    vulnerabilities, vuln_type_counter, brand_counter, exploit_counter = collect_vulnerabilities(
        args.rsf_path, args.targets_list, args.source_name
    )
    total_vulns = len(vulnerabilities)
    
    if total_vulns == 0:
        print(f"No vulnerabilities found for {args.source_name}")
        return
    
    # Write to CSV file
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['SHA256', 'BRAND', 'NAME', 'HASH', 'EXPLOIT_NAME', 'EXPLOIT_SHORT', 'VULNERABILITY_TYPE'])
        writer.writeheader()
        writer.writerows(vulnerabilities)
    
    # Write statistics to file
    write_statistics(output_stats, vuln_type_counter, brand_counter, exploit_counter, total_vulns)
    
    # Print summary statistics to console
    print(f"\nVulnerability Type Statistics for {args.source_name}:")
    for vuln_type, count in sorted(vuln_type_counter.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_vulns) * 100 if total_vulns > 0 else 0
        print(f"{vuln_type}: {count} ({percentage:.1f}%)")
    
    print(f"\nTotal vulnerabilities found: {total_vulns}")
    print(f"Results saved to {output_csv}")
    print(f"Detailed statistics saved to {output_stats}")

if __name__ == "__main__":
    main() 
