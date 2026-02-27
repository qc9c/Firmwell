#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess
import shutil
import time
import hashlib
import pathlib
from subprocess import PIPE

POTENTIAL_HTTPSERV = ["httpd", "uhttpd", "lighttpd", "jjhttpd", "shttpd", "thttpd","minihttpd", "mini_httpd", \
                    "mini_httpds", "dhttpd", "alphapd", "goahead", "boa", "appweb", "shgw_httpd", \
                    "tenda_httpd", "funjsq_httpd", "webs", "hunt_server", "hydra"]
POTENTIAL_UPNPSERV = ["miniupnpd", "miniupnpc", "mini_upnpd", "miniupnpd_ap", "miniupnpd_wsc", \
                      "upnp", "upnpc", "upnpd", "upnpc-static", "upnprenderer", \
                      "bcmupnp", "wscupnpd", "upnp_app", "upnp_igd", "upnp_tv_devices"]
POTENTIAL_DNSSERV = ["ddnsd", "dnsmasq"]

ARCH_MAP = {"arm": "qemu-arm-static",
            "armeb": "qemu-armeb-static",
            # "arm64": "qemu-aarch64-static",
            # "armeb64": "qemu-aarch64_be-static",
             "x86": "qemu-i386-static",
            "x86_64": "qemu-x86_64-static",
             "mips": "qemu-mips-static",
             "mipsel": "qemu-mipsel-static",
            "ppc": "qemu-ppc-static",
            "mips64": "qemu-mips64-static",
            # "mips64el": "qemu-mips64el-static",
            }

UNIX_DIRS = ["bin", "etc", "dev", "home", "lib", "mnt", "opt", "root",
             "run", "sbin", "tmp", "usr", "var"]
UNIX_THRESHOLD = 4

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            sha256.update(block)
    return sha256.hexdigest()

def get_all_filenames(directory):
    filenames = set()
    for root, dirs, files in os.walk(directory):
        for file in files:
            filenames.add(file)
    return filenames

def lfwc_unpack_success(extracted_path):
    # Check if any subdirectory of extracted_path has any common system dirs
    expected_dirs = {"bin", "var", "www", "etc", "sbin", "boot", "home", "lib", "opt", "root", "src", "usr"}
    for root, dirs, files in os.walk(extracted_path):
        if set(dirs) & expected_dirs:
            return True
    return False


def mksquashfs(output_path, extracted_path):
    
    
    
    cmd = f'cd "{extracted_path}" && mksquashfs . "{output_path}" -noappend'
    print("Running mksquashfs command:", cmd)
    try:
        subprocess.run(cmd, shell=True, check=True)
        print("mksquashfs done")
        return output_path
    except subprocess.CalledProcessError as e:
        print("Error during mksquashfs:", e)
        return ""

def get_arch_from_file_command(outline):
    if b"64-bit" in outline:
        if b" ARM" in outline and b" LSB" in outline:
            return "arm64"
        elif b" x86-64" in outline:
            return "x86_64"
        elif b" MIPS" in outline and b" MSB" in outline:
            return "mips64"
        elif b" MIPS" in outline and b" LSB" in outline:
            return "mips64el"
    else:
        if b" ARM" in outline and b" MSB" in outline:
            return "armeb"
        elif b" ARM" in outline and b" LSB" in outline:
            return "arm"
        elif b" x86-64" in outline:
            return "x86_64"
        elif b" 80386" in outline:
            return "x86"
        elif b" MIPS" in outline and b" MSB" in outline:
            return "mips"
        elif b" MIPS" in outline and b" LSB" in outline:
            return "mipsel"
        # elif b" PowerPC" in outline:
        #     return "ppc"
    return None

def identify_target_folder(self, extracted_path):
    found_fs = ""
    for root, dirs, subdirs in os.walk(extracted_path):
        dirs_sorted = sorted(dirs)
        for d in dirs_sorted:
            # if re.findall("^.*-root[-_0-9]*$", d):
            target_path = os.path.join(root, d)
            for target_root, target_dirs, target_files in os.walk(target_path):
                
                # count number of unix-like directories
                count = 0
                for subdir in os.listdir(target_root):
                    if subdir in UNIX_DIRS and \
                            os.path.isdir(os.path.join(target_root, subdir)) and \
                            len(os.listdir(os.path.join(target_root, subdir))) > 0:
                        count += 1
                
                # check for extracted filesystem, otherwise update queue
                if count <= UNIX_THRESHOLD:
                    continue
                
                for td in sorted(target_dirs):
                    if "bin" in td:
                        binfolder_path = os.path.join(target_root, td)
                        binfolder_path = os.path.realpath(binfolder_path)
                        if not binfolder_path.startswith(extracted_path):
                            continue
                        file_list = [os.path.basename(i) for i in get_all_filenames(target_root)]
                        # if not any(file in POTENTIAL_HTTPSERV for file in file_list):
                        #     continue
                        bin_files = os.listdir(binfolder_path)
                        for f in sorted(bin_files):
                            bin_path = os.path.join(target_root, td, f)
                            for indicator in self.indicators:
                                if bin_path.endswith(indicator):
                                    full_path = str(pathlib.Path(bin_path).resolve())  # handle symlinks
                                    print("Checking arch of binary at ", full_path.replace(target_path, ""))
                                    if not os.path.exists(full_path):
                                        print("    - does not exist, skipping...")
                                        continue
                                    sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
                                    stdout = sp.stdout
                                    stdout = stdout.replace(target_path.encode("u8"), b"")  # handle lfwc path
                                    arch = get_arch_from_file_command(stdout)
                                    print("    - ", f"[{arch}]", stdout)
                                    if arch in ARCH_MAP.keys():
                                        print("    - ", f"Found arch: {arch}")
                                    else:
                                        print("    - ", f"Unrecognized arch: {arch}")
                                    
                                    found_fs = target_root
                                    return found_fs
    
    return found_fs

def unpack_by_fact_extractor(img_path, extracted_path):
    # For demonstration, we reuse a temporary directory for fact extraction.
    fact_extracted = "/tmp/fact_extracted"
    if os.path.exists(fact_extracted):
        shutil.rmtree(fact_extracted)
    # Construct the command for fact_extractor_wrapper.py assumed to be in the same directory.
    fact_script = os.path.join(os.path.dirname(__file__), "fact_extractor_wrapper.py")
    fact_cmd = f'python "{fact_script}" -e -r "{img_path}" "{fact_extracted}"'
    print("Running fact extractor command:", fact_cmd)
    env = os.environ.copy()
    print("Environment:", env)
    # Adjust DOCKER_HOST if in a container environment.
    if "POD_NAME" in env:
        env["DOCKER_HOST"] = "tcp://127.0.0.1:2375"
        print("DOCKER_HOST set to", env["DOCKER_HOST"])
    subprocess.run(fact_cmd, shell=True, env=env)
    return fact_extracted


def binwalk_extract(img_path, extract_dir):
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)
    # Use binwalk for extraction
    binwalk_cmd = ["binwalk", "--preserve-symlinks", "-eMq", "-r", img_path, "-C", extract_dir]
    print("Running binwalk command:", " ".join(binwalk_cmd))
    subprocess.run(binwalk_cmd)
    # Let extraction settle.
    time.sleep(1)
    # Assume extracted folder name is img basename prefixed with "_" and ending with ".extracted"
    image_name = os.path.basename(img_path)
    extracted_name = "_" + image_name + ".extracted"
    extracted_path = os.path.join(extract_dir, extracted_name)
    return extracted_path


def main():
    parser = argparse.ArgumentParser(description="Extract image and build squashfs archive")
    parser.add_argument("--input", required=True, help="Input image file path")
    parser.add_argument("--output", required=True, help="Output squashfs file path")
    args = parser.parse_args()
    
    img_path = os.path.realpath(args.input)
    if not os.path.exists(img_path):
        print("Input file not found:", img_path)
        sys.exit(1)
    
    # Create extraction directory based on input file folder in /tmp.
    sha256hash = compute_sha256(img_path)
    extract_dir = os.path.join("/tmp", "extracted", sha256hash)
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)
    
    # First extraction using binwalk.
    extracted_path = binwalk_extract(img_path, extract_dir)
    
    zip_file = ""
    if os.path.exists(extracted_path) and lfwc_unpack_success(extracted_path):
        print("binwalk unpack success")
        print("Extracted path:", extracted_path)
        zip_file = mksquashfs(args.output, extracted_path)
    else:
        # Use fact extractor if binwalk extraction fails.
        print("binwalk extraction failed, trying fact extractor")
        extracted_path = unpack_by_fact_extractor(img_path, extracted_path)
        if lfwc_unpack_success(extracted_path):
            print("fact unpack success")
            zip_file = mksquashfs(args.output, extracted_path)
        else:
            print("Extraction via fact extractor failed.")
            sys.exit(1)
    
    if zip_file:
        print("Squashfs archive created at:", zip_file)
    else:
        print("Failed to create squashfs archive.")
        sys.exit(1)


if __name__ == "__main__":
    main()