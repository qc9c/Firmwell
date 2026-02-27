import os
import re
import json
import random
import string
import logging
import subprocess
import time
from collections import defaultdict
from pprint import pprint
import pathlib
from firmwell.backend.utils.NetworkUtil import NetworkUtil
from firmwell.backend.call_chain_utils.GhidraTool import GhidraTool

logger = logging.getLogger(__name__)

WEB_EXTS = ["html", "htm", "xhtm", "jhtm", "cgi", "xml", "js", "wss", "php", "php4", "php3", "phtml", \
            "rss", "svg", "dll", "asp", "aspx", "axd", "asx", "asmx", "ashx", "cfm", "swf", "stm"]
BACKUP_TAGS = ["bak", "bak2", "bkup"]
HOSTS = {
    "belkin": ["router"],
    "netgear": ["www.mywifiext.net", "www.routerlogin.net"],
    "tenda": ["tendawifi.com"],
    "tplink": ["tplinkrepeater.net"]
}

def check_ip_domain_mapping(ip, domain, file_path):
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split()
            if ip in parts and domain in parts:
                return True
    return False

def add_ip_domain_mapping(ip, domain, file_path):
    with open(file_path, 'a') as file:
        file.write(f"{ip} {domain}\n")


class FixStrategy:
    """
    Base class for implementing error fix strategies.
    
    Provides common utilities and interfaces for fixing different types of errors.
    """
    
    def __init__(self, brand, binary, fs_path, filesystem, env, fix_record,
                 nvram_brand_map, nvram_map,
                 cwd = "/",
                 restart_env=False,
                 enable_create=True,
                 enable_resue=True,
                 enable_fix_in_peer=True,
                 enable_infer=True,
                 enable_enhance_create=True,
                 fix_round=None):
        """
        Initialize with filesystem and docker manager.
        
        Args:
            filesystem: FileSystem object for accessing firmware filesystem
            env: DockerManager object for interacting with Docker container
        """
        self.brand = brand
        self.binary = binary
        self.filesystem = filesystem
        self.fs_path = fs_path
        self.env = env
        self.fix_record = fix_record
        self.nvram_brand_map = nvram_brand_map
        self.nvram_map = nvram_map
        self.restart_env = restart_env
        self.fix_round = fix_round
        self.cwd = cwd
        
        # ablation flag
        self.enable_create = enable_create
        self.enable_resue = enable_resue
        self.enable_fix_in_peer = enable_fix_in_peer
        self.enable_infer = enable_infer
        self.enable_enhance_create = enable_enhance_create        
    
    def apply_fix(self, error):
        """
        Apply the appropriate fix strategy based on the error category.
        
        Args:
            error (dict): Error information
            
        Returns:
            bool: True if fix applied successfully, False otherwise
        """
        category = error.get("category", "")
        description = error.get("description", "")
        fix_strategy = error.get("fix_strategy", "")

        logger.info(f"Applying fix for {category}/{description} using strategy {fix_strategy}")

        # Map fix strategies to methods
        strategy_map = {
            # CREATE strategies
            "create_network_device": self.create_network_device,
            "create_system_file": self.create_system_file,

            # INFER strategies
            "infer_nvram_value": self.infer_nvram_value,
            "fill_ioctl_content": self.fill_ioctl_content,
            "fill_random_content": self.fill_random_content,
            "fill_file_content": self.fill_file_content,

            # REUSE strategies
            "reuse_file": self.reuse_file,

            # FIX-IN-PEER strategies is implemented in Rehosting.py
        }

        if fix_strategy in strategy_map:
            try:
                print(f"\n\nApplying fix strategy: {fix_strategy}")
                
                return strategy_map[fix_strategy](error)
            
            
            except Exception as e:
                logger.error(f"Error applying fix strategy {fix_strategy}: {e}")
                exit(1)

        logger.warning(f"No implementation found for fix strategy: {fix_strategy}")
        return False
    
    
    def set_hosts(self):
        domain = []
        if self.brand in HOSTS:
            domain = HOSTS[self.brand]
        if len(domain) == 0:
            return
        
        # set hosts
        hosts = []
        with open("/etc/hosts", 'r') as f:
            for line in f:
                hosts.append(line.split(" "))
        
        if len(domain) > 0:
            try:
                curr_ips = [i[0] for i in self.network_info.values()]
                for ip in curr_ips:
                    for d in domain:
                        if not check_ip_domain_mapping(ip, d, "/etc/hosts"):
                            add_ip_domain_mapping(ip, d, "/etc/hosts")
            except Exception as e:
                print("error set_hosts", e)
    
    def _extract_original_syscall(self, error):
        """
        Extract original syscall text from error object regardless of structure.
        
        Args:
            error (dict): Error information that might contain original syscall text
            
        Returns:
            str: Original syscall text if found, empty string otherwise
        """
        if not error:
            return ""
            
        # Check if syscalls is a list with original_syscall
        syscalls = error.get("syscalls", [])
        if isinstance(syscalls, list) and len(syscalls) > 0:
            if isinstance(syscalls[0], dict) and "original_syscall" in syscalls[0]:
                return syscalls[0]["original_syscall"]
            # Try to find first syscall with original_syscall
            for syscall in syscalls:
                if isinstance(syscall, dict) and "original_syscall" in syscall:
                    return syscall["original_syscall"]
        
        # Check if it's a single syscall with original_syscall
        if isinstance(error.get("syscalls", {}), dict) and "original_syscall" in error["syscalls"]:
            return error["syscalls"]["original_syscall"]
            
        # Try direct access, some errors might have it at top level
        if "original_syscall" in error:
            return error["original_syscall"]
            
        # Log that we couldn't find it
        logger.debug(f"Could not extract original syscall from error: {error.get('category')}/{error.get('description')}")
        return ""

    def create_network_device(self, error):
        """
        Create missing network devices or configure existing ones with proper IP addresses.
        
        Args:
            error (dict): Network error information containing either:
                - miss_interfaces: Set of missing interface names
                - ip_address: IP address to assign
                
        Returns:
            bool: True if successful, False otherwise
        """
        # Get interfaces set and IP address from error
        interfaces = error.get('miss_interfaces', set())
        if interfaces and not isinstance(interfaces, set):
            # Convert to set if it's not already (handle single device name)
            interfaces = {interfaces}

        ip_address = error.get('ip_address')
        
        logger.info(f"Creating/configuring network device: interfaces={interfaces}, ip={ip_address}")
        
        if ip_address == "0.0.0.0":
            ip_address = None
        
        # Skip loopback interface
        if interfaces and "lo" in interfaces:
            interfaces.remove("lo")
            
        # Exit if no interfaces and no IP to configure
        if not interfaces and not ip_address:
            logger.warning("No network interfaces or IP address specified in error")
            return False
        
        # Record the original syscall for logging
        original_syscall = self._extract_original_syscall(error)
        success = False
        
        # If we have interfaces, create/configure each one
        if interfaces:
            for device_name in interfaces:
                # If we have a specific IP, use it, otherwise let NetworkUtil generate one
                target_ip = ip_address
                
                # Generate an IP if none provided
                if not target_ip:
                    if device_name == "br0":
                        target_ip = "192.168.0.1"
                    else:
                        # Find an unused IP in a different subnet from existing devices
                        current_network_info = self.env.network.get_network_info()
                        used_subnets = set()
                        for ips in current_network_info.values():
                            for ip in ips:
                                # Extract subnet (first 3 octets)
                                subnet = '.'.join(ip.split('.')[0:3])
                                used_subnets.add(subnet)
                        
                        # Find an available subnet
                        for i in range(1, 255):
                            subnet = f"192.168.{i}"
                            if subnet not in used_subnets:
                                target_ip = f"{subnet}.1"
                                break
                    
                    # If still no IP, use a default
                    if not target_ip:
                        target_ip = "192.168.100.1"
                
                # Use NetworkUtil to create the device
                if hasattr(self.env, 'network') and hasattr(self.env.network, 'create_network_device'):
                    result = self.env.network.create_network_device(device_name, target_ip)
                    if result:
                        success = True
                        # Record the fix
                        self.fix_record.add_fix_record(self.binary, {
                            "create_network_device": {
                                "device": device_name,
                                "ip": target_ip,
                                "action": "create_via_network_util",
                                "original_syscall": original_syscall
                            }
                        },
                        round_num=self.fix_round
                        )
                        logger.info(f"Successfully created network device {device_name} with IP {target_ip}")

        # Update network information if any operation was successful
        if success:
            self.network_info = self.env.network.get_network_info()
            logger.debug(f"Updated network info: {self.network_info}")
            self.set_hosts()
        
        return success

    def create_system_file(self, error):
        """
        Create missing system files (/proc, /sys, /dev) in the emulation environment.

        Args:
            error (dict): Error information containing the missing file path.

        Returns:
            bool: True if the file was created successfully, False otherwise.
        """
        
        file = error.get("path", "")
        original_syscall = self._extract_original_syscall(error)
        

        if file.startswith("/dev"):
            self.create_empty_file(file)
            self.fix_record.add_fix_record(self.binary, {
                "create_system_file": {
                    "path": file,
                    "original_syscall": original_syscall
                }
            },
            round_num=self.fix_round
            )
            return True
        elif file.startswith("/proc"):
            file = file.replace("/proc", "/ghproc", 1)
            self.create_empty_file(file)
            self.fix_record.add_fix_record(self.binary, {
                "create_system_file": {
                    "path": file,
                    "original_syscall": original_syscall
                }
            },
            round_num=self.fix_round
            )
            return True
        elif file.startswith("/sys"):
            file = file.replace("/proc", "/ghsys", 1)
            self.create_empty_file(file)
            self.fix_record.add_fix_record(self.binary, {
                "create_system_file": {
                    "path": file,
                    "original_syscall": original_syscall
                }
            },
            round_num=self.fix_round
            )
            return True
        
        return False
    
    # INFER strategies
    
    def _initialize_nvram_analyzer(self):
        # Extract firm_name from binary path or use a default
        if hasattr(self, 'binary') and self.binary:
            self.firm_name = os.path.splitext(os.path.basename(self.binary))[0]
        else:
            self.firm_name = "unknown_firmware"
            
        # Ghidra configuration - same as CallChainConstructor
        self.HEADLESS_ANALYZER = "/ghidra_11.2_PUBLIC/support/analyzeHeadless"
        self.GHIDRA_NVRAM_SCRIPT = "/fw/firmwell/backend/call_chain_utils/nvram_extract.py"
        
        # Setup project paths for NVRAM analysis
        firm_dir = os.path.join("/tmp", self.firm_name)
        self.ghidra_nvram_proj_path = os.path.join(firm_dir, "ghidra_nvram_project")
        if not os.path.exists(self.ghidra_nvram_proj_path):
            os.makedirs(self.ghidra_nvram_proj_path)
        
        self.ghidra_nvram_result_path = os.path.join(firm_dir, "ghidra_nvram_result")
        if not os.path.exists(self.ghidra_nvram_result_path):
            os.makedirs(self.ghidra_nvram_result_path)
    
    def run_ghidra_nvram_analysis(self, binary_path: str):
        logger.info(f"Running Ghidra NVRAM analysis on: {os.path.basename(binary_path)}")
        
        ghidra_tool = GhidraTool(project_path=self.ghidra_nvram_proj_path,
                                 project_name=self.firm_name,
                                 result_path=self.ghidra_nvram_result_path,
                                 ghidra_script=self.GHIDRA_NVRAM_SCRIPT,
                                 headless_analyzer=self.HEADLESS_ANALYZER)

        try:
            # For nvram analysis, we pass the result_path as target_str 
            # since nvram_extract.py expects result_path as first argument
            ghidra_tool.run(binary_path, self.ghidra_nvram_result_path)
            logger.info(f"Ghidra NVRAM analysis completed for: {os.path.basename(binary_path)}")
        except Exception as e:
            logger.error(f"Ghidra NVRAM analysis failed for {binary_path}: {e}")
            raise
        finally:
            ghidra_tool.stop_ghidra_process()
    
    def get_nvram_data_from_ghidra_result(self, binary_path: str):
        binary_name = os.path.basename(binary_path)
        result_file = os.path.join(self.ghidra_nvram_result_path, binary_name + "_nvram.json")
        
        if not os.path.exists(result_file):
            logger.warning(f"NVRAM result file not found: {result_file}")
            return {}
        
        try:
            with open(result_file, 'r') as f:
                nvram_data = json.load(f)
            
            # Convert from key -> [multiple_values] to key -> first_value format
            simplified_nvram_data = {}
            for key, values in nvram_data.items():
                if values and len(values) > 0:
                    # Take the first value as requested
                    simplified_nvram_data[key] = values[0]
                    logger.debug(f"NVRAM from Ghidra: {key} = {values[0]} (from {len(values)} possible values)")
            
            logger.info(f"NVRAM analysis extracted {len(simplified_nvram_data)} key-value pairs from {binary_name}")
            return simplified_nvram_data
            
        except Exception as e:
            logger.error(f"Error reading NVRAM result file {result_file}: {e}")
            return {}
    
    def analyze_binary_for_nvram(self, binary_path: str):
        self._initialize_nvram_analyzer()
        
        if not os.path.exists(binary_path):
            logger.error(f"Binary file not found: {binary_path}")
            return {}
        
        logger.info(f"Starting NVRAM analysis for: {os.path.basename(binary_path)}")
        
        try:
            # Run Ghidra analysis
            self.run_ghidra_nvram_analysis(binary_path)
            
            # Get and process results
            nvram_data = self.get_nvram_data_from_ghidra_result(binary_path)
            
            logger.info(f"NVRAM analysis completed. Found {len(nvram_data)} key-value pairs.")
            return nvram_data
            
        except Exception as e:
            logger.error(f"NVRAM analysis failed for {binary_path}: {e}")
            return {}
    
    def infer_nvram_value(self, error):
        nvram_list = error["miss_nvrams"]
        
        # Build commands for all NVRAM values
        nvram_commands = []
        for path in nvram_list:
            key = os.path.basename(path)
            
            if key in self.nvram_brand_map.keys():
                value = self.nvram_brand_map[key]
            elif key in self.nvram_map.keys():
                value = self.nvram_map[key]
            else:
                # If key is purely numeric, set value to 1, apmib_get
                if key.isdigit():
                    value = "1"
                else:
                    value = ""
            
            if len(value) > 0:
                nvram_commands.append(f'echo -n {value} > /fs/gh_nvram/{key}')
            else:
                nvram_commands.append(f'echo -n > /fs/gh_nvram/{key}')
            
            self.fix_record.add_fix_record(self.binary, {
                "infer_nvram_value": {
                    "key": key,
                    "value": value,
                }
            },
            round_num=self.fix_round
            )
        
        # Execute all NVRAM commands in a single shell command
        if nvram_commands:
            cmd = f'sh -c "{";".join(nvram_commands)}"'
            self.env.exec_run_lock(cmd)
        return True
    
    def fill_ioctl_content(self, error):
        op = int(error.get("op", ""), 16)
        
        ops = set()
        ops.add(str(op))
        if os.path.exists(os.path.join(self.fs_path, "hackioctl")):
            with open(os.path.join(self.fs_path, "hackioctl"), 'r') as f:
                for line in f:
                  ops.add(line.strip())
                  
        with open(os.path.join(self.fs_path, "hackioctl"), 'a') as f:
            for op in ops:
                f.write(op + "\n")
                
        self.env.docker_cp_to_container(os.path.join(self.fs_path, "hackioctl"), "/fs/hackioctl")
    
    
    def fill_random_content(self, error):
        """Fill file with random content."""
        path = error.get("path", "")
        if not path:
            return False
        
        original_syscall = self._extract_original_syscall(error)
        
        # Generate random content
        content = ''.join(random.choices(string.ascii_letters + string.digits, k=1024))
        
        # Write content to file
        cmd = f'bash -c "echo -n {content} > /fs{path}"'
        self.env.exec(cmd)
        
        self.fix_record.add_fix_record(
            self.binary,
            {
                "fill_random_content": {
                    "path": path,
                    "content_length": len(content),
                    "original_syscall": original_syscall
                }
            },
            round_num=self.fix_round
        )
        
        return True
    
    def infer_magic_bytes(self, binary_path, error, trace_file_path):
        """
        Use symbolic execution to infer the correct content for a file.
        """

        
        # Define paths for symbolic execution
        sym_infer_script = os.path.join(os.path.dirname(__file__), 'sym_main.py')
        output_dir = "/tmp/sym_infer_output"
        os.makedirs(output_dir, exist_ok=True)
        output_json = os.path.join(output_dir, "solution.json")

        # Construct command with resource limits
        # ulimit -v sets virtual memory limit in KB (2GB = 2097152 KB)
        # ulimit -t sets CPU time limit in seconds (1200s = 20 minutes)
        py_cmd = [
            '/root/venv/bin/python', sym_infer_script,
            '--main-binary', binary_path,
            '--fs-path', self.fs_path,
            '--trace-file', trace_file_path,
            '--error-file', error.get("path"),
            '--output-dir', output_dir
        ]
        cmd = [
            'bash', '-c',
            f"ulimit -v 2097152 && ulimit -t 1200 && exec {' '.join(py_cmd)}"
        ]
        
        print(f"Running symbolic execution: {' '.join(cmd)}")
        
        try:
            # The timeout for subprocess.run should be slightly longer than ulimit -t
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
            
            if result.returncode == 0:
                if os.path.exists(output_json):
                    with open(output_json, 'r') as f:
                        solution_data = json.load(f)
                    
                    content = solution_data.get("solution", "")
                    error_file = solution_data.get("error_file", "")

                    if content and error_file:
                        print("infer content", content)
                        
                        # Write the inferred content to the target file in the container
                        container_path = f"/fs{error_file}"
                        
                        if "/proc" in container_path:
                            container_path = container_path.replace("/proc", "/ghproc", 1)
                        elif "/sys" in container_path:
                            container_path = container_path.replace("/sys", "/ghsys", 1)
                        # Use a temporary file to handle content with special characters
                        with open("/tmp/sym_content.tmp", "w") as tmp_f:
                            tmp_f.write(content)
                            
                        with open("/tmp/sym_content.tmp", "r") as tmp_f:
                            print("/tmp/sym_content.tmp content:", tmp_f.read())
                        self.env.exec(f"rm -f {container_path}")  # Remove existing file if it exists
                        
                        # Copy file and verify success
                        try:
                            self.env.docker_cp_to_container("/tmp/sym_content.tmp", container_path)
                            
                            # Verify the file was copied successfully
                            verify_result = self.env.exec(f"test -f {container_path} && echo 'exists' || echo 'missing'")
                            if "missing" in verify_result:
                                print(f"Failed to copy file to {container_path}")
                                return False
                            
                            container_content = self.env.exec(f"cat {container_path}")
                            print(f"Content written to {container_path} in container: {container_content}")
                            
                        except Exception as e:
                            print(f"Error copying file to container: {e}")
                            return False
                        finally:
                            # Clean up temporary file
                            if os.path.exists("/tmp/sym_content.tmp"):
                                os.remove("/tmp/sym_content.tmp")
                                
                        
                        print(f"Successfully fixed {error_file} with content from symbolic execution.")
                        self.fix_record.add_fix_record(self.binary, {
                            "infer_magic_bytes": {
                                "path": error_file,
                                "inferred_content_length": len(content)
                            }
                        }, round_num=self.fix_round)
                        return True
                else:
                    print(f"Symbolic execution succeeded but output file not found: {output_json}")
            else:
                print(f"Symbolic execution failed. Return code: {result.returncode}")
                print(f"Stderr: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("Symbolic execution timed out after 20 minutes.")
        except Exception as e:
            print(f"An exception occurred during symbolic execution: {e}")
            
        return False
        
    def reuse_file(self, error):
        """Locate and reuse an existing file."""
        path = error.get("path", "")
        paths = error.get("paths", [])
        file_paths = error.get("file_paths", [])
        description = error.get("description")
        original_syscall = self._extract_original_syscall(error)

        # Handle batch template reuse case
        if description == "reuse_template" and paths and file_paths:
            success = True
            for dst_path, src_path in zip(paths, file_paths):
                # Create target directory
                target_dir = os.path.dirname(dst_path)
                self.env.exec(f"mkdir -p /fs{target_dir}")
                
                # Copy template file to target path
                self.env.docker_cp_to_container(src_path, f"/fs{dst_path}")
                
                # For .pem files, also copy to /fs/etc and /fs/tmp/etc
                if dst_path.endswith('.pem'):
                    self.env.exec("mkdir -p /fs/etc /fs/tmp/etc")
                    self.env.docker_cp_to_container(src_path, f"/fs/etc/{os.path.basename(dst_path)}")
                    self.env.docker_cp_to_container(src_path, f"/fs/tmp/etc/{os.path.basename(dst_path)}")
                
                # Record the fix
                self.fix_record.add_fix_record(self.binary, {
                    "reuse_template": {
                        "target": dst_path,
                        "source": src_path,
                        "original_syscall": original_syscall
                    }
                },
                round_num=self.fix_round
                )
            return success

        # Original logic for single file processing
        if not path:
            return False
        
        if description == "reuse_cwd":
            return self.reuse_cwd(error)
        elif description == "reuse_directory":
            return self.reuse_directory(error)
        elif description == "reuse_template":
            return self.reuse_template(error)
        elif description == "reuse_so_files":
            # Handle special case for .so files
            source_dir = error.get("source_dir", "")
            target_dir = error.get("target_dir", "")
            
            if not source_dir or not target_dir:
                logger.warning("Missing source_dir or target_dir for reuse_so_files")
                return False
                
            # Create target directory if it doesn't exist
            self.env.exec(f"mkdir -p /fs{target_dir}")
            
            # Copy all .so files from source directory to target directory
            self.env.exec(f'sh -c "cp -r /fs{source_dir}/*.so /fs{target_dir}/"')
            
            # Record the fix
            self.fix_record.add_fix_record(self.binary, {
                "reuse_so_files": {
                    "target_dir": target_dir,
                    "source_dir": source_dir,
                    "original_syscall": original_syscall
                }
            },
            round_num=self.fix_round
            )
            
            return True
        else: # reuse file
            src_path = error['file_path']
            # Copy file to target location
            
            if "www.satellite" in src_path: # copy all files in once
                src_dir = os.path.dirname(src_path)
                dst_dir = os.path.dirname(path)

                self.env.exec(f"mkdir -p /fs{dst_dir}")
                self.env.exec(f'sh -c "cp -r /fs/{src_dir}/* /fs{dst_dir}/"')
                
                self.fix_record.add_fix_record(self.binary, {
                    "reuse_directory": {
                        "target_dir": path,
                        "source_dir": src_path,
                        "original_syscall": original_syscall
                    }
                },
                round_num=self.fix_round
                )
                
                return True
            
            cmd = f'cp /fs{src_path} /fs{path}'
            self.env.exec(cmd)
            
            self.fix_record.add_fix_record(self.binary, {
                "reuse_file": {
                    "path": path,
                    "source_path": src_path,
                    "original_syscall": original_syscall
                }
            },
            round_num=self.fix_round
            )
        
        return True

    
    def fix_in_peer_process(self, error):
        """Fix error in peer process."""
        raise NotImplementedError()
    
    def create_empty_str_file(self, path):
        """Create a file with a default value of '1' at the given path (used for NVRAM keys)."""
        dirname = os.path.dirname(path)
        cmd = f'bash -c \"mkdir -p /fs{dirname} && echo 1 > /fs{path}\"'
        self.env.exec(cmd, detach=True)
    
    def create_empty_file(self, path):
        """Create an empty file at the given path inside the emulated filesystem."""
        dirname = os.path.dirname(path)
        filename = os.path.basename(path)
        dirname = str(pathlib.Path(os.path.join(self.fs_path, self.filesystem.get_rel_path(dirname))).resolve())
        dirname = dirname.replace(self.fs_path, "")
        cmd = f'bash -c \"mkdir -p /fs{dirname} && rm -f /fs{dirname}/{filename} && touch /fs{dirname}/{filename}\"'
        
        self.env.exec(cmd, detach=True)
        
    
    def reset_create_empty_file(self, path):
        cmd = f'bash -c \"rm /fs{path}\"'
        self.env.exec(cmd, detach=True)
    
    def create_mtd_file(self, path):
        cmd = f"bash ./fs/create_mtd.sh ./fs{path}"
        self.env.exec(cmd, detach=True)
    
    def reset_create_mtd_file(self, path):
        cmd = f'bash -c \"rm /fs{path}\"'
        self.env.exec(cmd, detach=True)
    
    def reuse_cwd(self, error):

        cwd = error.get("cwd")
        original_syscall = self._extract_original_syscall(error)
        
        if not cwd:
            logger.warning("No correct CWD provided in error")
            return False
        
        self.cwd = cwd
        
        # Record fix operation
        self.fix_record.add_fix_record(self.binary, {
            "reuse_cwd": {
                "old_cwd": error.get("old_cwd", "/"),
                "new_cwd": cwd,
                "original_syscall": original_syscall
            }
        },
        round_num=self.fix_round
        )
        
        return True

    
    def reuse_directory(self, error):

        path = error.get("path", "")
        original_syscall = self._extract_original_syscall(error)

        target_dir = os.path.dirname(path)
        
        if "www.satellite" in path:
            source_dir = "www"
            if os.path.exists(self.filesystem.exist_dir(source_dir)):
                self.env.exec(f"mkdir -p /fs{target_dir}")
                self.env.exec(f'sh -c "cp -r /fs/{source_dir}/* /fs{target_dir}/"')
                
                self.fix_record.add_fix_record(self.binary, {
                    "reuse_directory": {
                        "target_dir": target_dir,
                        "source_dir": source_dir,
                        "original_syscall": original_syscall
                    }
                },
                round_num=self.fix_round
                )
                
                return True

        
            
        return False
    
    def reuse_template(self, error):

        path = error.get("path")
        template_path = error.get("file_path")
        original_syscall = self._extract_original_syscall(error)

        if not path or not template_path:
            return False

        target_dir = os.path.dirname(path)
        self.env.exec(f"mkdir -p /fs{target_dir}")
        
        if not path.startswith("/"):
            path = f"/{path}"
        self.env.docker_cp_to_container(template_path, f"/fs{path}")
        
        self.fix_record.add_fix_record(self.binary, {
            "reuse_template": {
                "target": path,
                "source": template_path,
                "original_syscall": original_syscall
            }
        },
        round_num=self.fix_round
        )
        
        return True

    def fill_file_content(self, error):

        path = error.get("path")
        original_syscall = self._extract_original_syscall(error)
        
        if not path:
            return False
            
        
        if "/proc" in path or "/sys" in path or "/dev" in path:
            
            if "/proc" in path:
                path = path.replace("/proc", "/ghproc", 1)
            elif "/sys" in path:
                path = path.replace("/sys", "/ghsys", 1)
            
            try:
                self.env.exec(f"/bin/sh /fs/create_mtd.sh /fs{path}")
                self.fix_record.add_fix_record(self.binary, {
                    "fill_file_content": {
                        "path": path,
                        "content": "mtd_file",
                        "original_syscall": original_syscall
                    }
                },
                round_num=self.fix_round
                )
                return True
            except Exception as e:
                logger.error(f"Failed to create mtd file: {e}")
                return False

        # Generate random content as fallback
        import random
        import string
        content = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(64))

        # Write content to the file
        try:
            cmd = f'sh -c "echo \'{content}\' > /fs{path}"'
            self.env.exec(cmd)
            
            self.fix_record.add_fix_record(self.binary, {
                "fill_file_content": {
                    "path": path,
                    "content": content,
                    "original_syscall": original_syscall
                }
            },
            round_num=self.fix_round
            )
            
            return True
        except Exception as e:
            logger.error(f"Failed to fill file content: {e}")
            return False

    def fix_shared_memory(self, error):

        ipc_type = error.get("ipc_type")
        ipc_id = error.get("ipc_id")
        original_syscall = self._extract_original_syscall(error)
        
        if not ipc_type:
            logger.warning("No IPC type provided in error")
            return False
        
        try:
            if ipc_type == "SHMAT" and ipc_id == -1:
                # Clean up existing IPC shared memory segments
                self.env.exec('chroot fs /greenhouse/busybox rm -rf /tmp/shm_id')
                self.env.exec('sh -c "ipcs -m | awk \'NR>3 {print $2}\' | xargs -n1 ipcrm -m"')

                # Record the fix
                self.fix_record.add_fix_record(self.binary, {
                    "fix_shared_memory": {
                        "type": ipc_type,
                        "id": ipc_id,
                        "action": "recreate",
                        "original_syscall": original_syscall
                    }
                },
                round_num=self.fix_round
                )
                return True

            return False
            
        except Exception as e:
            logger.error(f"Failed to fix shared memory: {e}")
            return False

    def get_fixed_errors(self):
        """
        Retrieve all previously fixed errors from the fix record for ErrorLocator filtering.

        Returns:
            list: List of fixed error records with metadata about each fix applied.
        """
        if not hasattr(self, 'fix_record') or not self.fix_record:
            return []
        
        fixed_errors = []
        
        for binary, rounds in self.fix_record.repairs.items():
            for round_num, operations in rounds.items():
                for operation in operations:
                    for strategy_name, op_details in operation.items():
                        if isinstance(op_details, dict):
                            # Create a fixed error record
                            fixed_error = {
                                "fixed": True,
                                "fixed_binary": binary,
                                "fixed_round": round_num,
                                "fix_strategy": strategy_name
                            }
                            
                            # Add key path or identifier fields
                            if "path" in op_details:
                                fixed_error["path"] = op_details["path"]
                            if "socket_path" in op_details:
                                fixed_error["socket_path"] = op_details["socket_path"]
                            if "ipc_type" in op_details:
                                fixed_error["ipc_type"] = op_details["ipc_type"]
                            if "interface" in op_details:
                                fixed_error["interface"] = op_details["interface"]
                            if "device" in op_details:
                                fixed_error["interface"] = op_details["device"]
                            if "new_cwd" in op_details:
                                fixed_error["cwd"] = op_details["new_cwd"]
                            
                            fixed_errors.append(fixed_error)
        
        return fixed_errors

    def get_fixed_errors_for_locator(self):
        """
        Get fixed errors formatted for ErrorLocator consumption.

        Returns:
            list: Fixed error records suitable for ErrorLocator filtering.
        """
        return self.get_fixed_errors()

    # def fix_missing_network_device(self, error_info):
    #     """Create a missing network device that a process is trying to bind to"""
    #     device = error_info.get('device')
    #     if not device:
    #         print("[FixStrategy] Missing device name in error info")
    #         return False
    #
    #     print(f"[FixStrategy] Creating missing network device: {device}")
    #
    #     # First, check if this is a recognized network interface pattern
    #     if not re.match(r'^(eth|wlan|br)[0-9]+$', device):
    #         print(f"[FixStrategy] Unrecognized device pattern: {device}")
    #         return False
    #
    #     # Check if we can map this to an existing interface
    #     existing_interfaces = self.env.network.get_network_info()
    #     print(f"[FixStrategy] Existing interfaces: {existing_interfaces}")
    #
    #     # Find a suitable IP address from existing interfaces
    #     ip_address = None
    #     for interface, ips in existing_interfaces.items():
    #         if ips and isinstance(ips, list) and len(ips) > 0:
    #             ip_address = ips[0]
    #             ip_parts = ip_address.split('.')
    #             # Create a similar IP in the same subnet
    #             if len(ip_parts) == 4:
    #                 # Change last octet to avoid conflicts
    #                 last_octet = (int(ip_parts[3]) + 10) % 254
    #                 if last_octet == 0:
    #                     last_octet = 1
    #                 ip_parts[3] = str(last_octet)
    #                 ip_address = '.'.join(ip_parts)
    #             break
    #
    #     if not ip_address:
    #         # If no IP found from existing interfaces, use a default
    #         ip_address = "192.168.100.1"
    #
    #     # Create the device as a dummy interface
    #     try:
    #         # Create a dummy interface
    #         cmd = f"ip link add {device} type dummy"
    #         print(f"[FixStrategy] Running command: {cmd}")
    #         self.env.exec(cmd)
    #
    #         # Assign IP address
    #         cmd = f"ip addr add {ip_address}/24 dev {device}"
    #         print(f"[FixStrategy] Running command: {cmd}")
    #         self.env.exec(cmd)
    #
    #         # Set device up
    #         cmd = f"ip link set {device} up"
    #         print(f"[FixStrategy] Running command: {cmd}")
    #         self.env.exec(cmd)
    #
    #         print(f"[FixStrategy] Successfully created network device {device} with IP {ip_address}")
    #
    #         # Record the fix
    #         self.fix_record.add_fix_record("network", {
    #             "action": "create_device",
    #             "device": device,
    #             "ip": ip_address
    #         })
    #
    #         return True
    #
    #     except Exception as e:
    #         print(f"[FixStrategy] Failed to create network device: {e}")
    #         return False

    def replay_fixes(self, fix_record):
        """
        Replay previously recorded fixes in the current environment.
        
        Args:
            fix_record (dict): Dictionary containing fix records organized by binary and round number
            
        Returns:
            bool: True if all fixes were replayed successfully, False otherwise
        """
        if not fix_record or 'fix' not in fix_record:
            logger.warning("No fix record provided or invalid format")
            return False
        
        success = True
        
        # Iterate through each binary's fixes
        for binary, rounds in fix_record['fix'].items():
            logger.info(f"Replaying fixes for binary: {binary}")
            
            # Sort rounds by number to maintain order
            for round_num in sorted(rounds.keys()):
                operations = rounds[round_num]
                
                logger.info(f"Replaying round {round_num} operations")
                
                for operation in operations:
                    for strategy_name, details in operation.items():
                        try:
                            if strategy_name == 'reuse_template':
                                # Create target directory and copy template file
                                target_dir = os.path.dirname(details['target'])
                                self.env.exec(f"mkdir -p /fs{target_dir}")
                                self.env.docker_cp_to_container(details['source'], f"/fs{details['target']}")
                                
                                # Record the replay
                                self.fix_record.add_fix_record(binary, {
                                    "reuse_template": {
                                        "target": details['target'],
                                        "source": details['source'],
                                        "original_syscall": details.get('original_syscall', '')
                                    }
                                }, round_num=round_num)
                                
                            elif strategy_name == 'reuse_file':
                                # Create target directory and copy file
                                target_dir = os.path.dirname(details['path'])
                                self.env.exec(f"mkdir -p /fs{target_dir}")
                                self.env.exec(f"cp /fs{details['source_path']} /fs{details['path']}")
                                
                                # Record the replay
                                self.fix_record.add_fix_record(binary, {
                                    "reuse_file": {
                                        "path": details['path'],
                                        "source_path": details['source_path'],
                                        "original_syscall": details.get('original_syscall', '')
                                    }
                                }, round_num=round_num)
                                
                            elif strategy_name == 'infer_nvram_value':
                                # Write NVRAM value
                                key = details['key']
                                value = details['value']
                                
                                if len(value) > 0:
                                    self.env.exec(f'echo -n {value} > /fs/gh_nvram/{key}')
                                else:
                                    self.env.exec(f'echo -n > /fs/gh_nvram/{key}')
                                
                                # Record the replay
                                self.fix_record.add_fix_record(binary, {
                                    "infer_nvram_value": {
                                        "key": key,
                                        "value": value
                                    }
                                }, round_num=round_num)
                                
                            else:
                                logger.warning(f"Unsupported fix strategy for replay: {strategy_name}")
                                success = False
                                
                        except Exception as e:
                            logger.error(f"Failed to replay {strategy_name}: {e}")
                            success = False
                            
        return success
