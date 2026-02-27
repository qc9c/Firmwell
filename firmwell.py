import re
import io
import csv
import sys
import json
import logging
import os.path
import argparse
import traceback
import configparser
from pprint import pprint
from subprocess import PIPE
import subprocess
from firmwell.backend.Utils import Files
from firmwell.backend.new_utils import *
from firmwell.backend.utils.LoggingUtil import LoggingConfig


LoggingConfig.silence_third_party_loggers(min_level=logging.CRITICAL)

LoggingConfig.setup_project_logging(level=logging.CRITICAL)

rehosting_logger = logging.getLogger('firmwell.backend.Rehosting')
rehosting_logger.setLevel(logging.DEBUG)

error_locator_logger = logging.getLogger('firmwell.backend.reason_fix.ErrorLocator')
error_locator_logger.setLevel(logging.DEBUG)

modules_to_silence = [
    'angr', 'cle', 'pyvex', 'docker', 'urllib3', 'paramiko', 'requests',
    'firmwell.backend.QemuSysRunner', 'firmwell.backend.Planter', 'firmwell.backend.EntryPoint',
    'firmwell.backend.reason_fix.FixRecord',
    'firmwell.backend.utils.FileSystemUtil', 'firmwell.backend.utils', 'firmwell.plugins',
    'firmwell.backend.DockerManager', 'firmwell.backend.RsfChecker',
    'firmwell.backend.CallChainConstructor', 'firmwell.backend.reason_fix.LogPreprocessing',
    'firmwell.backend.reason_fix.FixStrategy', 'firmwell.backend.DockerManager.QemuUserRunner',
]

for module in modules_to_silence:
    module_logger = logging.getLogger(module)
    module_logger.setLevel(logging.CRITICAL)
    for handler in module_logger.handlers:
        module_logger.removeHandler(handler)

 
from firmwell.backend.QemuSysRunner import QemuSysRunner
from firmwell.plugins import *
from firmwell.backend.Planter import Planter
from firmwell.backend.Logger import CustomFormatter
from firmwell.backend.EntryPoint import EntryPoint
from firmwell.backend.reason_fix.FixRecord import FixRecord
from firmwell.backend.Rehosting import Rehosting
from firmwell.backend.utils.NetworkUtil import NetworkUtil
from firmwell.backend.utils.FileSystemUtil import FileSystem


# https://stackoverflow.com/questions/52026652/openblas-blas-thread-init-pthread-create-resource-temporarily-unavailable
os.environ['OPENBLAS_NUM_THREADS'] = '1'
io.DEFAULT_BUFFER_PARAMS = {'newline': '\n'}


logger = logging.getLogger(__name__)
formatter = CustomFormatter(
    fmt="%(levelname)s - %(message)s"
)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

docker_logger = logging.getLogger("docker")
docker_logger.setLevel(logging.CRITICAL)
for handler in docker_logger.handlers:
    docker_logger.removeHandler(handler)

urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.setLevel(logging.CRITICAL)
for handler in urllib3_logger.handlers:
    urllib3_logger.removeHandler(handler)

GH_SUCCESS_TAG = "GH_SUCCESSFUL_CACHE"
DOCKER_FS = "fs"
CONFIG_FILE = 'config.ini'

class FIRMWELL():
    REHOST_TYPE_MAP = {"HTTP": "HTTP",
                       "UPNP": "UPNP",
                       "DNS": "DNS",
                       "DHCP": "DHCP"}

    def __init__(self, args):
        self.basepath = os.path.dirname(os.path.abspath(__file__))
        self.gh_src_path = os.path.join(self.basepath, "firmwell", "greenhouse_files")
        self.scripts_path = os.path.join(self.basepath, "firmwell", "tools", "scripts")
        self.analysis_path = "/analysis"
        self.external_qemu = "/qemu_user"
        self.templates = os.path.join(self.basepath, "firmwell", "tools", "templates")

        self.outpath = args.outpath
        self.fixpath = args.fixpath
        self.rsfpath = args.rsfpath
        self.fs_path_override = args.fs_path
        self.target_bin_override = args.target_bin
        self.max_cycles = args.max_cycles
        self.logpath = args.logpath
        self.docker_ip = args.ip
        self.brand = args.brand
        self.runner = None
        self.name = ""
        self.target_cache_path = ""
        self.sha256hash = ""
        self.potential_http_set = set()

        # actual paths used by submodules
        self.img_path = args.img_path
        self.fs_path = ""
        self.bin_path = ""
        self.httpd_name = ""
        self.qemu_path = ""
        self.qemu_arch = ""

        self.urls = [args.ip]
        self.ports_base = self.setup_ports(args.ports)
        self.ports = self.ports_base.copy()
        self.timeout = args.timeout
        self.rehost_type = self.get_rehost_type(args.rehost_type)

        # defaults
        self.changelog = []

        self.init_file = ""

        self.tmp_dir = None
        self.tmp_fs_path = None
        self.debug = args.debug
        self.fixbash = args.fixbash
        self.httpd_path = None

        self.logger = logging.getLogger(__name__)

        self.privileged = args.privileged
        self.args = args
        self.file_list = None
        self.dir_list = []

        self.unpack_enhance = not args.nounpack_enhance
        self.kill_hang_process = not args.no_kill
        self.hackbind = not args.nohack_bind # hackbind default is True
        self.sanitize_dev = not args.no_sanitize_dev
        self.system = args.system # default is false
        self.use_ipv6 = args.use_ipv6

        self.baseline = args.baseline

        self.enable_nvram_faker = not args.no_nvram_faker
        self.enable_nvram_sematic = not args.no_nvram_sematic
        self.enable_env_variable = not args.noenv_variable
        self.entry_identify = not args.noentry_identify
        self.enable_proc_fix = not args.no_fix_proc
        self.enable_other_fix = not args.no_fix_other
        self.enable_fix_dev = not args.no_fix_dev
        self.enable_fix_bg_process = not args.no_fix_bg_process
        self.enable_mtd = not args.no_mtd
        self.enable_basic_procfs = not args.no_basic_procfs
        self.enable_fix_network = not args.no_fix_network

        self.hackdevproc = not args.nohack_devproc
        self.hacksysinfo = not args.nohack_sysinfo
        
        self.enable_fix_in_peer = not args.wo_peer
        self.enable_infer = not args.wo_infer
        self.enable_reuse = not args.wo_reuse
        self.enable_create = not args.wo_create


        self.enable_enhance_create = not args.no_enhance_create
        self.enable_fix_multi_binary = not args.no_multi_binary
        
        
        self.enable_3_2 = not args.wo_32
        self.enable_3_3 = not args.wo_33

        self.used_ipc = ""

        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_FILE)

        self.firmae_path = args.firmae
                
        self.clean_netdev()

        

    def get_rehost_type(self, rehost_string):
        if rehost_string in self.REHOST_TYPE_MAP.keys():
            return self.REHOST_TYPE_MAP[rehost_string]
        print("    - unrecognized rehost_type request [%s], defaulting to [HTTP]..." % rehost_string)
        return "HTTP"

    def setup_ports(self, portstring):
        try:
            ports = portstring.split(",")
        except:
            print("    - ERROR: invalid comma-seperated port string, defaulting to ''")
            return []
        return ports

    def setup_target(self, img_path):
        print("setup_target")
        if self.args.firmhash:
            sha256hash = self.args.firmhash
        else:
            sha256hash = Files.hash_file(img_path)
        print("TARGET HASH: ", sha256hash)
        self.sha256hash = sha256hash

        local_path = os.path.join("/tmp", f"{self.name}_container")
        dest_dir = os.path.join("/tmp", f"{self.name}_rehosted")
        if os.path.exists(local_path):
            Files.rm_folder(local_path)
        if os.path.exists(dest_dir):
            Files.rm_folder(dest_dir)

        # get brand
        if len(self.brand) == 0:
            if len(img_path) != 0:
                self.brand = self.get_firmware_brand_from_path(img_path)
                print("    - assuming firmware brand: ", self.brand)
            else:
                print("    - missing brand for fs, please supply --brand")
                return False
        else:
            print("    - target firmware brand: %s" % self.brand)

        # get name
        name = os.path.basename(self.img_path)
        for tag in [".tar", ".zip", ".bin", ".gz", ".xz"]:
            if name.lower().endswith(tag):
                name = name.rsplit(".", 1)[0]

        # sanitize
        self.name = name.replace("(", "_").replace(")", "_").replace("-", "_")
        
        # support lfwc
        if ":" in self.name:
            self.name = self.name.split(":")[1]
        
        self.target_cache_path = ""

        print("[FIRMWARE NAME]", self.name)

        # check sudo
        print("-" * 100)
        print("Check sudo...")
        subprocess.call(["sudo", "-v"])
        print("checked!")
        print("-" * 100)

        # unpack image & find target filesystem
        self.gh = Planter(gh_path=self.gh_src_path, scripts_path=self.scripts_path, qemu_src_path=self.external_qemu,
                          brand=self.brand, unpack_enhance=self.unpack_enhance, args=self.args)
        self.fs_path = self.gh.unpack_image(img_path, fs_path_override=self.fs_path_override, sha256hash=sha256hash)
        
        if self.fs_path == "":
            print("    - Error, unable to unpack image for %s" % img_path)
            return False

        # copy fs to /tmp/firm_name
        self.tmp_dir = os.path.join("/tmp", self.sha256hash)
        self.tmp_fs_path = os.path.join("/tmp", self.sha256hash, "fs")
        self.ori_fs_path = os.path.join("/tmp", self.sha256hash, "ori_fs") # without artifact files
        if not os.path.exists(self.tmp_dir):
            os.makedirs(self.tmp_dir, exist_ok=True)
        if not os.path.exists(self.tmp_fs_path):
            os.makedirs(self.tmp_fs_path, exist_ok=True)
        Files.copy_directory(self.fs_path, self.tmp_fs_path, via_cp=True)
        Files.copy_directory(self.fs_path, self.ori_fs_path, via_cp=True)
        self.fs_path = self.tmp_fs_path


        # find target binary to run
        if self.target_bin_override == "":
            self.bin_path = self.gh.get_target_binary(self.fs_path, self.rehost_type)
        else:
            if self.fs_path not in self.target_bin_override:
                self.target_bin_override = self.target_bin_override.strip("/")
                self.target_bin_override = os.path.join(self.fs_path, self.target_bin_override)
            self.bin_path = self.target_bin_override

        if self.bin_path == "" and not self.args.blank_state:
            print("    - Error, unable to find binary path for %s" % img_path)
            return False

        if len(self.gh.potential_http_set) > 1:
            self.potential_http_set = self.gh.potential_http_set

        print("[UNPACK SUCCESS]")
        print("[target bin]", self.bin_path)
        self.dir_list = os.listdir(self.fs_path)
        print("[dir list]", self.dir_list)

        self.httpd_name = self.bin_path.replace(self.fs_path, "").split("/")[-1]
        
        try:
            self.gh.clean_fs(self.fs_path)
        except Exception as e:
            print(f"clean_fs error: {e}")

        setupresult = self.gh.setup_env(self.external_qemu, self.tmp_fs_path, self.bin_path, self.fixbash, self.name,
                                        self.enable_nvram_faker, self.enable_nvram_sematic, self.enable_fix_dev,
                                        self.args.no_start_with_nvram, self.args.no_basic_dev, args)
        if not setupresult:
            return False

        self.nvram_map = self.gh.fixer.nvram_map
        self.nvram_brand_map = self.gh.fixer.nvram_brand_map

        self.qemu_path = self.gh.get_qemu_run_path()
        self.qemu_arch = self.gh.get_qemu_arch()

        if "qemu-mips-static" in self.qemu_arch:
            self.arch = "mips"
        if "qemu-mipsel-static" in self.qemu_arch:
            self.arch = "mipsel"
        if "qemu-arm-static" in self.qemu_arch:
            self.arch = "arm"

        return True

    def setup_urls(self, ip, ports):
        urls = []
        port_list = ports.split(",")
        for port in port_list:
            port = port.strip()
            url = "http://%s:%s" % (ip, port)
            urls.append(url)
        return urls

    def clean_netdev(self):
        def clean_host_netdev(netdev):
            host_net_dev = subprocess.check_output(["ip", "addr"]).decode()
            host_network_info = NetworkUtil.get_interfaces_ips(host_net_dev)
            for dev, _ in host_network_info.items():
                if dev.startswith(netdev):
                    subprocess.run(['ip', 'link', 'del', dev])
                else:
                    logger.warning("No prefix provided for cleaning network devices")
        
        clean_host_netdev("br")
        clean_host_netdev("tap")
        clean_host_netdev("veth")
    


    def run(self, img_path):
        """Execute the full rehosting pipeline for the given firmware image path."""
        try:
            print("#" * 100)
            if "POD_NAME" in os.environ.keys():
                podname = os.environ.get("POD_NAME")
                print("RUNNING ON K8 POD", podname)
                print("#" * 100)

            if self.setup_target(img_path):
                self.nvram_brand_map = self.gh.fixer.nvram_brand_map
                self.nvram_map = self.gh.fixer.nvram_map

                entry = EntryPoint(self.tmp_fs_path, self.bin_path, self.brand)


                if self.entry_identify:
                    entry.identify()
                else:
                    entry.default_entrypoint()
                    
                type, init_bash, init_bash_args, init_binary, init_binary_for_rc, etc = entry.get_result()

                self.FileSystem = FileSystem(self.ori_fs_path)
                self.file_list = get_all_filenames(self.tmp_fs_path)
                
                self.gh.fix_filesystem(self.fs_path, self.templates, self.arch)

                # Preprocess filesystem using Planter methods
                self.gh.preprocess_filesystem(self.FileSystem, self.file_list, self.fs_path, self.basepath, self.templates)
                

                self.gh.remove_high_cpu_usage_process(self.fs_path, self.FileSystem, self.rehost_type)
                
                self.gh.preprocess_bash2(self.FileSystem, self.tmp_fs_path)
                
                self.httpd_path = self.bin_path.replace(self.tmp_fs_path, "")
                
                potential_http_set = []
                for i in self.potential_http_set:
                    potential_http_set.append(i.replace(self.fs_path, ""))
                
                print("potential_http_set", potential_http_set)

                ret = self.run_rehosting(entry)

            else:
                exit(0)
        except Exception as e:
            print("!" * 100)
            print("Generic exception handler for future debugging")
            print(e)
            print(traceback.format_exc())            
            exit(1)
        return ret


    def get_firmware_brand_from_path(self, path):
        basepath = os.path.dirname(path)
        basedir = basepath.split("/")[-1]
        brand = basedir.split("_")[0]
        return brand

    def get_bin_paths(self):
        fileList = []
        for root, dirs, files in os.walk(self.tmp_fs_path, topdown=False):
            for file in files:
                path = os.path.join(root, file)
                fileList.append(path)
        return fileList

    def get_checker(self):
        if self.rehost_type == "HTTP":
            return HTTPInteractionCheck(self.brand, self.analysis_path)
        elif self.rehost_type == "UPNP":
            return UPNPInteractionCheck(self.brand, self.analysis_path)
        elif self.rehost_type == "DNS":
            return DNSInteractionCheck(self.brand, self.analysis_path)
        print("    - no checker found for %s, defaulting to HTTP..." % self.rehost_type)
        return HTTPInteractionCheck(self.brand, self.analysis_path)


    def run_rehosting(self, entry):
        print("[FIRMWELL] RUNNING ", time.ctime())
        starttime = time.time()

        self.changelog = []

        self.urls = [self.docker_ip]
        self.ports = self.ports_base.copy()

        self.ip_targets_path = os.path.join(self.tmp_fs_path, "target_urls")
        self.ports_path = os.path.join(self.tmp_fs_path, "target_ports")

        checker = self.get_checker()
        initializer = Initializer

        self.fix_record = FixRecord()
        
        
        if self.args.use_br0:
            self.urls = ["192.168.1.1", "172.104.0.1", "172.105.0.1", '192.168.2.1', '192.168.0.1']
        else:
            if self.brand == "dlink":
                self.urls = [
                    '192.168.1.1']
            else:
                self.urls = ['192.168.1.1']

        def get_ldd(path):
            try:
                res = subprocess.run(f"rabin2 -l {path}", shell=True,
                                     capture_output=True, text=True)
                return res.stdout
            except:
                return None
        
        uclibc_pthread = False
        if self.gh.fixer.clibc == "uclibc":
            ldd_res = get_ldd(self.bin_path)
            if ldd_res:
                for i in ldd_res.splitlines():
                    if "libpthread" in i:
                        with open(self.bin_path, 'rb') as f:
                            if b"pthread_create" in f.read():
                                uclibc_pthread = True
                        
        system_flag = False

        if (self.system or uclibc_pthread) and "uhttpd" not in os.path.basename(self.httpd_path) or self.FileSystem.file_in_filesystem("cos") \
                or self.FileSystem.file_in_filesystem("sysevent") \
                or self.FileSystem.file_in_filesystem("ncc"):
            system_flag = True

        
        print(f"system_flag: {system_flag}")
        
        self.runner = Rehosting(self.tmp_fs_path, self.bin_path, self.qemu_arch, self.name, self.debug,
                                   self.brand,
                                   self.basepath,
                                   self.rehost_type,
                                   self.httpd_path,
                                   self.FileSystem,
                                   config=self.config,
                                   fix_record=self.fix_record,
                                   tmp_dir=self.tmp_dir,
                                   tmp_fs_path=self.tmp_fs_path,
                                   httpd_name=self.httpd_name,
                                   args=self.args,
                                   nvram_map=self.nvram_map,
                                   nvram_brand_map=self.nvram_brand_map,
                                   potential_http_set=self.potential_http_set,
                                   analysis_path=self.analysis_path,
                                   rsfpath=self.rsfpath,
                                   hash=self.sha256hash,
                                   checker=checker, changelog=self.changelog, docker_ip=self.docker_ip,
                                   hackbind=self.hackbind,
                                   hackdevproc=self.hackdevproc,
                                   hacksysinfo=self.hacksysinfo,
                                   entry=entry,
                                   max_cycles=self.max_cycles,
                                   kill_hang_process=self.kill_hang_process,
                                   sanitize_dev=self.sanitize_dev,
                                   enable_env_variable=self.enable_env_variable,
                                   enable_nvram=self.enable_nvram_faker,
                                   enable_nvram_sematic=self.enable_nvram_sematic,
                                   enable_fix_multi_binary=self.enable_fix_multi_binary,
                                   enable_proc_fix=self.enable_proc_fix,
                                   enable_other_fix=self.enable_other_fix,
                                   enable_fix_dev=self.enable_fix_dev,
                                   enable_fix_bg_process=self.enable_fix_bg_process,
                                   enable_mtd=self.enable_mtd,
                                   entry_identify=self.entry_identify,
                                   enable_basic_procfs=self.enable_basic_procfs,
                                   enable_fix_network=self.enable_fix_network,
                                   no_cmdline=args.no_cmdline,
                                   no_ipc=args.no_ipc,
                                   no_env_var=args.no_env_var,
                                   no_dyn_file=args.no_dyn_file,
                                   initializer=initializer,
                                   use_ipv6=self.use_ipv6,
                                   enable_infer=self.enable_infer,
                                   enable_fix_in_peer=self.enable_fix_in_peer,
                                   enable_enhance_create=self.enable_enhance_create,
                                   enable_create=self.enable_create,
                                   enable_reuse=self.enable_reuse,
                                   enable_3_2=self.enable_3_2,
                                   enable_3_3=self.enable_3_3,
                                   system_flag=system_flag,
                                firmae_path=self.firmae_path,
                                    )
                                   

        # setup ip targets
        if not os.path.exists(self.ip_targets_path):
            self.gh.parse_ips(self.ip_targets_path, self.urls)

        # setup port targets
        if not os.path.exists(self.ports_path):
            self.gh.parse_ports(self.ports_path, self.ports)

        binfmt_misc_out = subprocess.run(["ls", "/proc/sys/fs/binfmt_misc"], stdout=PIPE, stderr=PIPE)
        pprint(binfmt_misc_out.stdout)

        self.runner.run(ports_file=self.ports_path)


        if system_flag:
            with open("/tmp/qemu.final.serial.log", "rb") as f:
                print("/tmp/qemu.final.serial.log:")
                for i in f:
                    print(i.decode(errors='ignore').strip())


        FIRMWELL_EXECUTE = self.runner.FIRMWELL_EXECUTE
        httpd_cmdline = self.runner.httpd_cmdline
        cwd = self.runner.cwd
        envp = list(self.runner.envp)
        ipc_process = self.runner.ipc_process
        accessed_files = list(self.runner.target_accessed_files)
        final_file_list = self.runner.final_file_list
        envp_init = self.runner.envp_init
        
        ipcs = self.runner.ipcs
        unix_domain = self.runner.unix_domain
        socket = self.runner.socket
        
        success, wellformed, connected = checker.check(trace=None, exit_code=None, timedout=None, errored=False,
                                                            strict=True)

        if connected or wellformed:
            FIRMWELL_EXECUTE = True


        
        
        # if self.args.export and not self.system:  # export for debug
        if wellformed and not system_flag and self.args.export and not self.system:  # do verify
            dest_dir = os.path.join("/tmp", f"{self.name}_rehosted")
            mininal_dir = os.path.join(dest_dir, "minimal")

            outpath = os.path.join(self.args.outpath, self.name)

            try:
                subprocess.call(["docker-compose", "build"], cwd=mininal_dir)
                subprocess.Popen(["docker-compose", "up"], cwd=mininal_dir)

                if not self.debug:  # sleep for container run
                    time.sleep(60)
                else:
                    time.sleep(10)
                ipaddr, port, loginurl, logintype, user, password, headers, payload = checker.get_working_ip_set()
                print("get_working_ip_set", ipaddr, port, loginurl, logintype, user, password, headers, payload)

                ip_prefix = NetworkUtil.get_ip_prefix(ipaddr)

                # Reset checker to avoid reusing stale probe results
                fresh_checker = self.get_checker()
                http_success = fresh_checker.probe([ipaddr], [port])
                if http_success:

                    Files.copy_directory(dest_dir, outpath)

                    print("export rehosting result success!!!")
                else:
                    new_ip = f"{ip_prefix}.1"
                    http_success = fresh_checker.probe([new_ip], [port]) # 192.168.0.50 -> 192.168.0.1
                    if http_success:
                        print("export rehosting result success!!!")
                        config_file = os.path.join(dest_dir, 'config.json')
                        config_data = json.load(open(config_file, 'r'))
                        config_data['targetip'] = new_ip
                        json.dump(config_data, open(config_file, 'w'), indent=4)

                        Files.copy_directory(dest_dir, outpath)

                        print("export rehosting result success!!!")

                        
                    else:
                        print("fail to export rehosting result!!!")

            finally:
                subprocess.Popen(["docker-compose", "down"], cwd=mininal_dir)



        print("  - [FIRMWELL UNPACK]:", True)  # if unpack failed, it will return early
        print("  - [FIRMWELL EXECUTE]:", FIRMWELL_EXECUTE)  # target port is bind
        print("  - [connected]:", connected)  # connect to web service and get response
        print("  - [wellformed]:", wellformed)  # interact with web service

        success_msg = "Success, filesystem runs!"
        rehost_result = "SUCCESS"
        if not wellformed:
            success_msg = "Partial " + success_msg
            rehost_result = "PARTIAL"
        print(success_msg)


        if success and wellformed and os.path.exists(self.target_cache_path):
            # mark cached fullrehost result as good
            success_tag = os.path.join(self.target_cache_path, GH_SUCCESS_TAG)
            print("    - tagging %s as a good fullrehost" % self.target_cache_path)
            Files.touch_file(success_tag)

        print("[FIRMWELL] Rehosting Complete, exiting...")
        if connected and not wellformed:
            rehost_result = "PARTIAL"


        totaltime = time.time() - starttime
        runtime = round(totaltime / 60, 2)




        result = dict()
        result['info'] = {
            "system_flag": system_flag,
            "brand": self.brand,
            "wellformed": wellformed,
            "connected": connected,
            "executed": FIRMWELL_EXECUTE,
            "binary_name": self.name,
            "hash": self.sha256hash,
            "rehost_type": self.rehost_type,
            "target_binary": self.bin_path,
            "target_cmdline": httpd_cmdline,
            "runtime": runtime,
            "cwd": cwd,
            "envp": envp,
            "ipc_process": ipc_process,
            "envp_init": envp_init,
            "init_bash": entry.init_bash,
            "init_bash_args": entry.init_bash_args,
            "init_binary": entry.init_binary,
            "init_binary_for_rc": entry.init_binary_for_rc,
        }
        result['fix'] = self.fix_record.repairs

        # Save remaining data as JSON
        json.dump(result, open(self.fixpath, 'w'), indent=4)

        pprint(result)

        print("="*50)
        print("[FIRMWELL] RUN FINISH ", time.ctime())
        print("[FIRMWELL] TIME TAKEN = ", runtime, "mins")

        print("REHOST STATUS - %s: %s" % (self.sha256hash, rehost_result))
        print("=" * 50)
    


        exit(0)
                

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Given a firmware image and target, generate and patch a runnable instance of the firmware')

    # -- Input/Output ----------------------------------------------------------
    io_group = parser.add_argument_group('Input/Output')
    io_group.add_argument('--img_path', default="",
                          help='path to the firmware image file to extract')
    io_group.add_argument('--fs_path', default="",
                          help='path to a pre-extracted filesystem (overrides --img_path)')
    io_group.add_argument('--outpath', default="/results",
                          help='path to the output folder for results')
    io_group.add_argument('-l', '--logpath', default="/shared/logpath",
                          help='filepath for logging roadblocks and interventions')
    io_group.add_argument('--fixpath', default="/tmp/fixlog",
                          help='path for fix log output')
    io_group.add_argument('--rsfpath', default="/tmp/rsflog",
                          help='path for RouterSploit result log')

    # -- Target Configuration --------------------------------------------------
    target_group = parser.add_argument_group('Target Configuration')
    target_group.add_argument('--brand', default="",
                              help='brand of target firmware (derived from folder name if omitted)')
    target_group.add_argument('--target_bin', default="",
                              help='path to the target binary (manual override)')
    target_group.add_argument('--rehost_type', default="HTTP",
                              help='protocol binary to target [HTTP/UPNP/DNS/DHCP]')
    target_group.add_argument('--ip', default="172.20.0.2",
                              help='IP address for testing connections')
    target_group.add_argument('--ports', default="80",
                              help='comma-separated list of port(s) for testing connections')
    target_group.add_argument('--timeout', type=int, default=5,
                              help='seconds to simulate the target binary before timeout')
    target_group.add_argument('--max_cycles', type=int, default=10,
                              help='maximum number of fix cycles before giving up')
    target_group.add_argument('--firmae', default="/work/FirmAE",
                              help='path to FirmAE folder for additional filesystem patching')

    # -- Execution Modes -------------------------------------------------------
    mode_group = parser.add_argument_group('Execution Modes')
    mode_group.add_argument('--debug', action="store_true", default=False,
                            help='enable local debug mode')
    mode_group.add_argument('--system', action="store_true", default=False,
                            help='use QEMU system mode emulation')
    mode_group.add_argument('--privileged', action="store_true", default=False,
                            help='start Docker container with privileged mode (use only inside a VM)')
    mode_group.add_argument('--baseline', action="store_true", default=False,
                            help='enable only the Section III-A module')
    mode_group.add_argument('--export', action="store_true", default=False,
                            help='export rehosted result as tar file')
    mode_group.add_argument('--rsf', action="store_true", default=False,
                            help='enable RouterSploit vulnerability check')
    mode_group.add_argument('--blank_state', action="store_true", default=False,
                            help='skip init.sh, just start a Docker container with the firmware filesystem')
    mode_group.add_argument('--unpack2zip', action="store_true", default=False,
                            help='only unpack, then save the result as a ZIP for future use')

    # -- Feature Toggles -------------------------------------------------------
    toggle_group = parser.add_argument_group('Feature Toggles')
    toggle_group.add_argument('-np', '--nohack_devproc', action="store_true", default=False,
                              help='disable /dev and /proc hacks')
    toggle_group.add_argument('-ni', '--nohack_sysinfo', action="store_true", default=False,
                              help='disable sysinfo hacks')
    toggle_group.add_argument('--nohack_bind', action="store_true", default=False,
                              help='disable all network-related modifications in QEMU')
    toggle_group.add_argument('--noenv_variable', action="store_true", default=False,
                              help='disable LD_LIBRARY_PATH and /etc/profile setup')
    toggle_group.add_argument('--nounpack_enhance', action="store_true", default=False,
                              help='disable enhanced unpacking (sqfs.img handling, D-Link detection)')
    toggle_group.add_argument('--noentry_identify', action="store_true", default=False,
                              help='disable entrypoint identification, use default /sbin/init')
    toggle_group.add_argument('--no_fix_proc', action="store_true", default=False,
                              help='disable /proc and /sys fix')
    toggle_group.add_argument('--no_fix_bg_process', action="store_true", default=False,
                              help='disable background process fix (e.g. datalib, xmldb, ubusd)')
    toggle_group.add_argument('--no_fix_other', action="store_true", default=False,
                              help='disable fix in other dirs (e.g. /var, /tmp)')
    toggle_group.add_argument('--no_fix_dev', action="store_true", default=False,
                              help='disable /dev fix')
    toggle_group.add_argument('--no_fix_network', action="store_true", default=False,
                              help='disable network device fix')
    toggle_group.add_argument('--no_mtd', action="store_true", default=False,
                              help='disable MTD device emulation')
    toggle_group.add_argument('--no_basic_dev', action="store_true", default=False,
                              help='disable /dev/null, /dev/random creation')
    toggle_group.add_argument('--no_basic_procfs', action="store_true", default=False,
                              help='disable procfs mount in /fs/proc')
    toggle_group.add_argument('--no_cmdline', action="store_true", default=False,
                              help='disable command-line dependency analysis')
    toggle_group.add_argument('--no_ipc', action="store_true", default=False,
                              help='disable IPC dependency analysis')
    toggle_group.add_argument('--no_env_var', action="store_true", default=False,
                              help='disable environment variable dependency analysis')
    toggle_group.add_argument('--no_dyn_file', action="store_true", default=False,
                              help='disable dynamic file dependency analysis')
    toggle_group.add_argument('--no_sanitize_dev', action="store_true", default=False,
                              help='disable continuous /dev sanitization in container')
    toggle_group.add_argument('--no_nvram_faker', action="store_true", default=False,
                              help='disable NVRAM faker (libnvram-faker.so)')
    toggle_group.add_argument('--no_nvram_sematic', action="store_true", default=False,
                              help='disable NVRAM semantic inference (return empty on missing keys)')
    toggle_group.add_argument('--no_enhance_create', action="store_true", default=False,
                              help='disable enhanced CREATE strategy')
    toggle_group.add_argument('--no_multi_binary', action="store_true", default=False,
                              help='disable multi-binary dependency resolution')
    toggle_group.add_argument('--no_kill', action="store_true", default=False,
                              help='disable killing hung processes')
    toggle_group.add_argument('--no_start_with_nvram', action="store_true", default=True,
                              help='start with empty NVRAM instead of copying existing values')
    toggle_group.add_argument('--fixbash', action="store_true", default=True,
                              help='fix bash scripts missing shebang lines')

    # -- Ablation Study --------------------------------------------------------
    ablation_group = parser.add_argument_group('Ablation Study')
    ablation_group.add_argument('--wo_peer', action="store_true", default=False,
                                help='disable the FIX-IN-PEER strategy')
    ablation_group.add_argument('--wo_infer', action="store_true", default=False,
                                help='disable the INFER strategy')
    ablation_group.add_argument('--wo_reuse', action="store_true", default=False,
                                help='disable the REUSE strategy')
    ablation_group.add_argument('--wo_create', action="store_true", default=False,
                                help='disable the CREATE strategy')
    ablation_group.add_argument('--wo_32', action="store_true", default=False,
                                help='disable the Section III-B module')
    ablation_group.add_argument('--wo_33', action="store_true", default=False,
                                help='disable the Section III-C module')

    # -- Advanced/Internal -----------------------------------------------------
    advanced_group = parser.add_argument_group('Advanced/Internal')
    advanced_group.add_argument('--jobindex', default="1",
                                help='job index for batch processing')
    advanced_group.add_argument('--firmhash', default=None,
                                help='SHA256 hash of the firmware, used for filesystem path')
    advanced_group.add_argument('--use_br0', action="store_true", default=False,
                                help='start with default br0 network bridge')
    advanced_group.add_argument('--use_ipv6', action="store_true", default=False,
                                help='start with default IPv6 network configuration')
    advanced_group.add_argument('--enable_redis_lock', action="store_true", default=False,
                                help='enable Redis-based distributed locking for batch mode')
    advanced_group.add_argument('--working_dirs', default="/",
                                help='working directory within container')
    advanced_group.add_argument('--greenhouse_fix', action="store_true", default=False,
                                help='replace fix logic with Greenhouse fix logic')
    advanced_group.add_argument('--greenhouse_patch', action="store_true", default=False,
                                help='use Greenhouse patch logic to enhance FIRMWELL')
    advanced_group.add_argument('--nocallchain', action="store_true", default=False,
                                help='skip call chain analysis')
    advanced_group.add_argument('--nobuildcallchain', action="store_true", default=False,
                                help='skip building call chain from scratch')
    
    
    args, unknownargs = parser.parse_known_args()
    
    print("args", args)
    print("unknownargs", unknownargs)
    if len(unknownargs) > 0:
        print("exit by unknownargs")
        exit(0)
    

    print("\n\n\n")
    print("[ARGS]", ' '.join(sys.argv))
    print("\n\n\n")
    print("DOCKER_HOST", os.getenv("DOCKER_HOST"))

    fw = FIRMWELL(args)

    fw.run(img_path=args.img_path)
