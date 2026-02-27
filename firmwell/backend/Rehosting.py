import re
import json
import time
import logging
import os.path
import datetime
import traceback
from pprint import pprint
from subprocess import PIPE
from collections import defaultdict

import requests
from docker.errors import DockerException

from .DockerManager import *
from .RsfChecker import *
from firmwell.backend.utils.NetworkUtil import NetworkUtil

from .new_utils import *

from firmwell.backend.CallChainConstructor import CallChainConstructor

from firmwell.backend.reason_fix.LogPreprocessing import LogPreprocessing
from firmwell.backend.reason_fix.ErrorLocator import ErrorLocator
from firmwell.backend.reason_fix.FixStrategy import FixStrategy

from firmwell.backend.DockerManager import QemuUserRunner
from firmwell.backend.QemuSysRunner import QemuSysRunner

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

docker_logger = logging.getLogger("docker")
docker_logger.setLevel(logging.CRITICAL)

for handler in docker_logger.handlers:
    docker_logger.removeHandler(handler)

urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.setLevel(logging.CRITICAL)
for handler in urllib3_logger.handlers:
    urllib3_logger.removeHandler(handler)


DOCKER_FS = "fs"
FS = "/fs"
BG_SCRIPT = "run_background.sh"
SETUP_SCRIPT = "run_setup.sh"
INIT_SCRIPT = "init.sh"
DEBUG_COMMANDS = "FROM 32bit/ubuntu:16.04\nCOPY fs /%s\nCMD [\"./%s/run.sh\"]\n" % (
DOCKER_FS, DOCKER_FS)
TRACE_LOG = "trace.log"
EXIT_CODE_TAG = "Greenhouse_EXIT_CODE::"
DONE_TAG = "GH_DONE"
HARD_TIMEOUT = 3  # mins
MISSING_NVRAM_FILE = "MISSING_NVRAMS"
BG_LOG = "GREENHOUSE_BGLOG"
GREENHOUSE_LOG = "GREENHOUSE_STDLOG"
GH_NVRAM = "gh_nvram"
FW_STDLOG = "FW_STDLOG"

FIRMWELL_NET = os.path.join(FS, f"FIRMWELL_NET")
BASH_RECORD = "FIRMWELL_BASH"

BUSYBOX = f"{DOCKER_FS}/greenhouse/busybox"
CHROOT_FS = "chroot fs"
RETRY_TIMES = 2


from firmwell.backend.utils.NetworkUtil import check_ip_domain_mapping, add_ip_domain_mapping, HOSTS


class Rehosting:
    ERROR_CODES = [139,  # segfault
                   255,  # can also mean exiting with -1
                   20,  # 'network' error (peripheral device)
                   -11,
                   127,  # assertion failed (invalid command)
                   132,  # illegal instruction
                   134,  # abort
                   -6,
                   135,  # bus error
                   136,  # arithmetic error
                   -8]
    TIMEOUT_CODE = 124  # linux timeout return value
    VERBOSE_LOG_TIMEOUT_MULTIPLIER = 5

    def __init__(self, fs_path, bin_path, qemu_arch, name, debug, brand, basepath, rehost_type, httpd_path, FileSystem,
                 tmp_dir, tmp_fs_path, httpd_name,
                 args, nvram_map, nvram_brand_map, potential_http_set, analysis_path, rsfpath, config,
                 hash="", checker=None,
                 changelog=[], docker_ip="172.20.0.2", hackbind=True, hackdevproc=True,
                 hacksysinfo=True, entry=None, max_cycles=1, kill_hang_process=True, sanitize_dev=True,
                 enable_env_variable=True, enable_nvram=True, enable_fix_multi_binary=False, enable_proc_fix=True,
                 enable_other_fix=True, enable_fix_dev=True, enable_nvram_sematic=True, enable_fix_bg_process=True, enable_mtd=True, fix_record=None,
                 entry_identify=True, enable_nvram_faker=True, enable_basic_procfs=True, enable_fix_network=True, no_cmdline=False, no_ipc=False, no_env_var=False,
                 no_dyn_file=False, initializer=None, use_ipv6=False, enable_infer=True, enable_fix_in_peer=True, enable_enhance_create=True, enable_create=True, enable_reuse=True,
                 enable_3_2=True, enable_3_3=True,
                 system_flag=False,
                 firmae_path="/work/FirmAE",
                 ):
        self.fs_path = fs_path
        self.bin_path = bin_path
        self.qemu_arch = qemu_arch
        self.name = name
        self.debug = debug
        self.brand = brand
        self.final_file_list = []
        self.args = args
        self.basepath = basepath
        self.rehost_type = rehost_type
        self.hash = hash
        self.checker = checker
        self.changelog = changelog
        self.docker_ip = docker_ip
        self.last_bincwd = "/"
        self.relative_bin_path = ""
        self.extra_args = ""
        self.nd_args = ""
        self.bg_cmds = []
        self.bg_sleep = 0
        self.qemu_command = ""
        self.emulation_output = ""
        self.ipv6enable = False
        self.nvram_map = nvram_map
        self.nvram_brand_map = nvram_brand_map
        self.potential_http_set = potential_http_set
        self.analysis_path = analysis_path
        self.rsfpath = rsfpath

        self.enable_fix_multi_binary = enable_fix_multi_binary

        self.docker_manager = None
        self.img = None
        self.network_info = None
        self.potential_urls = []

        self.max_cycles = max_cycles

        self.rcS_File = None  # abs path

        self.entry = entry

        self.broken_main_link = None
        self.all_broken_link = None

        self.bash_script_list = list()

        self.tmp_dir = tmp_dir
        self.tmp_fs_path = tmp_fs_path
        self.analyzed_bash = list()

        self.run_script_cmd = list()
        self.set_script_cmd = list()

        self.httpd_name = httpd_name
        self.httpd_path = httpd_path
        self.httpd_cmdline = ''
        self.fx = None
        self.logger = logging.getLogger(__name__)
        self.LD_LIBRARY_PATH_set = set()
        self.cwd = "/"
        self.cwd_map = defaultdict(str)
        self.target_accessed_files = set()
        self.ipc_process = ""
        self.envp = set()

        self.FileSystem = FileSystem

        self.target_cmdline = ""
        self.FIRMWELL_EXECUTE = False

        # ablation
        self.kill_hang_process = kill_hang_process
        self.hackbind = hackbind
        self.sanitize_dev = sanitize_dev
        self.enable_env_variable = enable_env_variable
        self.enable_nvram = enable_nvram
        self.enable_nvram_sematic = enable_nvram_sematic
        self.enable_proc_fix = enable_proc_fix
        self.enable_other_fix = enable_other_fix
        self.enable_fix_dev = enable_fix_dev
        self.enable_fix_bg_process = enable_fix_bg_process
        self.enable_mtd = enable_mtd
        self.entry_identify = entry_identify
        self.enable_nvram_faker = enable_nvram_faker
        self.enable_basic_procfs = enable_basic_procfs
        self.enable_fix_network = enable_fix_network

        self.no_cmdline = no_cmdline
        self.no_ipc = no_ipc
        self.no_env_var = no_env_var
        self.no_dyn_file = no_dyn_file

        self.hackdevproc = hackdevproc
        self.hacksysinfo = hacksysinfo
        self.use_ipv6 = use_ipv6
        self.enable_infer = enable_infer
        self.enable_fix_in_peer = enable_fix_in_peer
        self.enable_enhance_create = enable_enhance_create
        self.enable_create = enable_create
        self.enable_reuse = enable_reuse
        self.enable_3_2 = enable_3_2
        self.enable_3_3 = enable_3_3
        
        self.fixed_things = set()
        self.envp_init = ""

        self.config = config

        self.fix_times = 0
        self.fix_binary = set()

        # for fix operation record
        self.fix_record = fix_record
        self.fix_round_start = 0
        self.fix_round = 0

        self.set_net_flag = False
        self.added_br0 = False
        self.initializer = initializer

        self.call_chain = None

        self.env = None
        self.system_flag = system_flag
        
        self.located_errors = defaultdict(list)
        self.firmae_path = firmae_path
        
        self.global_not_found_error = False
        
        self.ipcs = ""
        self.unix_domain = ""
        self.socket = ""

    def __del__(self):
        pass


    def get_minimal_command(self, base_cmd):
        command = "/%s" % (self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " -execve \"/%s" % (self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " \""
        command += " -E LD_PRELOAD=\"libnvram-faker.so\""
        command += " %s\n" % (base_cmd)
        return command

    def get_script_command(self, base_cmd):
        command = "chroot %s /%s" % (DOCKER_FS, self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " -execve \"/%s" % (self.qemu_arch)
        if self.hackbind:
            command += " -hackbind"
        if self.hackdevproc:
            command += " -hackproc"
        if self.hacksysinfo:
            command += " -hacksysinfo"
        command += " \""
        command += " -E LD_PRELOAD=\"libnvram-faker.so\""
        command += " %s\n" % (base_cmd)
        return command

    def wrap_binary_with_qemu(self, binary, args="", hackproc=True, hacksysinfo=True, tracelog=True, trace_sublog=True, stream=False, caught_crash_sig=False, use_nvram=True, use_execve=True, use_hack_bind=True, debug=False, trace_init=False, pc_trace=False):
        
        qemu_command = []
        logfilename = "/" + TRACE_LOG
        if not debug:
            qemu_command.extend(["chroot", DOCKER_FS, "/"+self.qemu_arch])
        else:
            qemu_command.extend(["chroot", ".", "/"+self.qemu_arch])
        if self.hackbind and use_hack_bind:
            qemu_command.extend(["-hackbind"])
        if hackproc:
            qemu_command.extend(["-hackproc"])
        if hacksysinfo:
            qemu_command.extend(["-hacksysinfo"])
            
        if os.path.exists(os.path.join(self.fs_path, "hackioctl")):
            qemu_command.extend(["-hackioctl"])
            
        if pc_trace:
            qemu_command.extend(["-d", "exec,nochain,page"])
        
        if trace_init:
            # qemu_command.extend(["-D", "/"+TRACE_LOG]+"_init")
            # qemu_command.extend(["-strace"])
            qemu_command.extend(["-d", "strace"])
        elif tracelog:
            qemu_command.extend(["-D", logfilename])
            qemu_command.extend(["-strace"])
            if pc_trace:
                qemu_command.extend(["-d", "exec,nochain,page"]) # "-pconly"
                
                
        # if caught_crash_sig and not self.args.greenhouse_fix:
        #     qemu_command.extend(["-caught_crash_sig"])
        if use_execve:
            qemu_command.extend(["-execve", "\"/"+self.qemu_arch+" "])
            if self.hackbind and use_hack_bind:
                qemu_command.extend(["-hackbind"])
            if hackproc:
                qemu_command.extend(["-hackproc"])
            if hacksysinfo:
                qemu_command.extend(["-hacksysinfo"])

            if tracelog and trace_sublog:
                qemu_command.extend(["-D", logfilename])
                qemu_command.extend(["-strace"])
            qemu_command.extend(["\""])
        if self.enable_nvram and use_nvram:
            if self.brand == "tenda":
                PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
                qemu_command.extend((["-E", f'QEMU_SET_ENV="PATH={PATH},LD_PRELOAD=libnvram-faker.so"']))
            else:
                qemu_command.extend(["-E", "LD_PRELOAD=\"libnvram-faker.so\""])
        if self.enable_env_variable and len(self.LD_LIBRARY_PATH_set) > 0 and not self.no_env_var:
            if "/" in self.LD_LIBRARY_PATH_set:
                self.LD_LIBRARY_PATH_set.remove("/")
            if "" in self.LD_LIBRARY_PATH_set:
                self.LD_LIBRARY_PATH_set.remove("")

            if "/opt/bitdefender/lib" in self.LD_LIBRARY_PATH_set: # R6700v3_V1.0.4.102_10.0.75, /usr/sbin/httpd: '/opt/bitdefender/lib/libc.so.0' library contains unsupported TLS
                self.LD_LIBRARY_PATH_set.remove("/opt/bitdefender/lib")

            LD_LIBRARY_PATH_set = self.LD_LIBRARY_PATH_set.copy()
            if "/usr/lib" not in LD_LIBRARY_PATH_set:
                LD_LIBRARY_PATH_set.add("/usr/lib")
            if "/lib" not in LD_LIBRARY_PATH_set:
                LD_LIBRARY_PATH_set.add("/lib")
            if len(LD_LIBRARY_PATH_set) > 0:
                LD_LIBRARY_PATH = ":".join(LD_LIBRARY_PATH_set)
                qemu_command.extend(["-E", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}"])
        qemu_command.extend([binary, args])
        # if stream:
        #     qemu_command.extend([f"> {FW_STDLOG} 2>&1"])
        return " ".join(qemu_command)

    def build_init_script(self, start_with_blank_state):
        print("Building init.sh file...")
        print("=" * 50)

        print("init binary", self.entry.init_binary)
        print("init bash", self.entry.init_bash)

        trace_main_flag = False
        trace_sub_flag = False
        use_execve = True

        
        trace_init = True


        init_script_path = os.path.join(self.tmp_fs_path, INIT_SCRIPT)

        procd_flag = False # edge-case
        procd = Files.find_file_paths(self.tmp_fs_path, "procd")
        if len(procd) > 0:
            if "sbin" in procd[0]:
                procd_flag = True


        with open(init_script_path, "w", newline="\n") as ws:
            ws.write("#!/bin/sh\n")
            ws.write(". /etc/profile\n")

            if not self.args.blank_state and not start_with_blank_state:
                if len(self.entry.init_binary_for_rc) > 0: # sbin/preinit -> sbin/rc
                    qemu_cmd = "exec " + self.wrap_binary_with_qemu(self.entry.init_binary_for_rc, args="", tracelog=trace_main_flag, trace_sublog=trace_sub_flag, use_execve=use_execve, trace_init=trace_init, use_hack_bind=False)
                    ws.write(qemu_cmd)
                elif self.brand == "ubiquiti" and os.path.join(self.fs_path, "init") in self.FileSystem.bash_files:
                    qemu_cmd = "exec " + self.wrap_binary_with_qemu("/bin/sh", args="/init", tracelog=trace_main_flag, trace_sublog=trace_sub_flag, use_execve=use_execve, trace_init=trace_init, use_hack_bind=False)
                    ws.write(qemu_cmd)
                elif self.brand == "ubiquiti" and os.path.join(self.fs_path, "init") in self.FileSystem.elf_files:
                    qemu_cmd = "exec " + self.wrap_binary_with_qemu("/init", tracelog=trace_main_flag, trace_sublog=trace_sub_flag, use_execve=use_execve, trace_init=trace_init, use_hack_bind=False)
                    ws.write(qemu_cmd)
                elif "rc" in self.entry.init_binary: # sbin/rc start
                    qemu_cmd = "exec " + self.wrap_binary_with_qemu(self.entry.init_binary, args="start", tracelog=trace_main_flag, trace_sublog=trace_sub_flag, use_execve=use_execve, trace_init=trace_init, use_hack_bind=False)
                    ws.write(qemu_cmd)
                elif "busybox" in self.entry.init_binary:
                    qemu_cmd = "exec " + self.wrap_binary_with_qemu(self.entry.init_binary, args="init",
                                                                    tracelog=trace_main_flag, trace_sublog=trace_sub_flag, use_execve=use_execve, trace_init=trace_init, use_hack_bind=False)
                    ws.write(qemu_cmd)
                elif len(self.entry.init_binary) > 0 and procd_flag: # for procd, use_execve make it running ! D7000v2_FW_V1.0.0.40_1.0.1
                    qemu_cmd = "exec " + self.wrap_binary_with_qemu(self.entry.init_binary, args="",
                                                                    tracelog=trace_main_flag, trace_sublog=trace_sub_flag, use_execve=use_execve, trace_init=trace_init, use_hack_bind=False)
                    ws.write(qemu_cmd)
                elif len(self.entry.init_binary) > 0:
                    qemu_cmd = "exec " + self.wrap_binary_with_qemu(self.entry.init_binary, args="",
                                                                    tracelog=trace_main_flag, trace_sublog=trace_sub_flag, use_execve=use_execve, trace_init=trace_init, use_hack_bind=False)
                    ws.write(qemu_cmd)
                    
                
            ws.write("\nwhile true; do sleep 10000; done\n") # handle edge-case
            ws.write("\n")

        Files.chmod_exe(init_script_path)

        with open(init_script_path, 'r') as f:
            init_script_cmd = f.readlines()
            pprint(init_script_cmd)

    def build_run_script(self):
        print("Building fw.sh file...")
        print("=" * 50)

        wrapper_script_path = os.path.join(self.tmp_fs_path, "fw.sh")
        with open(wrapper_script_path, "w", newline="\n") as f_run:
            f_run.write("#!/bin/sh\n")
            f_run.write("\n")
            f_run.write("\n")

            f_run.write("chroot /fs /greenhouse/busybox sh /sanitize_dev.sh & \n")
            f_run.write("bash /fs/fw_watchdog.sh & \n")
            
            f_run.write('bash -c "rm /fs/etc/hosts; cp /etc/hosts /fs/etc/hosts" \n')
            f_run.write('bash -c "rm /fs/etc/resolv.conf; cp /etc/hosts /fs/etc/resolv.conf" \n')
            
            f_run.write("while true; do sleep 10000; done \n")
            f_run.write("\n")
        Files.chmod_exe(wrapper_script_path)

        with open(wrapper_script_path, 'r') as f:
            self.run_script_cmd = f.readlines()
            pprint(self.run_script_cmd)

    @staticmethod
    def parse_cmdline(cmdline):
        '''
        input: http -D trace.log -strace /usr/sbin/httpd -S -E /usr/sbin/ca.pem /usr/sbin/httpsd.pem
        output: -D "trace.log" -E "/usr/sbin/ca.pem /usr/sbin/httpsd.pem"
        '''
        # pattern = re.compile(r'-(\w)\s+((?:[^\s-]+(?:\s+|$))+)')
        pattern = re.compile(r'-(\w)\s+((?:[^\s-][^\s]*\s*)*)')
        matches = pattern.findall(cmdline)
        params = ""
        for key, value in matches:
            if "/*" in value: #Bug: Pattern matching issue with paths containing wildcard (*)
                continue
            
            params += f' -{key} \"{value.strip()}\"'

        if "\"\"" in params:
            params = params.replace("\"\"", "")

        if '-E "/usr/sbin/ca.pem /usr/sbin/httpsd.pem"' in params:
            params = params.replace('-E "/usr/sbin/ca.pem /usr/sbin/httpsd.pem"', '-E /usr/sbin/ca.pem /usr/sbin/httpsd.pem')

        if cmdline == "httpd 1":
            params = " 1"
        if cmdline == "httpd 1 1 1":
            params = " 1"
        return params


    def find_httpd_args(self):
        httpd_args = set()
        cmd = f'grep -rn "{self.bin_path.replace(self.fs_path, "")}"'

        try:
            stdout = subprocess.run(cmd, shell=True, cwd=self.tmp_fs_path, text=True, capture_output=True).stdout
            for line in stdout.splitlines():
                arg = line.split(":")[-1].replace("&", "", -1)
                if "-" in arg:
                    httpd_args.add(arg)

                if len(httpd_args) > 3:
                    break
        except Exception as e:
            print("[find_httpd_args]")
            print(e)

        if len(httpd_args) == 0:
            httpd_args.add("")

        print("[find_httpd_args]", httpd_args)
        return httpd_args

    def get_bind_ip_port(self):
        potential_port = []
        if self.rehost_type == "HTTP":
            potential_port = ['80', '81', '8000', '8080', '8181', '9090', '9091', '20003', '1']
        elif self.rehost_type == "DNS":
            potential_port = ['53']
        elif self.rehost_type == "UPNP":
            potential_port = ['80', '1900', "7777", "9000"]
        bind_port, bind_ip = set(), set()
        
        
        netstat_output = self.env.exec("netstat -antu")
        print("netstat_output")
        print(netstat_output)
        bind_info = NetworkUtil.get_netstat(netstat_output)
        for info in bind_info:
            port = info[2]
            ip = info[1]
            if port in potential_port:
                bind_port.add(port)
                if ip != "0.0.0.0":
                    bind_ip.add(ip)

        return list(bind_ip), sorted(list(bind_port))


    def probe(self, reset_network=True):
        http_success, success, wellformed, connected = False, False, False, False

        print("[probe]")
        print("self.network_info", self.network_info)
        
        if self.system_flag:
            reset_network = False
        
        if reset_network:
            self.env.network.reconfig_network(self.network_info)
            time.sleep(1)

        target_ip = set()
        br0 = NetworkUtil.get_ip_by_dev(self.network_info, 'br0')
        if br0:
            target_ip.add(br0)
        eth0 = NetworkUtil.get_ip_by_dev(self.network_info, 'eth0')
        if eth0:
            target_ip.add(eth0)
        eth1 = NetworkUtil.get_ip_by_dev(self.network_info, 'eth1')
        if eth1:
            target_ip.add(eth1)

        ips, ports = self.get_bind_ip_port()
        print("service bind port:", ports)

        if len(ports) > 0:
            self.FIRMWELL_EXECUTE = True
            if len(target_ip) == 0:
                try:
                    ip_addr = [i[0] for i in self.network_info.values()][0]  # first curr ip
                except:
                    ip_addr = "192.168.0.1"
                target_ip.add(ip_addr)

        print("service bind ip:", ips)
        for i in ips:
            if i not in target_ip:
                target_ip.add(i)
        for i in self.potential_urls:
            if i not in target_ip:
                target_ip.add(i)
        print("target_ip:", target_ip)
        
        if self.system_flag: # some time cant get output
            if "80" not in ports:
                ports.append("80")


        probe_success = self.checker.probe(list(target_ip), ports)
        if probe_success:
            success, wellformed, connected = self.checker.check(trace=None, exit_code=None, timedout=None, errored=False, strict=True)
            print(f"[success] {success}, [wellformed] {wellformed}, [connected] {connected}")

            if success and wellformed and connected:
                http_success = True

        return http_success

    def waiting_all_process(self, target_path):
        if self.args.blank_state or self.debug:
            return

        waiting_time = time.time()
        process_set = set()

        time.sleep(90)
        
        
        max_time = 4
        while True:  # sleep until no new process name apperance
            if not self.debug:
                time.sleep(30)
            else:
                time.sleep(10)
            
            if self.brand == 'asus':
                self.env.exec(
                    'sh -c "echo -n 1 > /fs/gh_nvram/asus_mfg"')  # without this setup, preinit will consume all CPU
            
            print("Wainting for all service start")
            new_process_dict = self.env.process.get_process_dict()
            pprint(new_process_dict)
            print("\n\n")
            new_process_set = {i for i in set(new_process_dict.values()) if "sleep" not in i}
            if self.env.process.get_defunct_process_num(new_process_dict) > 20: # 0118, delete?
                break

            # Kill processes containing uci_apply_defaults if not system_flag. had move to watchdog.sh
            if not self.system_flag:
                for pid, cmdline in new_process_dict.items():
                    if "uci_apply_defaults" in cmdline: # endless fork and oom
                        try:
                            self.env.exec(f"kill -9 {pid}")
                            print(f"Killed process {pid} with cmdline: {cmdline}")
                        except Exception as e:
                            print(f"Failed to kill process {pid}: {e}")

            target_cmdline = self.get_service_cmdline(target_path, new_process_dict)
            if len(target_cmdline) > 0: # target service is called
                break

            if len(new_process_set - process_set) > 0:  # have new process name
                process_set = new_process_set
            else:
                process_set = new_process_set
                break
            max_time -= 1
            if max_time == 0:
                break

        print("waiting for ", time.time() - waiting_time, "s")

        print("\n\n")
        print("="*50)
        print("after sleeping process dict")

    
    def merge_consecutive_duplicates(self, tracelog_dict):
        """
        Merge consecutive duplicate lines in tracelog_dict.
        For sequences >= 50 duplicates, only keep the last occurrence.
        For sequences < 50 duplicates, keep all occurrences.
        Also merges sequences of lines containing 'close' and '=' if >= 50 consecutive occurrences.
        """
        for pid in tracelog_dict:
            lines = tracelog_dict[pid]
            if not lines:
                continue
                
            merged_lines = []
            curr_line = lines[0]
            count = 1
            
            for line in lines[1:]:
                # Check for exact duplicates
                if line == curr_line:
                    count += 1
                # Check for close/= pattern
                elif "close" in curr_line and "=" in curr_line and "close" in line and "=" in line: # qemu close
                    count += 1
                else:
                    if count >= 50:
                        # Only keep the last occurrence for sequences >= 50
                        merged_lines.append(curr_line)
                    else:
                        # Keep all occurrences for sequences < 50
                        merged_lines.extend([curr_line] * count)
                    curr_line = line
                    count = 1
            
            # Handle the last sequence
            if count >= 50:
                merged_lines.append(curr_line)
            else:
                merged_lines.extend([curr_line] * count)
                
            tracelog_dict[pid] = merged_lines
        return tracelog_dict
    
    
    def get_pc_trace_log(self, subpid=True, delete=True) -> dict:
        """
        Get PC execution trace log from container.
        :param subpid: whether to include subprocess logs
        :return: path to filtered trace log file on host
        """
        # Check if we're using system mode or user mode
        system_flag = hasattr(self, 'system_flag') and self.system_flag
        
        tracelog_dict = dict()
            
        trace_log = "fs/trace.log"
        trace_log_host_path = f"/tmp/trace.log"
        trace_log_host_path_filtered = f"/tmp/trace.log_filtered"
        if os.path.exists(trace_log_host_path):
            os.remove(trace_log_host_path)
        if os.path.exists(trace_log_host_path_filtered):
            os.remove(trace_log_host_path_filtered)

        self.env.docker_cp_to_host(f"{trace_log}", trace_log_host_path)
        time.sleep(3)
        
        
        
        
        filter_script = "/fw/firmwell/tools/scripts/filt_trace.sh"
        if os.path.exists(filter_script):
            cmd = ["bash", filter_script, trace_log_host_path, trace_log_host_path_filtered]
            subprocess.run(cmd, capture_output=True, text=True, timeout=1200, check=True)
            time.sleep(3)
            with open(f"{trace_log_host_path}_filtered", "r") as f:
                print(f"Filtered trace log: {len(f.readlines())} lines")
        
        # delete all trace log in container
        if delete:
            self.env.exec(f'sh -c \"rm fs/trace.log\"',
                                                detach=True, noprint=True)
                
        return trace_log_host_path_filtered
    
    def get_trace_log(self, subpid=True, delete=True) -> dict:
        """
        Get strace log from container, organized as a dict keyed by PID.
        :param subpid: whether to include subprocess trace logs
        :return: tracelog_dict: {str(pid): stracelog_lines}
        """
        # Check if we're using system mode or user mode
        system_flag = hasattr(self, 'system_flag') and self.system_flag
        trace_num = 5000
        
        def extract_number(filename):
            """Extract the first number from a filename, defaulting to 0."""
            match = re.search(r'\d+', filename)
            if match:
                return int(match.group(0))
            return 0
        
        # get all target folders
        www_dirs = set()
        tracelog_dict = dict()
        
        for _dir in os.listdir(self.tmp_fs_path):
            if "www" in _dir:
                tmp_path = str(pathlib.Path(os.path.join(self.tmp_fs_path, _dir)).resolve())
                www_dirs.add(tmp_path)
        
        # Different handling for system mode and user mode
        if system_flag:
            # For QemuSysRunner, trace.log is directly at root level, no subprocesses
            trace_log = "/trace.log"
            ret = self.env.exec(f"cat {trace_log}")  # don't use tail, it may miss forked process output
            
            # Add any output from /dev/null (where stderr might be redirected)
            ret += self.env.exec("tail -n 1000 /dev/null")
            
            assert len(ret) is not None
            
            main_stracelog = ret.splitlines()
            tracelog_dict["0"] = main_stracelog
            
            # Clean up trace log in container if needed
            if len(main_stracelog) > 0:
                self.env.exec(f'rm {trace_log}', detach=True, noprint=True)
            
            return tracelog_dict
        else:
            # For QemuUserRunner, use the original implementation
            httpd_trace_log_path = list()
            
            out = self.env.exec(
                f'sh -c "find fs -type d \( -path fs/proc -o -path fs/sys \) -prune -o  -type f -name trace.log*"').splitlines()
            for line in out:
                if "No such file or directory" not in line and "fs/sys" not in line and "fs/proc" not in line:
                    httpd_trace_log_path.append(line)
            
            httpd_trace_log_path = sorted(httpd_trace_log_path, key=extract_number)
            
            if len(httpd_trace_log_path) == 0:
                return tracelog_dict
            
            if len(httpd_trace_log_path) > 100:
                httpd_trace_log_path = httpd_trace_log_path[0:100]
            
            trace_log = "fs/trace.log"
            if trace_log in httpd_trace_log_path:
                httpd_trace_log_path.remove(trace_log)
            
            ret = self.env.exec(f"cat {trace_log}")


            ret += self.env.exec(f"tail -n {trace_num} /fs/ghdev/null")
            
            assert len(ret) is not None
            
            main_stracelog = ret.splitlines()
            tracelog_dict["0"] = main_stracelog
            
            
            tracelog_dict = self.merge_consecutive_duplicates(tracelog_dict)
            
            
            if subpid and len(httpd_trace_log_path) > 0:
                for file in httpd_trace_log_path:
                    iid = extract_number(file)
                    stracelog = self.env.exec(f"tail -n 1000 {file}", noprint=True).splitlines()
                    tracelog_dict[str(iid)] = stracelog
            
            # delete all trace log in container
            if delete and (len(httpd_trace_log_path) > 0 or len(main_stracelog) > 0):
                self.env.exec(f'sh -c \"rm fs/trace.log {" ".join(httpd_trace_log_path)}\"',
                                                  detach=True, noprint=True)
                self.env.exec(f'sh -c \"echo -n > /fs/ghdev/null\"',
                              detach=True, noprint=True)
                
            return tracelog_dict


    def run_binary(self, service_path, service_cmdline, probe=True, use_execve=True, use_hack_bind_flag=False, tracelog=True, trace_sublog=True, pc_trace=False):
        system_flag = hasattr(self, 'system_flag') and self.system_flag

        # Kill any existing processes with the same name
        self.env.process.kill_process_by_name(service_path)
        
        if not system_flag:
            if not self.FIRMWELL_EXECUTE: # user mode, bind syscall
                try:
                    result = self.env.exec('cat /fs/FIRMWELL_NET')
                    if "No such file" not in result:
                        self.FIRMWELL_EXECUTE = True
                except Exception as e:
                    logger.error(f"Error checking FIRMWELL_NET file: {e}")
        
        # Clean up trace logs differently based on system/user mode
        if system_flag:
            # In system mode, trace.log is at the root
            self.env.exec('rm /trace.log*')
        else:
            # In user mode, trace.log is under /fs
            self.env.exec('sh -c "rm /fs/trace.log*"')
            self.env.exec('sh -c "rm /fs/ghdev/null"')
            self.env.exec('sh -c "touch /fs/ghdev/null"')
            self.env.exec('sh -c "rm /fs/FIRMWELL_NET"')
            
        if "sbin/init" in service_path or "sbin/rc" in service_path:  # don't trace subprocess
            trace_sublog = False


        use_nvram = True
        use_hack_bind = True

        # if dlink xmldb is error, consider run binary directly
        if self.brand == "dlink" and (self.name.startswith("DCS_65") or self.name.startswith("DCS_75") or self.name.startswith("DIR_880") or self.name.startswith("DAP_1360")):
            use_nvram = False # special nvram value
            use_execve = False # if cwd is "/www" or "/tmp/www", maybe not use execve?
            use_hack_bind = False
            self.enable_nvram = False

        if self.FileSystem.file_in_filesystem("xmldb"):
            use_nvram = False  # special nvram value
            use_execve = False  # if cwd is "/www" or "/tmp/www", maybe not use execve?
            use_hack_bind = False
            
            if self.args.rsf:
                use_execve = True
            
        if self.rehost_type == "DNS":
            use_nvram = False
            use_execve = False
            use_hack_bind = False

        if self.name.startswith("TEW_72"): # TEW_721BRMv1_FW1.00B13_, otherwise miss /apps/web/index.html
            use_nvram = False
            use_execve = False
            use_hack_bind = False

        if "/var/etc/httpd.cfg" in service_cmdline:
            # /sbin/httpd -s wrgn23_dlwbr_dir300b -f /var/etc/httpd.cfg
            # /sbin/httpd: cannot add multicast membership
            # setsockopt: No such device
            use_hack_bind = True

        if self.brand == "linksys" and "lighttpd.conf" in service_cmdline:
            use_hack_bind = False

        if "WL" in self.name and ("600g" in self.name or "604g" in self.name):
            use_execve = False

        if self.brand == "belkin" and (self.name.startswith("F7D440") or self.name.startswith("F9K1")):
            use_execve = False
            
        if use_hack_bind_flag is True:
            use_hack_bind = True

        # Check LD_LIBRARY_PATH from QEMU_CMDLINE (prefer setting LD_LIBRARY_PATH over copying libs)
        LD_LIBRARY_PATH_set = set()
        data = self.docker_manager.read_file("QEMU_CMDLINE")
        for i in data.splitlines():
            if "   - envp LD_LIBRARY_PATH=" in i:
                line = i.split("   - envp LD_LIBRARY_PATH=")[1].strip()
                for lib in line.split(":"):
                    LD_LIBRARY_PATH_set.add(lib)

        if len(LD_LIBRARY_PATH_set) > 0:
            for i in LD_LIBRARY_PATH_set:
                self.LD_LIBRARY_PATH_set.add(i)

        if self.no_cmdline:
            service_cmdline = service_path
        
        
        if service_path in self.cwd_map:
            cwd = self.cwd_map[service_path]
        else:
            cwd = self.cwd
        
        # Handle system mode vs user mode differently
        if system_flag:
            # For QemuSysRunner, use strace directly
            if cwd != "/" and cwd != "":
                # When a specific working directory is needed
                base_cmd = f"cd {cwd} && /firmadyne/strace -f -o /trace.log -a 0 {service_cmdline}"
            else:
                base_cmd = f"/firmadyne/strace -f -o /trace.log -a 0 {service_cmdline}"
            
            # Execute with redirection of stdout/stderr
            qemu_httpd_cmd = f"{base_cmd}"
        else:
            # For QemuUserRunner, use the existing approach with wrap_binary_with_qemu
            if cwd != "/" and cwd != "":
                wrap_bash = "run.sh"
                self.wrap_binary_with_cwd(wrap_bash, cwd, service_cmdline)
                qemu_httpd_cmd = self.wrap_binary_with_qemu("/bin/sh", args=wrap_bash, stream=True, caught_crash_sig=True,
                                                        use_nvram=use_nvram, use_execve=use_execve,
                                                        use_hack_bind=use_hack_bind, tracelog=tracelog, trace_sublog=trace_sublog, pc_trace=pc_trace)
            else:
                qemu_httpd_cmd = self.wrap_binary_with_qemu(service_cmdline, stream=True, caught_crash_sig=True,
                                                        use_nvram=use_nvram, use_execve=use_execve,
                                                        use_hack_bind=use_hack_bind, tracelog=tracelog, trace_sublog=trace_sublog, pc_trace=pc_trace)

        # Ensure network is configured correctly before running (some firmware requires correct IP)
        if probe:
            self.env.network.reconfig_network(self.network_info)
        
        self.env.exec(qemu_httpd_cmd, detach=True)

        if self.FileSystem.file_in_filesystem("ntgrcryptwd"):
            time.sleep(30)
        elif self.brand == "asus" and self.httpd_name == "webs":
            time.sleep(60)
        elif self.brand == 'trendnet':
            time.sleep(30)
        else:
            max_time = 30
            if not self.debug:
                if self.name.startswith("R64") or self.name.startswith("R67") or self.name.startswith("JNR"): # acos_nat_cli, first probe failed, need to sleep a long time
                    max_time += 60
                if self.brand == "tenda" and len(
                        self.FileSystem.get_exe_path_by_name("monitor")) > 0 and service_cmdline == "/bin/httpd":
                    max_time += 30
            
            # Wait for trace log differently based on system/user mode
            if system_flag:
                trace_log_path = "/trace.log"
            else:
                trace_log_path = "/fs/trace.log"
            
            if not system_flag:
                for i in range(0, max_time): # wait for 30 s
                    res = self.env.exec(f"tail -n 10 {trace_log_path}", noprint=True).splitlines()
                    if len(res) > 0 and (res[-1] in ["newselect", "exit", "nosleep", "SIGSEGV", "accept"] or all(line == res[0] for line in res)):
                        break
                    time.sleep(1)
            else:
                time.sleep(max_time)

        # if self.brand == "trendnet":
        #     if self.FileSystem.file_in_filesystem("uci"):
        #         uci = self.FileSystem.get_exe_path_by_name("uci")
        #         self.env.exec(f"chroot /fs /{self.qemu_arch} {uci} set cameo.cameo.setup_wizard_rt=0")
        http_success = None
        if probe:
            http_success = self.probe()
            return http_success

        if service_path in self.cwd_map:
            cwd = self.cwd_map[service_path]
        else:
            cwd = self.cwd

        if probe:
            if len(self.checker.urlchecks) > 0 and self.checker.urlchecks[0].last_status_code == 400:  # QEMU NR_close bug can pollute HTTP response
                if system_flag:
                    # For QemuSysRunner, retry without tracing
                    if cwd != "/" and cwd != "":
                        base_cmd = f"cd {cwd} && {service_cmdline}"
                    else:
                        base_cmd = service_cmdline
                    qemu_httpd_cmd = f"{base_cmd} > /dev/null 2>&1"
                else:
                    # For QemuUserRunner, use the existing approach
                    qemu_httpd_cmd = self.wrap_binary_with_qemu(service_cmdline, stream=True, caught_crash_sig=True, tracelog=False)
                
                self.env.process.kill_process_by_name(self.httpd_path)
                time.sleep(5)
                self.env.exec(qemu_httpd_cmd, detach=True)
                if not self.debug:
                    time.sleep(40)
                else:
                    time.sleep(20)
                http_success = self.probe()

        return http_success


    def set_nvram_ip(self):

        if self.brand == "tenda":
            # US_AC500V1BR_V1.0.0.14_en_TD
            user = self.env.exec("cat /fs/gh_nvram/sys.username")
            password = self.env.exec("cat /fs/gh_nvram/sys.password")

            if user != "user":
                self.env.exec("bash -c 'echo -n admin > /fs/gh_nvram/sys.username'")
                self.env.exec("bash -c 'echo -n YWRtaW4= > /fs/gh_nvram/sys.userpass'")

        if "br0" in self.network_info.keys() and len(self.network_info['br0']) > 0:
            ip_addr = self.network_info['br0'][0]
        else:
            try:
                ip_addr = self.network_info['eth0'][0]
            except:
                ip_addr = "192.168.0.1"
        if self.enable_nvram is True and self.enable_nvram_sematic:
            self.env.exec(f'bash -c "echo -n {ip_addr} > /fs/gh_nvram/lan_ipaddr"') # R6300v2_V1.0.4.18_10.0.84, if not exist lan_ipaddr fix_loop will not fix this error
            nvram_ip = self.env.exec('bash -c "find /fs/gh_nvram -name "lan*ipaddr""')

            for i in nvram_ip.splitlines():
                self.env.exec(f'bash -c "echo -n {ip_addr} > {i}"')


        config_path, datalib_path = "", ""
        if os.path.exists(os.path.join(self.tmp_fs_path, "bin/datalib")):
            config_path = os.path.join(self.tmp_fs_path, "bin/config").replace(self.tmp_fs_path, "")
            datalib_path = os.path.join(self.tmp_fs_path, "bin/datalib").replace(self.tmp_fs_path, "")
        if os.path.exists(os.path.join(self.tmp_fs_path, "/usr/bin/datalib")):
            config_path = os.path.join(self.tmp_fs_path, "/usr/bin/config").replace(self.tmp_fs_path, "")
            datalib_path = os.path.join(self.tmp_fs_path, "/usr/bin/datalib").replace(self.tmp_fs_path, "")


        if len(config_path) > 0 and self.enable_nvram_sematic and self.enable_fix_network:
            ip = self.env.exec(f"chroot fs /{self.qemu_arch} {config_path} get lan_ipaddr")
            if ip:
                ip = ip.strip()
                if len(ip) > 0: # have default ip, e.g. 192.168.1.250
                    if ip != ip_addr:
                        self.potential_urls.append(ip)
                        self.env.exec(f"chroot fs /{self.qemu_arch} {config_path} set lan_ipaddr={ip_addr}")
                else:
                    self.env.exec(f"chroot fs /{self.qemu_arch} {config_path} set lan_ipaddr={ip_addr}", detach=True)
    
    def rehosting_binary(self, httpd_cmdline, fix_round, is_peer_process=False):

        
        service_path = httpd_cmdline.split(" ")[0]
        if service_path == self.httpd_path:
            self.httpd_cmdline = httpd_cmdline
        if service_path in self.cwd_map:
            cwd = self.cwd_map[service_path]
        else:
            cwd = self.cwd
        print("=" * 50)
        print("[rehosting_binary]", service_path)
        print("[httpd_cmdline]", httpd_cmdline)
        
        if not self.enable_3_3:
            http_success = self.run_binary(service_path, httpd_cmdline) # run and probe and eixt
            return http_success
        
        not_found_error = False
        for i in range(0, 2):
            
            self.env.network.reconfig_network(self.network_info)
            

            self.set_nvram_ip()  # for no start with nvram
            

            
            # 1. Rerun and collect strace
            print("\n\n\n")
            print("=" * 20, "[FIX ROUND]", self.fix_round, httpd_cmdline)
            http_success = self.run_binary(service_path, httpd_cmdline)
            if http_success:
                return True
            
            try:
                if self.checker.urlchecks[0].last_status_code == 400: # qemu bug, return "fcntl64(3, F_SETFD,1)=0" in response
                    if not self.system_flag:
                        # Remove qemu binary from container
                        self.env.exec(f"rm -f /fs/{self.qemu_arch}")
                        # Copy qemu binary from host to container
                        
                        self.env.docker_cp_to_container(f"/gh/qemu/{self.qemu_arch}", f"/fs/{self.qemu_arch}")
                    
                    http_success = self.run_binary(service_path, httpd_cmdline)
                if http_success:
                    return True
            except Exception as e:
                print(e)
            
            tracelog_dict = dict()
            restart_env = False
            
            tracelog_dict = self.get_trace_log()
            restart_env = False
            
            if service_path in self.cwd_map:
                cwd = self.cwd_map[service_path]
            else:
                cwd = self.cwd
            
            # Handle system mode vs user mode differently
            # For QemuSysRunner, use strace directly
            if cwd != "/" and cwd != "":
                use_bash = True
            else:
                use_bash = False
            
            try:
                if use_bash:
                    print_id = "1"
                else:
                    print_id = "0"
                for i in tracelog_dict[print_id][-50:]:
                    print(i)
            except Exception as e:
                print(f"Error printing trace log: {e}")
                

            
            # 2. parse strace
            preprocessor = LogPreprocessing(tracelog_dict=tracelog_dict, initial_binary=self.httpd_path)
            process_info, meta_info = preprocessor.parse_files(use_bash=use_bash)
            if is_peer_process:
                found_peer_process = False
            else:
                found_peer_process = True
            
            
            locater = ErrorLocator(process_info, meta_info, meta_info.get("initial_pid", 0),
                                   fixed_errors=self.located_errors[service_path],
                                   fs_path=self.fs_path,
                                   cwd=cwd,
                                   env=self.env,
                                   network_info=self.network_info,
                                   found_peer_process=found_peer_process,
                                   tracelog_dict=tracelog_dict,
                                   enable_create=self.enable_create,
                                   enable_infer=self.enable_infer,
                                   enable_reuse=self.enable_reuse,
                                   enable_fix_in_peer=self.enable_fix_in_peer,
                                   enable_enhance_create=self.enable_enhance_create,
                                   FileSystem=self.FileSystem)
            candidate = locater.locate_errors()
            self.located_errors[service_path].append(candidate)
            print("\n\n[candidate] ")
            pprint(f"{candidate}")
            
            fixer = FixStrategy(brand=self.brand,
                    binary=service_path,
                    fs_path=self.fs_path,
                    filesystem=self.FileSystem,
                    env=self.env,
                    fix_record=self.fix_record,
                    nvram_brand_map=self.nvram_brand_map,
                    nvram_map=self.nvram_map,
                    restart_env=restart_env,
                    fix_round=self.fix_round,
                    )
            
            
            if candidate and candidate.get("category") != "FIX-IN-PEER" and candidate.get("fix_strategy") != "infer_magic_byte": # and candidate type != ipc
    
                fixer.apply_fix(candidate)
                self.global_not_found_error = False
                
                if candidate.get("fix_strategy") == "reuse_file":
                    new_cwd = fixer.cwd
                    if new_cwd != self.cwd:
                        self.cwd = new_cwd
                    
                    if service_path in self.cwd_map:
                        if self.cwd_map[service_path] != new_cwd:
                            self.cwd_map[service_path] = new_cwd
                    else:
                        self.cwd_map[service_path] = new_cwd
            
            elif candidate and candidate.get("category") == "FIX-IN-PEER":
                
                # get ipc process name
                ipc_process_name = candidate.get("peer_process_name")
                
                if self.fs_path in ipc_process_name:
                    ipc_process_name = ipc_process_name.replace(self.fs_path, "")
                    ipc_process_name = ipc_process_name.replace(self.tmp_fs_path, "")
                    
                if f"/tmp/{self.hash}/ori_fs" in ipc_process_name:
                    ipc_process_name = ipc_process_name.replace(f"/tmp/{self.hash}/ori_fs", "")
                
                print(f"ipc_process_name: {ipc_process_name}")
                # get ipc process cmdline
                ipc_process_name_cmdline = self.get_service_cmdline(ipc_process_name)
                if ipc_process_name_cmdline == "":
                    ipc_process_name_cmdline = ipc_process_name
                    
                if "ubusd" in ipc_process_name:
                    self.env.exec("rm /fs/var/run/ubus.sock", detach=True)

                if "self" in ipc_process_name and candidate.get("fix_strategy") == "fix_shared_memory":
                    ipc_process_name_cmdline = httpd_cmdline
                    self.env.exec('sh -c "ipcs -m | awk \'NR>3 {print $2}\' | xargs -r -n1 ipcrm -m; ipcs -s | awk \'NR>3 {print $2}\' | xargs -r -n1 ipcrm -s"')
                    self.env.exec("rm -f /fs/tmp/shm_id")
                    self.env.exec("rm -f /fs/var/tmp/shm_id")
                    self.env.exec("mount -o remount,size=100M /fs/var")
                    self.env.exec("mount -o remount,size=100M /fs/tmp")
                    self.fix_record.add_fix_record(service_path, {
                        "fix_ipc_socket_service": {
                            "type": "fix_ipc_socket_service",
                            "ipc_process_name": service_path,
                            "action": "fix_shared_memory",
                            
                        }
                    },
                   round_num=self.fix_round
                   )                    
                   
                else:
                    self.fix_record.add_fix_record(service_path, {
                        "fix_ipc_socket_service": {
                            "type": "fix_ipc_socket_service",
                            "ipc_process_name": service_path,
                            "action": "recreate",
                            
                        }
                    },
                     round_num=self.fix_round
                    )
                
                self.fix_round += 1
                self.rehosting_binary(ipc_process_name_cmdline, self.fix_round, is_peer_process= True)
                
                
            elif candidate and candidate.get("fix_strategy") == "infer_magic_byte": # run binary again to get pc trace
                self.fix_record.add_fix_record(service_path, {
                    "infer_magic_byte": {
                        "type": "infer_magic_byte",
                        "ipc_process_name": service_path,
                        "action": "infer_magic_byte",
                        
                    }
                }, round_num=self.fix_round)
                
                
                self.run_binary(service_path, httpd_cmdline, pc_trace=True)
                trace_log_host_path_filtered = self.get_pc_trace_log()
                
                # trace_log_path = "/tmp/trace.log"
                # with open(trace_log_path, "w") as f:
                #     for line in trace_log_dict.get('0', []):
                #         f.write(f"{line}\n")
                    
                fixer.infer_magic_bytes(self.bin_path, candidate, trace_log_host_path_filtered)
                os.remove(trace_log_host_path_filtered)
            
            # No error found in strace, rerun without fix
            else:
                not_found_error = True
            
            self.network_info = self.env.network.get_network_info()
            
            if not_found_error: #
                # if self.args.greenhouse_patch:
                    
                #     # tools = ["ip", "ifconfig", "brctl", "vconfig"]
                #     # for tool in tools:
                #     #     for path in Files.find_file_paths(self.tmp_fs_path, tool):
                #     #         # if "greenhouse" in path:
                #     #         #     continue
                #     #         # whether is link or not，*.bak'
                #     #         # *bak -> ori
                #     #         if os.path.exists(f"{path}.bak") and os.path.exists(f"{path}"):
                #     #             shutil.copy(f"{path}",f"{path}_x86")
                #     #             os.unlink(path)
                #     #             os.rename(f"{path}.bak", path)
                                
                #     self.greenhouse_fix_func(
                #         httpd_cmdline, self.args.greenhouse_patch)
                    
                #     # for tool in tools:
                #     #     for path in Files.find_file_paths(self.tmp_fs_path, tool):
                #     #         # if "greenhouse" in path:
                #     #         #     continue
                #     #         # whether is link or not，*.bak'
                #     #         if os.path.exists(f"{path}_x86") and os.path.exists(f"{path}"):
                #     #             shutil.copy(f"{path}",f"{path}.bak")
                #     #             os.unlink(path)
                #     #             os.rename(f"{path}.x86", path)
                                
                #     # ，，3.2
                #     self.fix_round += 1
                #     return None
                if self.global_not_found_error:
                    return False
                else:
                    self.global_not_found_error = True
                    continue
            else: 
                self.fix_round += 1
                return None
    

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

    def min_dockerfile(self, dockerfileDest, ports):
        # construct minimal dockerfile for exporting
        with open(dockerfileDest, "w") as dockerFile:
            dockerFile.write("FROM scratch\n")
            dockerFile.write("ADD fs /\n\n")
            dockerFile.write("ENV LD_PRELOAD=libnvram-faker.so\n")
            if len(self.LD_LIBRARY_PATH_set) > 0:
                LD_LIBRARY_PATH_set = self.LD_LIBRARY_PATH_set.copy()
                LD_LIBRARY_PATH_set.discard("/")
                LD_LIBRARY_PATH_set.discard("")
                LD_LIBRARY_PATH_set.discard("/opt/bitdefender/lib")
                if "/usr/lib" not in LD_LIBRARY_PATH_set:
                    LD_LIBRARY_PATH_set.add("/usr/lib")
                if "/lib" not in LD_LIBRARY_PATH_set:
                    LD_LIBRARY_PATH_set.add("/lib")
                if len(LD_LIBRARY_PATH_set) > 0:
                    dockerFile.write("ENV LD_LIBRARY_PATH=%s\n" % ":".join(LD_LIBRARY_PATH_set))
            dockerFile.write("\n")
            for port in ports:
                dockerFile.write("EXPOSE %s/tcp\n" % port)
                dockerFile.write("EXPOSE %s/udp\n" % port)
            dockerFile.write("\n")
            dockerFile.write("ENTRYPOINT [\"/greenhouse/busybox\", \"sh\", \"/run_clean.sh\"]\n\n")
            dockerFile.write("CMD [\"%s\", \"--\"" % (self.qemu_arch))
            for arg in self.httpd_cmdline.split():
                dockerFile.write(", \"%s\"" % arg.replace("\"", "\'"))
            dockerFile.write("]")
        dockerFile.close()

    def build_run_clean(self, minfs):
        print("Building run_clean.sh wrapper...")
        clean_script_path = os.path.join(minfs, "run_clean.sh")

        clean_command = ["/"+self.qemu_arch]
        if self.hackbind:
            clean_command.extend(["-hackbind"])
        if self.hackdevproc:
            clean_command.extend(["-hackproc"])
        if self.hacksysinfo:
            clean_command.extend(["-hacksysinfo"])

        clean_command.extend(["-execve", "\"/"+self.qemu_arch])
        if self.hackdevproc:
            clean_command.extend(["-hackbind -hackproc"])
        if self.hacksysinfo:
            clean_command.extend(["-hacksysinfo"])
        clean_command.extend(["\""])
        clean_command.extend(["-E", "LD_PRELOAD=\"libnvram-faker.so\""])
        if len(self.LD_LIBRARY_PATH_set) > 0:
            LD_LIBRARY_PATH_set = self.LD_LIBRARY_PATH_set.copy()
            LD_LIBRARY_PATH_set.discard("/")
            LD_LIBRARY_PATH_set.discard("")
            LD_LIBRARY_PATH_set.discard("/opt/bitdefender/lib")
            if "/usr/lib" not in LD_LIBRARY_PATH_set:
                LD_LIBRARY_PATH_set.add("/usr/lib")
            if "/lib" not in LD_LIBRARY_PATH_set:
                LD_LIBRARY_PATH_set.add("/lib")
            if len(LD_LIBRARY_PATH_set) > 0:
                LD_LIBRARY_PATH = ":".join(LD_LIBRARY_PATH_set)
                clean_command.extend(["-E", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}"])
        clean_command.extend(["/bin/sh", "qemu_run.sh"])
        docker_clean_command = " ".join(clean_command)

        with open(clean_script_path, "w") as ws:
            ws.write("#!/bin/sh\n")
            ws.write("\n")
            ws.write("/%s\n" % SETUP_SCRIPT)
            ws.write("\n")
            command = self.get_minimal_command("/bin/sh /%s > /%s 2>&1\n" % (BG_SCRIPT, BG_LOG))
            ws.write(command)
            ws.write("\n")
            ws.write(docker_clean_command)
            ws.write("\n")
            ws.write("while true; do /greenhouse/busybox sleep 100000; done")
        ws.close()
        print("done!")

    def export_config_json(self, dest_dir, result):
        ports = ["80", "1900"]  # also expose UDP ports
        configs = dict()
        qemu_args = dict()

        ipaddr, port, loginurl, logintype, user, password, headers, payload = ("", "", "", "", "", "", "", "")
        # make json dump
        if self.checker is not None:
            ipaddr, port, loginurl, logintype, user, password, headers, payload = self.checker.get_working_ip_set()
            port = port.strip()
            if len(port) > 0 and port not in ports:
                ports.append(port)

        # path to background script
        bg_scripts = []
        bg_path = self.get_minimal_command("/bin/sh /%s" % BG_SCRIPT).strip()
        setup_bind_path = "/%s" % SETUP_SCRIPT
        bg_scripts.append((bg_path, self.bg_sleep))
        bg_scripts.append((setup_bind_path, 1))

        # add extra qemu arguments
        otherargs = "/" + self.qemu_arch
        if self.hackbind:
            qemu_args["hackbind"] = ""
            otherargs += " -hackbind"
        if self.hackdevproc:
            qemu_args["hackproc"] = ""
            otherargs += " -hackproc"
        if self.hacksysinfo:
            qemu_args["hacksysinfo"] = ""
            otherargs += " -hacksysinfo"
        qemu_args["execve"] = otherargs

        configs["image"] = self.name
        configs["hash"] = self.hash
        configs["brand"] = self.brand
        configs["result"] = result
        configs["seconds_to_up"] = 60
        configs["targetpath"] = self.httpd_path
        configs["targetip"] = ipaddr
        configs["targetport"] = port
        configs["ipv6enable"] = self.ipv6enable
        env_dict = {"LD_PRELOAD": "libnvram-faker.so"}
        if len(self.LD_LIBRARY_PATH_set) > 0:
            LD_LIBRARY_PATH_set = self.LD_LIBRARY_PATH_set.copy()
            LD_LIBRARY_PATH_set.discard("/")
            LD_LIBRARY_PATH_set.discard("")
            LD_LIBRARY_PATH_set.discard("/opt/bitdefender/lib")
            if "/usr/lib" not in LD_LIBRARY_PATH_set:
                LD_LIBRARY_PATH_set.add("/usr/lib")
            if "/lib" not in LD_LIBRARY_PATH_set:
                LD_LIBRARY_PATH_set.add("/lib")
            if len(LD_LIBRARY_PATH_set) > 0:
                env_dict["LD_LIBRARY_PATH"] = ":".join(LD_LIBRARY_PATH_set)
        configs["env"] = env_dict
        configs["workdir"] = self.last_bincwd
        configs["background"] = bg_scripts
        configs["loginuser"] = user
        configs["loginpassword"] = password
        configs["loginurl"] = loginurl
        configs["logintype"] = logintype
        configs["loginheaders"] = headers
        configs["loginpayload"] = payload
        configs["qemuargs"] = qemu_args
        try:
            netdev = NetworkUtil.get_dev_by_ip(self.network_info, ipaddr)
        except Exception as e:
            print(e)
            netdev = ""
        configs["netdev"] = netdev
        jsonFileDest = os.path.join(dest_dir, "config.json")
        with open(jsonFileDest, "w") as jsonFile:
            json.dump(configs, jsonFile, indent=6)
        jsonFile.close()
        return ports

    def build_run_sh(self, debugfs):
        print("Building run.sh wrapper...")
        run_script_path = os.path.join(debugfs, "run.sh")

        with open(run_script_path, "w") as ws:
            ws.write("#!/bin/sh\n")
            ws.write("\n")
            ws.write("chroot /%s /%s\n" % (DOCKER_FS, SETUP_SCRIPT)) # chroot /fs /run_setup.sh
            ws.write("\n")
            command = self.get_script_command("/bin/sh /%s > /%s/%s 2>&1\n" % (BG_SCRIPT, DOCKER_FS, BG_LOG))  # /bin/sh /run_background.sh
            ws.write(command)
            ws.write("\n")
            cmdline = self.wrap_binary_with_qemu("/bin/sh", args='qemu_run.sh', tracelog=False)
            ws.write(cmdline)
            ws.write("\n")
            ws.write("echo \"%s\"$? >> /%s/%s" % (EXIT_CODE_TAG, DOCKER_FS, GREENHOUSE_LOG))
            ws.write("\n")
            ws.write("echo \"%s\" > %s" % (EXIT_CODE_TAG, DONE_TAG))
            ws.write("\n")
            ws.write("while true; do sleep 10000; done")
            ws.write("\n")
        ws.close()
        org_mode = os.stat(run_script_path)
        os.chmod(run_script_path, org_mode.st_mode | stat.S_IXUSR)

        # create debug script
        debugRun = os.path.join(debugfs, "run_debug.sh")
        with open(debugRun, "w") as df:
            df.write("#!/bin/sh\n")
            df.write("\n")
            df.write("chroot /%s /%s\n" % (DOCKER_FS, SETUP_SCRIPT))
            df.write("\n")
            command = self.get_script_command("/bin/sh /%s > /%s/%s 2>&1\n" % (BG_SCRIPT, DOCKER_FS, BG_LOG))
            df.write(command)
            df.write("\n")
            command = self.get_script_command("/bin/sh /qemu_run.sh\n")
            df.write(command)
            df.write("\n")
            df.write("while true; do sleep 10000; done")
        df.close()
        org_mode = os.stat(debugRun)
        os.chmod(debugRun, org_mode.st_mode | stat.S_IXUSR)

    def build_run_bg_sh(self, fs, working_ip, xmldb_bg_cmd):
        print("Building run_background.sh...")

        bg_cmd = []
        if self.FileSystem.file_in_filesystem("datalib"):
            bg_cmd.append("/bin/datalib &")
            bg_cmd.append("/bin/config set dns_hijack=0 &")
            bg_cmd.append(f"/bin/config set lan_ipaddr={working_ip} &")
            bg_cmd.append("/bin/sleep 2")
            self.ipc_process = "datalib"

        if self.FileSystem.file_in_filesystem("xmldb"):
            bg_cmd = xmldb_bg_cmd
            self.ipc_process = "xmldb"

        # check ubus
        httpd_path = self.FileSystem.get_rel_path(self.httpd_path)
        flag = binary_containt_strings(os.path.join(self.fs_path, httpd_path), "ubus.sock")
        if flag:
            ubus_path = self.FileSystem.get_exe_path_by_name("ubusd")
            bg_cmd.append(f"{ubus_path} &")
            self.ipc_process = "ubus"
            
        # check inetd
        httpd_path = self.FileSystem.get_rel_path(self.httpd_path)
        if binary_containt_strings(os.path.join(self.fs_path, httpd_path), "/var/run/inetd.pid"):
            inetd_path = self.FileSystem.get_exe_path_by_name("inetd")
            if inetd_path:
                bg_cmd.append(f"{inetd_path} &")

        cfg_manager = os.path.join(self.fs_path, "userfs/bin/cfg_manager")
        if os.path.exists(cfg_manager):
            bg_cmd.append(f"{cfg_manager} &")


        bg_script_path = os.path.join(fs, BG_SCRIPT)
        with open(bg_script_path, "w") as ws:
            ws.write("#!/bin/sh\n")
            ws.write("\n")
            ws.write("\n")
            for base_cmd in bg_cmd:
                ws.write(base_cmd)
                ws.write("\n")
        ws.close()
        org_mode = os.stat(bg_script_path)
        os.chmod(bg_script_path, org_mode.st_mode | stat.S_IXUSR)

    def build_run_setup_sh(self, mindest, interface_cmds, flag):
        # modify run_setup script for standalone fuzzing
        setupRun = os.path.join(mindest, "run_setup.sh")
        setup_interface = os.path.join(mindest, "interface_setup.sh")

        with open(setupRun, "w") as pf:
            pf.write("#!/bin/sh\n")
            pf.write("\n")
            # pf.write("/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev\n") # 0522 update, delete
            pf.write("/greenhouse/busybox touch /dev/null\n") # random and urandom use mount

            pf.write("/greenhouse/busybox cp -r /ghtmp/* /tmp\n")
            pf.write("/greenhouse/busybox cp -r /ghetc/* /etc\n")
            pf.write("\n")
            # pf.write(interface_cmds.replace("/fs/greenhouse/ip", "/greenhouse/ip").replace('bash -c "', '').replace('\"', ''))

            # update, use fuzz.sh to set netdev
            if flag == "min": # debug use docker-compose
                for cmd in interface_cmds:
                    pf.write(f"/greenhouse/busybox {cmd}\n")
                # pf.write("/greenhouse/ip addr flush dev eth0\n")
                # for devName, ip_list in self.network_info.items():
                #     if len(ip_list) > 0:
                #         url = ip_list[0]
                #     else:
                #         url = '0.0.0.0'
                #     if devName == "lo":
                #         continue
                #     pf.write("/greenhouse/ip link add %s type dummy\n" % devName)
                #     pf.write("/greenhouse/ip addr add %s/24 dev %s\n" % (url, devName))
                #     pf.write("/greenhouse/ip link set %s up\n" % devName)
        pf.close()
        Files.chmod_exe(setupRun)


        with open(setup_interface, "w") as pf:
            pf.write("#!/bin/sh\n")
            pf.write("\n")
            pf.write("/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev\n")
            pf.write("/greenhouse/busybox cp -r /ghtmp/* /tmp\n")
            pf.write("/greenhouse/busybox cp -r /ghetc/* /etc\n")
            pf.write("\n")

            if flag == "min":  # debug uses docker-compose
                for devName, ip_list in self.network_info.items():
                    if len(ip_list) > 0:
                        url = ip_list[0]
                    else:
                        url = '0.0.0.0'
                    if devName == "lo":
                        continue
                    # If the interface already exists (e.g. eth0 from Docker), flush and reconfigure;
                    # otherwise create it as a dummy interface.
                    pf.write("if /greenhouse/ip link show %s >/dev/null 2>&1; then\n" % devName)
                    pf.write("  /greenhouse/ip addr flush dev %s\n" % devName)
                    pf.write("else\n")
                    pf.write("  /greenhouse/ip link add %s type dummy\n" % devName)
                    pf.write("fi\n")
                    pf.write("/greenhouse/ip addr add %s/24 dev %s\n" % (url, devName))
                    pf.write("/greenhouse/ip link set %s up\n" % devName)
        pf.close()
        Files.chmod_exe(setup_interface)

    def build_setup_dev_sh(self, fs):
        setup_dev = os.path.join(self.basepath, "tools", "scripts", "setup_dev.sh")
        dst = os.path.join(fs, "setup_dev.sh")
        Files.copy_file(setup_dev, dst)
        Files.chmod_exe(dst)
        
    def save_container_fs_to_host(self, local_path, kill=True):
        tar_file = f"{self.hash}.tar.gz"
        
        if os.path.exists(local_path):
            Files.rm_folder(local_path)
        
        if not os.path.exists(local_path):
            Files.mkdir(local_path)

        # kill all pid in docker container
        if kill:
            self.docker_manager.kill_all_pid_in_docker()
        # umount special dir
        
            self.env.exec("/bin/sh /fs/clean_fs.sh") # delete special files
            time.sleep(10)

        tar_file_local_path = os.path.join("/tmp", tar_file)
        if os.path.exists(tar_file_local_path):
            Files.rm_file(tar_file_local_path)
            

            
        # Replace block and character devices in /fs/dev with empty regular files
        sanitize_dev_cmd = (
            "find /fs/dev -type b -o -type c | while read f; do rm -f \"$f\" && touch \"$f\"; done"
        )
        self.env.exec(f"/bin/sh -c '{sanitize_dev_cmd}'", detach=True)
        time.sleep(5)

        cmd = f"tar -C /fs -cf /{tar_file} --numeric-owner --exclude=proc --exclude=sys --exclude='*.sock' --exclude='*.fifo' --exclude='*.pipe' ."
        self.env.exec(cmd, detach=True)
        if not self.debug:
            time.sleep(40)
        else:
            time.sleep(10)

        self.docker_manager.docker_cp_to_host(f"/{tar_file}", "/tmp")
        time.sleep(3)
        
        cmd = ["tar", "-xvf", f"/tmp/{tar_file}", "-C", local_path, "--strip-components=1"]
        print(cmd)
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        new_fs = local_path
        assert len(os.listdir(new_fs)) != 0, "Filesystem copy failed: directory is empty"
        
        if os.path.exists(tar_file_local_path):
            Files.rm_file(tar_file_local_path)
        
        return new_fs


    def export_rehosting_container(self, result, working_ip, httpd_cmdline, interface_cmds):

        # export bg data
        xmldb_bg_cmd = []
        if self.FileSystem.file_in_filesystem("xmldb"): # TODO, add a dir "bg_script"
            xmldb_path = self.FileSystem.get_exe_path_by_name('xmldb')
            xmldbc_path = self.FileSystem.get_exe_path_by_name('xmldbc')

            # dump xml data
            xmldb_cmd = self.get_service_cmdline(xmldb_path)
            dump_cmd = f"bash -c 'chroot /fs /{self.qemu_arch} {xmldbc_path} -D xmldb_data'"
            self.env.exec(dump_cmd)

            # for load xml data
            xmldb_bg_cmd.append(f"{xmldb_cmd} &")
            xmldb_bg_cmd.append("sleep 3")
            if "var/etc" in httpd_cmdline: # DAP_1522, /sbin/httpd -s "wapnd01_dlink_dap1522" -f "/var/etc/httpd.cfg"
                xmldb_bg_cmd.append(f'{xmldbc_path} -l "xmldb_data"')
            else:
                xmldb_bg_cmd.append(f'{xmldbc_path} -L "xmldb_data"')

        
        local_path = os.path.join("/tmp", f"{self.name}_container")
        dest_dir = os.path.join("/tmp", f"{self.name}_rehosted")
        
        if os.path.exists(local_path):
            Files.rm_folder(local_path)
        if not os.path.exists(local_path):
            os.mkdir(local_path)
        if os.path.exists(dest_dir):
            Files.rm_folder(dest_dir)
        if not os.path.exists(dest_dir):
            os.mkdir(dest_dir)

        
        new_fs = self.save_container_fs_to_host(local_path) # local_path/fs
        
        
        # Store current working directory
        original_cwd = os.getcwd()

        # Change working directory to new_fs
        os.chdir(new_fs)

        # Remove special virtual devices that will be recreated later
        special_devices = [
            "dev/null",
            "dev/random",
            "dev/urandom"
        ]
        for device in special_devices:
            if os.path.exists(device):
                os.remove(device)

        # Remove shared memory ID file
        shm_id_path = "tmp/shm_id"
        if os.path.exists(shm_id_path):
            os.remove(shm_id_path)

        # Remove all character, block, socket and pipe special files
        subprocess.run("find . \( -type c -o -type b -o -type s -o -type p \) -exec rm -f {} \;", shell=True)

        # Remove core dump files
        subprocess.run("find . -type f -name '*.core' -exec rm -f {} +", shell=True)

        # Change back to original working directory
        os.chdir(original_cwd)


        minimal_folder = "minimal"
        debug_folder = "debug"

        mindest = os.path.join(dest_dir, minimal_folder)
        mindestfs = os.path.join(mindest, "fs")
        debugdest = os.path.join(dest_dir, debug_folder)
        debugdestfs = os.path.join(debugdest, "fs")
        if not os.path.exists(mindest):
            Files.mkdir(mindest, silent=True)
        Files.copy_directory(new_fs, mindestfs)
        if not os.path.exists(debugdest):
            Files.mkdir(debugdest, silent=True)
        Files.copy_directory(new_fs, debugdestfs)

        # copy tmp and etc folders for minimal container
        tmp_path = str(pathlib.Path(os.path.join(mindestfs, "tmp")).resolve())  # handle symlinks
        if not tmp_path.startswith(mindestfs):
            tmp_path = os.path.join(mindestfs, tmp_path.strip("/"))
        if not os.path.exists(tmp_path):
            Files.mkdir(tmp_path, silent=True)
        Files.copy_directory(tmp_path, os.path.join(mindestfs, "ghtmp"))
        # copy etc folder for min container
        etc_path = str(pathlib.Path(os.path.join(mindestfs, "etc")).resolve())  # handle symlinks
        if not etc_path.startswith(mindestfs):
            etc_path = os.path.join(mindestfs, etc_path.strip("/"))
        if not os.path.exists(etc_path):
            Files.mkdir(etc_path, silent=True)
        Files.copy_directory(etc_path, os.path.join(mindestfs, "ghetc"))

        incremental_copy(os.path.join(mindestfs, "dev"), os.path.join(mindestfs, "ghdev"))  # /dev will be replaced at runtime

        ports = self.export_config_json(dest_dir, result)

        # create dockerfile in minfs
        dockerfileDest = os.path.join(mindest, "Dockerfile")
        self.min_dockerfile(dockerfileDest, ports)

        # create debug dockerfile in debugfs
        dockerfileDest = os.path.join(debugdest, "Dockerfile")
        # construct debug dockerfile for exporting
        with open(dockerfileDest, "w", newline="\n") as dockerFile:
            dockerFile.write(DEBUG_COMMANDS)
        dockerFile.close()
 
        # create qemu_run.sh wrapper for the service command
        qemu_run_path = os.path.join(self.tmp_fs_path, "qemu_run.sh")
        with open(qemu_run_path, 'w') as qemu_run:
            if self.cwd != "/" and len(self.cwd) > 0:
                qemu_run.write(f"cd {self.cwd}" + '\n')
            qemu_run.write(httpd_cmdline + '\n')
        qemu_run_MinDest = os.path.join(mindestfs, "qemu_run.sh")
        qemu_run_DebugDest = os.path.join(debugdestfs, "qemu_run.sh")
        if os.path.exists(qemu_run_path):
            Files.copy_file(qemu_run_path, qemu_run_MinDest, silent=True)
            Files.copy_file(qemu_run_path, qemu_run_DebugDest, silent=True)

        # run_clean.sh in minfs
        self.build_run_clean(mindestfs)

        # run_setup.sh
        self.build_run_setup_sh(mindestfs, interface_cmds, "min")
        self.build_run_setup_sh(debugdestfs, interface_cmds, "debug")

        # run.sh
        self.build_run_sh(debugdestfs)
        self.build_run_sh(mindestfs)
        


        self.build_run_bg_sh(debugdestfs, working_ip, xmldb_bg_cmd)
        self.build_run_bg_sh(mindestfs, working_ip, xmldb_bg_cmd)

        # no need setup dev, use cmdlien to set /dev/urandom
        # setup_dev.sh for minfs and debugfs
        # self.build_setup_dev_sh(debugdestfs)
        # self.build_setup_dev_sh(mindestfs)

        # copy the docker-compose
        composeSrc = os.path.join(self.tmp_fs_path, "docker-compose.yml")
        composeMinDest = os.path.join(mindest, "docker-compose.yml")
        composeDebugDest = os.path.join(debugdest, "docker-compose.yml")
        if os.path.exists(composeSrc):
            Files.copy_file(composeSrc, composeMinDest, silent=True)
            Files.copy_file(composeSrc, composeDebugDest, silent=True)

        # some firmware /bin/sh is broken
        sh = os.path.join(mindestfs, "bin", "sh")
        busybox = os.path.join(mindestfs, "bin", "busybox")

        print("Checking binary at ", sh)
        sp = subprocess.run(["file", sh], stdout=PIPE, stderr=PIPE)
        stdout = sp.stdout.decode('u8')
        stdout = stdout.replace(sh, "")
        print("    - ", stdout)
        if ": data" in stdout:
            try:
                curr_dir = os.getcwd()
                print(curr_dir)
                os.chdir(os.path.dirname(sh))

                os.remove("sh")
                os.symlink("busybox", "sh")

                os.chdir(curr_dir)
            except Exception as e:
                print("[error] some firmware /bin/sh is broken")
                print(e)


        # clean fs
        print("Cleaning up ", self.fs_path)
        ARTIFACTS = ["GREENHOUSE_WEB_CANARY", "shm_id", "GH_SUCCESSFUL_BIND", "QEMU_CMDLINE"]

        for root, dirs, files in os.walk(mindestfs, topdown=False):
            for f in files:
                if f in ARTIFACTS or f.startswith("trace.log"):
                    path = os.path.join(root, f)
                    Files.rm_target(path, silent=True)
            for d in dirs:
                if d in ARTIFACTS:
                    path = os.path.join(root, d)
                    Files.rm_target(path, silent=True)
        print("...done!")

    def run_init_bash(self):
        def read_first_line(file_path):
            try:
                with open(file_path, 'r') as file:
                    first_line = file.readline()
                    return first_line
            except Exception as e:
                return f"read_first_line: {e}"

        first_line = read_first_line(self.entry.init_bash)
        if "/etc/rc.common" in first_line:
            bash_cmd = f"chroot /fs /greenhouse/busybox sh /etc/rc.common {self.entry.init_bash} {self.entry.init_bash_args} &"
        else:
            bash_cmd = f"chroot /fs {self.entry.init_bash} {self.entry.init_bash_args}"

        self.env.exec(bash_cmd, detach=True, tty=True)

    def wrap_binary_with_cwd(self, filename, cwd, cmd):
        print("[wrap_binary_with_cwd]", cwd)
        print("[wrap_binary_with_cwd]", filename, cmd)
        service_sh_dst = f"{FS}/{filename}"  # build a bash script for run binary with cwd
        service_sh_src = os.path.join(self.fs_path, filename)
        if not os.path.exists(service_sh_src): # only do once
            with open(service_sh_src, 'w') as f:
                f.write("#!/bin/sh\n")
                f.write(f"cd {cwd}\n")
                f.write(f"{cmd}\n")
                f.flush()
            os.chmod(service_sh_src, 0o777)
            self.docker_manager.docker_cp_to_container(service_sh_src, service_sh_dst)
            self.env.exec("chmod 777 /fs/run.sh")
            time.sleep(2)

    def get_last_executed_on_chain(self, process_dict):
        worklist = []
        
        if len(self.call_chain) > 0:
            worklist = self.call_chain
        else:
            worklist.append(self.entry.init_binary)
            if len(self.entry.init_bash) > 0:
                worklist.append(self.entry.init_bash)
            worklist.append(self.httpd_path)
        
        last_node = worklist[0]  # set init to last node
        last_node_cmdline = last_node
        for node in self.call_chain:
            cmdline = self.get_service_cmdline(node, process_dict)
            if len(cmdline) > 0:
                last_node = node
                last_node_cmdline = cmdline

        return last_node, last_node_cmdline
    
    
    def get_execve_trace_set(self):
        if not self.system_flag:
            # Use existing Docker implementation
            execve_trace_path = os.path.join(DOCKER_FS, f"EXECVE_TRACE")
            execve_trace = self.env.exec(f"cat {execve_trace_path}")
            return execve_trace.split("\n")
        else:
            # Parse QEMU system mode log for execve_trace and environment variables
            execve_trace_set = []
            try:
                with open("/tmp/qemu.final.serial.log", 'r') as f:
                    lines = f.readlines()
                    
                    for i, line in enumerate(lines):
                        if "[ANALYZE]" in line and "PID:" in line:
                            # Extract the command following the colon
                            parts = line.split("]: ", 1)
                            if len(parts) > 1:
                                command = parts[1].strip()
                                execve_trace_set.append(command)
                                
                                # Check for environment variables in the next line
                                if i + 1 < len(lines) and "envp:" in lines[i + 1]:
                                    # For httpd command, store the environment variables
                                    httpd_basename = os.path.basename(self.httpd_path)
                                    cmd_parts = command.split()
                                    if cmd_parts and (
                                            cmd_parts[0] == self.httpd_path or cmd_parts[0] == httpd_basename):
                                        self.envp_init = lines[i + 1].strip().replace("envp: ", "")
            except Exception as e:
                print(f"Error parsing execve trace from qemu log: {e}")
            
            return execve_trace_set

    def get_service_cmdline(self, service_path, _process_dict=None):
        def get_cwd(pid):
            print("[get_cwd]", pid)
            # Use previously determined cwd if available
            if service_path in self.cwd_map:
                cwd = self.cwd_map[service_path]
            else:
                cwd = self.cwd
                
            if cwd != "" and cwd != "/":
                return cwd
            
            path = self.env.exec(f"{BUSYBOX} readlink /proc/{pid}/cwd")
            path = path.strip()
            if path == FS:
                return "/"
            else:
                return path.replace(FS, "")  # /fw/www -> /www
        
        if len(self.httpd_cmdline) > 0 and os.path.basename(service_path) == os.path.basename(self.httpd_path):
            return self.httpd_cmdline
        
        httpd_cmdline = ""
        service_name = os.path.basename(service_path)

        if _process_dict:
            process_dict = _process_dict
        else:
            process_dict = self.env.process.get_process_dict()
        
        print("get_service_cmdline1")
        for pid, ps in process_dict.items():
            if ".sh" in ps: # exclude webs.sh
                continue
            
            if ps.startswith("./"):
                ps = ps[2:]
            index = -1
            if service_path in ps:
                index = ps.find(service_path)
                
            elif os.path.basename(service_path) == os.path.basename(ps.split(" ")[0]):
                index = ps.find(service_name)

            if index != -1:
                line = ps[index:]  # start from args
                args = self.parse_cmdline(line.replace("+", "").lstrip())
                httpd_cmdline = service_path + args
                if self.brand != 'dlink' and "-f" not in httpd_cmdline and "-d" not in httpd_cmdline and "www" not in httpd_cmdline and "root" not in httpd_cmdline:
                    self.cwd = get_cwd(pid) # FIXME: bug here, check cwd in later by tracelog. 0326, tmp use thish
                    
                    self.cwd_map[service_path] = self.cwd
                self.envp_init = self.env.exec(f"cat /proc/{pid}/environ")
                return httpd_cmdline
        
        print("get_service_cmdline2")
        execve_trace_set  = self.get_execve_trace_set()
        
        for line in execve_trace_set:
            if ".sh" in line:
                continue
            if line.startswith(service_path) and "lighttpd-angel" not in line and "lighttpd-port" not in line:
                httpd_cmdline = line.strip()
                return httpd_cmdline

        if self.FileSystem.file_in_filesystem("ubus"):
            for line in execve_trace_set:
                if "/bin/ubus call service set " in line and self.httpd_name in line:
                    try:
                        line = line.replace("/bin/ubus call service set ", "")
                        data = json.loads(line)
                        httpd_cmdline = " ".join([i.replace("\\","") for i in data['instances']['instance1']['command']])
                        return httpd_cmdline
                    except Exception as e:
                        print(e)
                        print('self.FileSystem.file_in_filesystem("ubus")')
        
        print("get_service_cmdline3")
        # try to get httpd cmdline from bash trace
        if self.system_flag:
            bashDockerPath = f"/{BASH_RECORD}"
        else:
            bashDockerPath = os.path.join(DOCKER_FS, BASH_RECORD)
        bash_record = self.env.exec(f"cat {bashDockerPath}")
        execute_lines, _ = parse_bash_trace_log(bash_record)

        for line in execute_lines:
            line = line.replace("+", "").lstrip()
            if line.startswith(service_path):
                tmp_cmdline = line.replace("+ ", "").lstrip()
                httpd_cmdline = service_path + self.parse_cmdline(tmp_cmdline)
                return httpd_cmdline
            
            if self.FileSystem.get_full_path(service_path):
                first_part = line.split(" ")[0]
                
                # + lan.sh
                if os.path.basename(first_part) == os.path.basename(service_path) and \
                        "=" not in first_part: # + UHTTPD_BIN=/usr/sbin/uhttpd, no space
                    httpd_cmdline = line
                    return httpd_cmdline
                
            #  start-stop-daemon -q -S -p /var/run/nice.pid -x /bin/nice -- -n -20 /usr/sbin/dnsmasq -C /var/etc/dnsmasq.conf
            if line.startswith("start-stop-daemon") and service_path in line:
                arg = line.split(service_path)[-1]
                httpd_cmdline = service_path + arg
                return httpd_cmdline
        
        print("get_service_cmdline4")
        # 2. if can't find httpd cmdline with path, use service_name
        find_flag = False
        for pid, ps in process_dict.items():
            if service_name in ps:  # /etc/mini_httpd -> /sbin/mini_httpd
                ps_path = ps.split(" ")[0]

                # check process path is equal with service_path
                if ps_path == service_path:  # no symbolic link
                    find_flag = True
                else:  # symbolic link
                    path = self.env.exec(f"chroot fs /greenhouse/busybox readlink {ps_path}")
                    path = path.strip()
                    if self.FileSystem.filepath_exist_in_filesystem(path, True):
                        find_flag = True

                if find_flag:
                    index = ps.find(service_name)
                    if index != -1:
                        line = ps[index:]  # start from args
                        args = self.parse_cmdline(line.replace("+", "").lstrip())
                        httpd_cmdline = service_path + args
                        self.envp_init = self.env.exec(f"cat /proc/{pid}/environ")
                        return httpd_cmdline

        return httpd_cmdline
    
    def rsf_check(self):
        print("rsf_check")
        ipaddr, port, loginurl, logintype, user, password, headers, payload = self.checker.get_working_ip_set()
        
        if self.brand == "dlink":
            try:
                ipaddr = self.env.network.get_network_info()["br0"][0]
            except:
                pass
        
        if len(ipaddr) == 0:
            self.probe()
            ipaddr, port, loginurl, logintype, user, password, headers, payload = self.checker.get_working_ip_set()
        
        if len(ipaddr) == 0:
            ipaddr = "192.168.0.1"
        
        if len(port) == 0:
            port = "80"
        
        print(ipaddr, port, loginurl, logintype, user, password, headers, payload)
    
        GH_PATH_TRAVERSAL = "/fw/firmwell/greenhouse_files/GH_PATH_TRAVERSAL"
        self.docker_manager.docker_cp_to_container(GH_PATH_TRAVERSAL, f"/fs/GH_PATH_TRAVERSAL")
        etc_passwd_set = set()
        etc_passwd = self.env.exec(
            f'bash -c "find fs -type d \( -path fs/proc -o -path fs/sys \) -prune -o  -type f -name passwd"')
        if "No such file or directory" not in etc_passwd:
            for i in etc_passwd.splitlines():
                if "passwd" in i:
                    etc_passwd_set.add(i)
        
        etc_passwd_set.add("fs/etc/passwd")
        etc_passwd_set.add("fs/etc_ro/passwd")
        
        for file in etc_passwd_set:
            self.env.exec(f"rm /{file}")
            self.docker_manager.docker_cp_to_container(GH_PATH_TRAVERSAL, f"/{file}")
        
        rsf_checker = RsfChecker(ipaddr, port, user, password, self.hash, self.name, self.args.logpath)
        rsf_checker.probe()
        
        file_list_after_probe = self.env.exec("ls /fs").splitlines()
        print("file_list_after_probe")
        print(file_list_after_probe)
        
        rsf_checker.post_probe(file_list_after_probe)
        
        rsf_checker.process_result(self.rsfpath)
    
    def start_env(self, ports, network_config, mac):
        """Start the QEMU emulation environment (user-mode Docker or system-mode).

        Builds init and run scripts, creates the appropriate runner (QemuUserRunner
        or QemuSysRunner), and starts the container. Retries with blank state if
        the first attempt fails.
        """
        start_with_blank_state = False
        
        if self.httpd_path == "boa":
            start_with_blank_state = True  # D-Link boa requires blank state init

        for i in range(0, 2):  # start docker container for 2 times
            
            self.build_init_script(start_with_blank_state)
            self.build_run_script()
            
            print("Building rehosting environment...")
            
            # Use QemuSysRunner for system mode or DockerManager for user mode
            if self.system_flag:
                print("Starting QEMU System Mode...")
                system_runner = QemuSysRunner(
                    network_config,
                    self.basepath, self.fs_path, self.bin_path, self.qemu_arch,
                    self.name, self.debug, self.hash, self.brand, self.rehost_type,
                    self.entry, self.checker, self.kill_hang_process, self.enable_create,
                    self.enable_fix_bg_process, self.fix_record, self.rsfpath,
                    self.enable_basic_procfs, self.args,
                    self.no_cmdline, self.no_ipc, self.enable_fix_in_peer,
                    self.enable_3_3, self.FileSystem, self.args.jobindex,
                    self.firmae_path, self.FIRMWELL_EXECUTE
                )
                self.docker_manager = system_runner
                DOCKER_FS = "/"
                status = system_runner.start_rehosting_env(
                    self.tmp_fs_path, ports, network_config, mac,
                    enable_basic_procfs=self.enable_basic_procfs,
                    use_ipv6=self.use_ipv6
                )
            else:
                print("Starting QEMU User Mode in Docker...")
                docker_manager = QemuUserRunner(
                    self.tmp_dir, self.tmp_fs_path, self.hash, self.debug, self.name,
                    self.args, self.FileSystem
                )
                
                
                self.docker_manager = docker_manager
                status = docker_manager.start_rehosting_env(
                    self.tmp_fs_path, ports, network_config, mac,
                    enable_basic_procfs=self.enable_basic_procfs,
                    use_ipv6=self.use_ipv6
                )
            
            if status is True:
                from firmwell.backend.utils.ProcessUtil import ProcessUtil
                from firmwell.backend.utils.NetworkUtil import NetworkUtil
                
                self.docker_manager.process = ProcessUtil(self.docker_manager, self.FileSystem)
                self.docker_manager.network = NetworkUtil(self.docker_manager)
                
                # Create appropriate environment wrapper based on mode
                self.env = self.docker_manager  # QemuSysRunner already implements RehostingEnv
                
                self.start_watchdog()
                
                
                if start_with_blank_state:  # init binary failed to run, start manually
                    # start init binary or bash
                    if len(self.entry.init_bash) > 0:
                        self.run_init_bash()
                    else:
                        if "rc" in self.entry.init_binary:
                            cmdline = "/sbin/init"
                        else:
                            cmdline = self.entry.init_binary
                        self.run_binary(self.entry.init_binary, cmdline, probe=False, tracelog=False)
                break
            else:
                print("Environment startup failed, retry\n\n\n")
                start_with_blank_state = True  # start container for rehost pid 1 program
        
        print("...created! Beginning Emulation.")

    def build_call_chain(self):
        call_chain_info = os.path.join("/tmp/", f"{self.hash}", f"{self.hash}_callchain.json")
        print(f"call_chain_info: {call_chain_info}")
        
        if os.path.exists(call_chain_info):
            self.call_chain = json.load(open(call_chain_info))
        call_chain_info = os.path.join("/shared/callchain/", f"{self.hash}_callchain.json")
        if os.path.exists(call_chain_info):
            self.call_chain = json.load(open(call_chain_info))
            if self.call_chain is not None:
                return
        
        if self.call_chain is not None:
            return
        
        
        if self.args.nobuildcallchain:
            self.call_chain = []
            return
        
        cc = CallChainConstructor(self.hash, self.FileSystem, self.config)
        self.call_chain = cc.run(self.entry, self.httpd_path)
        
        call_chain_info = os.path.join("/tmp/", f"{self.hash}", f"{self.hash}_callchain.json")
        
        if self.call_chain is not None and len(self.call_chain) > 0:
            if os.path.exists(os.path.dirname(call_chain_info)):
                json.dump(self.call_chain, open(call_chain_info, "w"), indent=4)
            
        
        if self.call_chain is None or len(self.call_chain) == 0:
            self.call_chain = []
        #     if len(self.entry.init_binary) > 0:
        #         self.call_chain.append(self.entry.init_binary)
        #     if len(self.entry.init_bash) > 0:
        #         self.call_chain.append(self.entry.init_bash)
        #     self.call_chain.append(self.httpd_path)
        #
        #     print("call chain failed, use default call chain")
        #     pprint(self.call_chain)
        #     return

    def copy_gh_qemu_to_container(self, planter):
        qemu_path = planter.get_qemu_run_path()
        qemu_arch = planter.get_qemu_arch()

        if not os.path.exists(qemu_path):
            print(f"QEMU binary not found: {qemu_path}")
            return

        qemu_filename = os.path.basename(qemu_path)
        qemu_gh_filename = f"{qemu_filename}-gh"
        container_qemu_path = os.path.join("/fs", qemu_gh_filename)

        self.docker_manager.docker_cp_to_container(qemu_path, container_qemu_path)
        print(f"Copied GH QEMU to: {container_qemu_path}")
        
        
    def greenhouse_fix_func(self, error_process_cmdline, only_use_greenhouse_patch=False):
        """Apply Greenhouse fix logic by saving the filesystem and running the GH patch loop."""
        print("greenhouse fix")
        localgh_fs_path = "/tmp/greenhouse_fs"
        self.save_container_fs_to_host(localgh_fs_path, kill=False)

        new_bin_path = os.path.join(localgh_fs_path, get_rel_path(self.httpd_path))
        
        def remove_leading_space(s):
            if s.startswith(' '):
                return s[1:]
            return s
        
        new_run_args = error_process_cmdline.replace(self.httpd_path, "")
        new_run_args = remove_leading_space(new_run_args)
        
        print("[FW_GH_CMDLINE]", error_process_cmdline)
        print("FW_GH_ARGS]", new_run_args)

        
        import sys
        sys.path.append('/fw')
        from firmwell.eval_gh.Greenhouse.gh import call_patch_loop

        gh_path = "/fw/firmwell/eval_gh/Greenhouse/greenhouse_files"
        scripts_path = "/fw/firmwell/eval_gh/Greenhouse/scripts"
        qemu_src_path = "/fw/firmwell/eval_gh/Greenhouse/qemu"
        
        print("gh_path:", gh_path)
        print("scripts_path:", scripts_path) 
        print("qemu_src_path:", qemu_src_path)
        
        gh_qemu_path = os.path.join(qemu_src_path, self.qemu_arch)
        dst_gh_qemu_path = os.path.join("/fs", f"{self.qemu_arch}-gh")
        os.chmod(gh_qemu_path, 0o777)
        self.docker_manager.docker_cp_to_container(gh_qemu_path, dst_gh_qemu_path)

        cwd = "/"
        if self.cwd == "":
            self.cwd = "/"
        if self.cwd != "/":
            cwd = self.cwd

        docker_ip = '192.168.1.1'

        res = call_patch_loop(
            docker_ip,
            localgh_fs_path,
            new_bin_path,
            self.qemu_arch,
            self.hash,
            self.checker,
            new_run_args,
            cwd,
            self.docker_manager.container,
            self.docker_manager,
            self.brand,
            self.rehost_type,
            only_use_greenhouse_patch,
        )
        
        exit(res)

    def find_error_proc(self, error_process_cmdline):
        if self.args.nocallchain:
            error_process_cmdline = self.get_service_cmdline(self.httpd_path)
            print(f"get_service_cmdline: {error_process_cmdline}" )
            if error_process_cmdline == "":
                error_process_cmdline = self.httpd_path
            else:
                self.httpd_cmdline = error_process_cmdline
            
            return error_process_cmdline
        
        
        if "sbin/rc" in error_process_cmdline:
            print(f"find_error_proc, sleep 60s")
            time.sleep(60) # after fix init binary

        process_dict = self.env.process.get_process_dict() # TODO: if this func is iter, need to update process_dict

        httpd_cmdline = self.get_service_cmdline(self.httpd_path, process_dict)
        print("[1]try to get httpd_cmdline:")
        print(httpd_cmdline)

        if len(httpd_cmdline) > 0: # target binary is invoked but not success
            return httpd_cmdline

        if not self.enable_3_2: 
            if len(httpd_cmdline) == 0:
                httpd_cmdline = self.httpd_path # use default
            return httpd_cmdline # or get from execve
        
        self.build_call_chain()
        
        if self.FileSystem.file_in_filesystem("rc_apps") and len(self.get_service_cmdline("/usr/sbin/rc_app/rc_start")) > 0: # edge-case,multi sym link points to one binary
            if os.path.islink(os.path.join(self.fs_path, "usr/sbin/rc_app/rc_start")):
                return "/usr/sbin/rc_app/rc_start"
        new = []  # Replace /sbin/rc with the actual init binary if available
        for node in self.call_chain:
            if node == "/sbin/rc" and len(self.entry.init_binary_for_rc) > 0:
                node = self.entry.init_binary_for_rc
            new.append(node)
        self.call_chain = new
        
        print('callchain:')
        print(self.call_chain)
        
        if self.call_chain is None or len(self.call_chain) == 0:
            return "" # use default httpd path
        
        # Walk the call chain, killing blocking processes to allow httpd to start
        process_tree = dict()
        process_tree_kill_index = defaultdict(set)
        
        killed_process_name_set = set()
        for i in range(0,15): # kill 10 times
            process_dict = self.env.process.get_process_dict() # update after kill
            
            last_node, last_node_cmdline = self.get_last_executed_on_chain(process_dict)
            last_node_pid = self.env.process.get_pid_by_name(process_dict, last_node)

            if last_node == self.httpd_path:
                return last_node_cmdline

            pprint(process_dict)

            logger.info(f"last_node: {last_node}, last_node_cmdline: {last_node_cmdline}, last_node_pid: {last_node_pid}")
            if not self.env.process.process_is_alive(last_node) and not any("etc/rc" in i for i in process_dict.values()):  # exited state
                logger.info(f"last_node: {last_node} is not alive")
                logger.info(f"last_node_cmdline: {last_node_cmdline}")

                if "sbin/rc" in last_node_cmdline:
                    
                    if len(self.entry.init_binary_for_rc) > 0: # preinit
                        print(f"replace sbin/rc with {self.entry.init_binary_for_rc}")
                        last_node_cmdline = self.entry.init_binary_for_rc
                    
                    execve_trace_set  = self.get_execve_trace_set()
                    for line in execve_trace_set:
                        line = line.strip()
                        if self.entry.init_binary_for_rc in line and self.rehost_type.lower() in line and "start" in line \
                                and "=" not in line: # /bin/echo =============rc start
                            return line

                    for line in execve_trace_set:
                        line = line.strip()
                        if self.entry.init_binary_for_rc in line and "start" in line \
                                and "=" not in line: # /bin/echo =============rc start
                            return line

                   
                    return last_node_cmdline # '/usr/sbin/rc init'
                print(f"replace sbin/rc with last_node_cmdline", last_node_cmdline)
                return last_node_cmdline
            
            if "/bin/sh /etc/rc.d/rc" in  process_dict.values(): # JWNR2000/a1f0cfb6b900b7f67b486ffdb8ca8b881de758bee4c0542534243fb837ba79e7
                last_node_pid = self.env.process.get_pid_by_name(process_dict, "/bin/sh /etc/rc.d/rc")
            
            if last_node == "/sbin/preinit" and len(process_dict) == 1:
                return last_node
            
            if last_node == "/sbin/rc" and len(process_dict) == 1:
                last_node_cmdline = self.entry.init_binary_for_rc
                return last_node_cmdline

            process_graph, process_dict = self.env.process.get_process_tree()
            subprocess_num = self.env.process.get_subtree_depth(process_graph, last_node_pid)

            if subprocess_num > 0 and self.kill_hang_process:

                process_tree_path = self.env.process.get_all_paths(process_graph)

                print("process_tree_path")
                pprint(process_tree_path)
                
                deep_leaf = self.find_deepest_leaf(process_graph)
                
                worklist = deep_leaf
                dominant_node = None
                for k,v in process_tree_path: # ['1', '9849', '10135', '11865', '12025'], 5),
                    dominant_node = k[1]
                    process_tree[dominant_node] = k
                    if deep_leaf[0] in k:
                        worklist = k
                try:
                    dominant_node = worklist[1]  # update
                except Exception as e:
                    print("error dominant_node", e)
                    return ""  # only PID 1 remaining, something went wrong

                to_kill_pid = set()
                to_kill_process_name = ""
                for index in range(len(worklist) - 1, -1, -1):
                    pid = worklist[index]
                    process_name = process_dict[pid]
                    if "busybox" in process_name or "etc/init.d/rcS" in process_name or "etc/rc.d/rcS" in process_name or "etc_ro/init.d/rcS" in process_name or "etc_ro/rc.d/rcS" in process_name:
                        continue
                    if "sleep" in process_name:
                        continue
                    if process_name in killed_process_name_set:  # avoid killing same process
                        continue
                    if index in process_tree_kill_index[dominant_node]:  # avoid killing at same index
                        continue
                    if pid == dominant_node:  # reached dominant node, reset kill index and restart
                        process_tree_kill_index[dominant_node] = set()
                        break
                    to_kill_pid.add(pid)
                    to_kill_process_name = process_name
                    killed_process_name_set.add(process_name)
                    process_tree_kill_index[dominant_node].add(index)
                    # break
                    
                    # update: indexkill，killprocess
                    # find all same name process
                    # for same_pid, ps_name in process_dict.items():
                    #     if ps_name == process_dict[pid].split(" ")[0]:
                    #         to_kill_pid.add(same_pid)
                    # break
                    
                    # 0414 update,kill lib/uci，OOM
                    # find all same name process
                    for same_pid, ps_name in process_dict.items():
                        if ps_name == process_dict[pid]:
                            to_kill_pid.add(same_pid)
                    # break
                    
                # to_kill_pid_list = " ".join(to_kill_pid)
                # print(f"[kill] {to_kill_pid_list} {process_name}")
                # self.env.exec(f"kill -9 {to_kill_pid_list}", detach=True)
                # self.fix_record.add_fix_record("kill", {"kill": to_kill_process_name})
                #
                # if self.debug:
                #     time.sleep(3)
                # else:
                #     time.sleep(10)
                    
                    # 0413 update,
                    
                    if len(to_kill_pid) == 0:
                        break # kill -9，kill
                    to_kill_pid_list = " ".join(to_kill_pid)
                    print(f"[kill] {to_kill_pid_list} {process_name}")
                    self.env.exec(f"kill -9 {to_kill_pid_list}", detach=True)
                    self.fix_record.add_fix_record("kill", {"kill": to_kill_process_name})
                    
                    if self.debug:
                        time.sleep(3)
                    else:
                        time.sleep(10)
                        
                    break
                    
        return ""  # default: no error process found
                    
    
    def find_deepest_leaf(self, process_graph):

        roots = [n for n in process_graph.nodes if process_graph.in_degree(n) == 0]
        
        max_depth = -1
        deepest_leaf = None
        
        def dfs(node, depth):
            nonlocal max_depth, deepest_leaf
            children = list(process_graph.successors(node))
            if not children:  # leaf node
                if depth >= max_depth:
                    max_depth = depth
                    deepest_leaf = node
            else:
                for child in children:
                    dfs(child, depth + 1)
        
        for root in roots:
            dfs(root, 0)
        
        return [deepest_leaf] if deepest_leaf is not None else []

    def start_watchdog(self):
        """
        add some watchdog to monitor the process, e.g. prevent fork bomb
        """
        exec_command = f"/bin/sh -x {DOCKER_FS}/fw.sh"
        self.env.exec(exec_command, stream=False, detach=True, tty=True)

    def generate_interface_commands(self):
        # Get current network configuration
        network_info = self.env.network.get_network_info()
        interface_cmds = []
        
        # For each network interface (except loopback)
        for interface, ip_list in network_info.items():
            if interface == "lo":
                continue
                
            # Skip interfaces with no IPs
            if not ip_list:
                continue
                
            # First IP in the list
            ip = ip_list[0]
            
            # Commands needed to set up the interface
            # First add the interface as a dummy device
            interface_cmds.append(f"ip link add {interface} type dummy")
            
            # Then add the IP address with /24 subnet mask
            interface_cmds.append(f"ip addr add {ip}/24 dev {interface}")
            
            # Finally set the interface up
            interface_cmds.append(f"ip link set {interface} up")
        
        self.interface_cmds = interface_cmds
        return interface_cmds

    def run(self, start_net_ip=None, ports_file="", mac=""):
        print("Starting rehosting environment")
        print(self.httpd_path)
        
        # Default network configuration if none is provided
        if start_net_ip is None:
            start_net_ip = {
                "eth0": ["192.168.1.1"],
                "eth1": ["172.104.0.1"],
                "eth2": ["172.105.0.1"],
                "eth3": ["192.168.2.1"],
                "br0": ["192.168.0.1"]
            }
        
        # Filter network interfaces based on use_br0 flag
        initial_network_config = {}
        if self.args.use_br0:
            # Use all network interfaces
            initial_network_config = start_net_ip.copy()
        else:
            # Use only eth0
            if self.system_flag:
                initial_network_config = {"br0": start_net_ip.get("br0", ["192.168.0.1"])}
            else:
                initial_network_config = {"eth0": start_net_ip.get("eth0", ["192.168.1.1"]), "eth1": [], "eth2": []}

                if self.rehost_type == "DNS" or self.rehost_type == "UPNP":
                    initial_network_config = start_net_ip

                if self.debug:
                    initial_network_config = {"eth0": start_net_ip.get("eth0", ["192.168.1.1"])}
            
        self.initial_network_config = initial_network_config
        
        # get ports to probe
        ports = []
        with open(ports_file, "r+") as pFile:
            for p in pFile:
                p = p.strip()
                ports.append(p)
        pFile.close()
        
        self.set_hosts()
        
        print("="*50)
        
        self.interface_cmds = []
        
        try:
            restart_needed = False
            restart_count = 0
            
            
            for i in range(0, 3): 
                self.start_env(ports, initial_network_config, mac)
                
                
                # =============network config=========================
                # Configure network with initial or updated configuration
                self.env.network.reconfig_network(initial_network_config)
                self.network_info = initial_network_config # default network

                
                print("Wainting for all service start")
                
                self.waiting_all_process(self.httpd_path)
                
                # Check if network configuration has changed
                current_network_info = self.env.network.get_network_info()
                
                print("Initial network configuration:", initial_network_config)
                print("Current network configuration:", current_network_info)
                
                
                
                ps_dict =  self.env.process.get_process_dict()
                if self.FileSystem.file_in_filesystem("procd"):
                    if (not any("/etc/rc.common" in i for i in self.env.process.get_process_dict().values()) \
                            or len(ps_dict) < 10) \
                            and i != 2:  # not last attempt; restart to retry procd
                        print("\n\ntrying to restart to start procd \n\n")
                        self.docker_manager.remove_docker()  # kill and restart
                        restart_count -= 1
                        continue
                        
                break
            
            pprint(self.env.process.get_process_dict())
            print("before rehosting========================")

            # Collect LD_LIBRARY_PATH from QEMU_CMDLINE before rehosting loop,
            # so it is available for export even if probe succeeds immediately.
            try:
                data = self.docker_manager.read_file("QEMU_CMDLINE")
                for line in data.splitlines():
                    if "   - envp LD_LIBRARY_PATH=" in line:
                        ld_path = line.split("   - envp LD_LIBRARY_PATH=")[1].strip()
                        for lib in ld_path.split(":"):
                            self.LD_LIBRARY_PATH_set.add(lib)
            except Exception as e:
                print("failed to read LD_LIBRARY_PATH from QEMU_CMDLINE:", e)
        

            for i in range(0, 10):  # fix up to 10 rounds for all binaries
                
                # ================== 3.1 ==================
                if i == 0:
                    http_success = self.probe(reset_network=False)
                    
                    if http_success:
                        print("success without any fix")
                        self.target_cmdline = self.get_service_cmdline(self.httpd_path)
                        print("3.1 cmdline:", self.target_cmdline)
                        break
                    
                    if self.args.baseline:  # in baseline mode, disable all improvement
                        print("baseline_mode, exit...")
                        break
                
                
                
                # ================== 3.2 ==================
                # Rehosting Blocking Process Identification
                
                error_process_cmdline = ""
                error_process_cmdline = self.find_error_proc(error_process_cmdline)
                print(f"current error process: {error_process_cmdline}")
                
                http_success = self.probe()
                
                if http_success:
                    print("success after kill")
                    break
                    
                    
                
                if len(error_process_cmdline) == 0: 
                    print("no error process found")
                    error_process_cmdline = self.httpd_path
                    
                    if os.path.basename(self.httpd_path) == "lighttpd":
                        lighttpd_conf_paths = Files.find_file_paths(self.tmp_fs_path, 'lighttpd.conf') # FirmAE
                        if lighttpd_conf_paths:
                            conf_path = lighttpd_conf_paths[0].replace(self.tmp_fs_path, "")
                            error_process_cmdline = f"{self.httpd_path} -f {conf_path}"
                            self.httpd_cmdline = error_process_cmdline
                            
                    if os.path.basename(self.httpd_path) == "miniupnpd":
                        error_process_cmdline = f"{self.httpd_path} -f /miniupnpd.conf"
                        
                    if os.path.basename(self.httpd_path) == "dnsmasq":
                        error_process_cmdline = f"{self.httpd_path} -C /dnsmasq.conf"
                            
                    print("")
                    
                

                error_process_path = error_process_cmdline.split(" ")[0]
                if self.entry.init_bash == error_process_path :
                    print("some bug, locate bash again, use default path")
                    if len(self.entry.init_bash_args) > 0 and self.entry.init_bash_args not in error_process_cmdline:
                        error_process_cmdline = f"{self.entry.init_bash} {self.entry.init_bash_args}"
                        print(f"[run] {error_process_cmdline}")
                    else:
                        error_process_cmdline = f"{self.entry.init_bash}"
                    
                    # run bash
                    if self.system_flag:
                        self.env.exec(error_process_cmdline)
                    else:
                        cmd = self.wrap_binary_with_qemu("/bin/sh", args=error_process_cmdline, tracelog=False, use_hack_bind=False)
                        self.env.exec(cmd, detach=True)
                    continue
                    
                if "busybox" in error_process_cmdline:
                    error_process_cmdline = self.httpd_path
                    
                

                if len(self.get_service_cmdline(self.httpd_path)) == 0 and i == 5:
                    # some binary have error, but can be fix
                    error_process_cmdline = self.httpd_path
                    print("not found httpd_cmdline, use httpd_path")
                    
                    print('[set_default_cmdline]', error_process_cmdline)
    
    
    
    
    
                # ================== 3.3 ==================
                # Root Cause Oriented Misemulation Fix
                
                if not self.args.greenhouse_fix: # firmwell
                    rehost_success = self.rehosting_binary(error_process_cmdline, i)
                    
                    if rehost_success is False and self.args.greenhouse_patch:
                        print("rehosting_binary failed, try greenhouse patch")
                        rehost_success = self.greenhouse_fix_func(error_process_cmdline, only_use_greenhouse_patch=True)
                    
                    if rehost_success is not None and self.httpd_path in error_process_cmdline:
                        print("success or no error to fix")
                        break
                    
                else: # for greenhouse eval experiment
                    if self.system_flag:
                        print(f"greenhouse_fix_func sys node")
                        rehost_success = self.rehosting_binary(error_process_cmdline, i)
                        if rehost_success is not None and self.httpd_path in error_process_cmdline:
                            print("success or no error to fix")
                            break
                    
                    elif self.httpd_path not in error_process_cmdline:
                        # fix call chain binary by firmwell
                        rehost_success = self.rehosting_binary(error_process_cmdline, i)
                        if rehost_success is not None and self.httpd_path in error_process_cmdline:
                            print("use greenhouse fix multi-binary")
                            break
                    else:
                        print(f"greenhouse_fix_func target_binary")
                        
                        tools = ["ip", "ifconfig", "brctl", "vconfig"]
                        for tool in tools:
                            for path in Files.find_file_paths(self.tmp_fs_path, tool):
                                if os.path.exists(f"{path}.bak"):
                                    os.unlink(path)
                                    os.rename(f"{path}.bak", path)
                                    
                        self.greenhouse_fix_func(error_process_cmdline)
                            
            
            
            print("rehostin end")
            
            if len(self.httpd_cmdline) == 0:
                self.httpd_cmdline = self.get_service_cmdline(self.httpd_path)
                
                if len(self.httpd_cmdline) == 0:
                    self.httpd_cmdline = self.httpd_path
            
            
            if not self.system_flag:
                if not self.FIRMWELL_EXECUTE: # user mode, bind syscall
                    try:
                        result = self.env.exec('cat /fs/FIRMWELL_NET')
                        if "No such file" not in result:
                            self.FIRMWELL_EXECUTE = True
                    except Exception as e:
                        print("[error]", e)
            
        
            
            success, wellformed, connected = self.checker.check(trace=None, exit_code=None, timedout=None,
                                                                errored=False, strict=True)
            if wellformed:
                self.httpd_cmdline = self.get_service_cmdline(self.httpd_path)
                if self.no_cmdline:
                    self.cwd = "/"
                    http_success = self.run_binary(self.httpd_path, self.httpd_cmdline)
                    print("wellformed and without cmdline:", http_success)
                if self.no_ipc:
                    self.docker_manager.exec_run_lock("kill -9 -1")
                    self.docker_manager.docker_cp_to_container("/fw/firmwell/greenhouse_files/clean_ipc.sh", "/")
                    self.docker_manager.exec_run_lock("chmod +x clean_ipc.sh")
                    self.docker_manager.exec_run_lock("/bin/sh /clean_ipc.sh")
                    http_success = self.run_binary(self.httpd_path, self.httpd_cmdline)
                    print("wellformed and without IPC:", http_success)
                
                if self.no_env_var:
                    http_success = self.run_binary(self.httpd_path, self.httpd_cmdline)
                    print("wellformed and without env_var:", http_success)
                    
                if self.no_dyn_file:
                    
                    file_list = self.docker_manager.exec_run_lock(
                        '''sh -c "find /fs ! -type d ! -path '/fs/proc/*' ! -path '/fs/sys/*' -printf '%P\n'"''')
                    dyn_set = set()
                    for i in file_list.splitlines():
                        if i.endswith(".bak"):
                            continue
                        dyn_set.add(f"/{i}")
                    
                    self.final_file_list = list(dyn_set)
                    

                    static_file_list = []
                    for root, dirs, files in os.walk(self.fs_path):
                        for file in files:
                            rel_path = os.path.relpath(os.path.join(root, file), self.fs_path)
                            if not rel_path.startswith('proc/') and not rel_path.startswith('sys/'):
                                static_file_list.append(rel_path)
                    
                    dyn_set = set()
                    static_set = set()
                    for i in static_file_list:
                        if not i.startswith("/"):
                            static_set.add(f"/{i}")
                    
                    diff_set = dyn_set - static_set
                    path_list = []
                    for i in diff_set:
                        if not any(e in i for e in ['gh_nvram', "/dev", "/proc", "/sys", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/usr/lib", "/usr/lib64", "qemu"]): # nvram is not files but we treat it as files
                            path_list.append(f"rm -f /fs/{i} ; ")
                    
                    to_remove = " ".join(path_list)
                    to_remove = to_remove.rsplit(" ; ", 1)[0]
                    self.docker_manager.exec_run_lock(to_remove)
                    http_success = self.run_binary(self.httpd_path, self.httpd_cmdline)
                    print("wellformed and without env_var:", http_success)
            
            
           

            if self.args.rsf:
                self.rsf_check()
            
            if self.system_flag:
                ipcs_cmd = "/firmadyne/busybox ipcs -a"
                unix_domain_cmd = "/firmadyne/busybox cat /proc/net/unix"
                socket_cmd = "/firmadyne/busybox netstat -np"
                file_list = self.env.exec(
                    '''sh -c "find / -type f -printf '/%P\n'"''')
                
            else:
                ipcs_cmd = "ipcs -a"
                unix_domain_cmd = "cat /proc/net/unix"
                socket_cmd = "netstat -np"
                file_list = self.env.exec(
                    '''sh -c "find /fs -type f ! -path '/fs/proc/*' ! -path '/fs/sys/*' -printf '/%P\n'" ''')
            
            self.ipcs = self.env.exec(ipcs_cmd)
            self.unix_domain = self.env.exec(unix_domain_cmd)
            self.socket = self.env.exec(socket_cmd)
            
            dyn_set = set()
            for i in file_list.splitlines():
                dyn_set.add(f"{i}")
            
            self.final_file_list = list(dyn_set)

            
            try:
                if (wellformed or connected) and self.args.export:
                    
                    if self.system_flag:
                        print("TODO export system mode")
                        return
                    
                    ipaddr, port, loginurl, logintype, user, password, headers, payload = self.checker.get_working_ip_set()
                    result = 'SUCCESS'
                    
                    self.interface_cmds = self.generate_interface_commands()
                    self.export_rehosting_container(result, ipaddr, self.httpd_cmdline, self.interface_cmds)
            
            except Exception as e:
                print("[export error]", e)
                print(traceback.format_exc())
            
        

        except Exception as e:
            print("!! UNCAUGHT EXCEPTION !!")
            print(e)
            print(traceback.format_exc())
            print(f"POD_NAME" in os.environ.keys())
            if "POD_NAME" in os.environ.keys() or self.debug:
                os.environ['DOCKER_HOST'] = 'tcp://127.0.0.1:2375'
            print(subprocess.check_output(["docker", "ps"]).decode('u8'))
            print(subprocess.check_output(["free", "-h"]).decode('u8'))
            
        finally:
            self.env.remove_docker()

        print("<" * 60)
        print("DONE!")

