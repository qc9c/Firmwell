import os
import shutil
import time
import random
from socket import *
import subprocess
import re
from collections import defaultdict
from pprint import pprint
import paramiko
import pexpect
from typing import Optional, Dict, List, Union, Tuple

from firmwell.backend.utils.NetworkUtil import NetworkUtil
from firmwell.backend.utils.FileSystemUtil import FileSystem
from firmwell.backend.Utils import Files
from firmwell.backend.RehostingEnv import RehostingEnv
import subprocess as sb

BUSYBOX = "/firmadyne/busybox"


class SSHClient:
    """SSH client for communicating with the QEMU VM"""
    
    def __init__(self, hostname, port=22, username='root', password='root'):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    def connect(self):
        try:
            self.ssh.connect(self.hostname, self.port, self.username, self.password, timeout=20)
            return True
        except Exception as e:
            print(f"[ssh]: {e}")
    
    def exec_command(self, command, detach=False):
        if detach:
            command = f"{command} > /dev/null 2>&1 &"
        if self.ssh:
            print(f"[ssh] {command}")
            stdin, stdout, stderr = self.ssh.exec_command(command)
            if not detach:
                return stdout.read().decode('utf-8', errors='ignore')
        return None
    
    def upload_file(self, local_path, remote_path):
        try:
            with self.ssh.open_sftp() as sftp:
                sftp.put(local_path, remote_path)
                print(f"[ssh] file upload: {local_path} -> {remote_path}")
        except Exception as e:
            print(f"[ssh] file upload failed: {e}")
    
    def download_file(self, remote_path, local_path):
        try:
            with self.ssh.open_sftp() as sftp:
                sftp.get(remote_path, local_path)
                print(f"[ssh] file download: {remote_path} -> {local_path}")
        except Exception as e:
            print(f"[ssh] file download failed: {e}")
    
    def close(self):
        if self.ssh:
            self.ssh.close()
            self.ssh = None


class QemuNetworkManager:
    """Manages network setup and configuration for QEMU VM"""
    
    @staticmethod
    def stop_tap_netdev():
        """Stop and clean up tap network devices"""
        # NetworkUtil.clean_host_netdev("tap")
        
        def clean_host_netdev(netdev):
            host_net_dev = subprocess.check_output(["ip", "addr"]).decode()
            host_network_info = NetworkUtil.get_interfaces_ips(host_net_dev)
            for dev, _ in host_network_info.items():
                if dev.startswith(netdev):
                    subprocess.run(['ip', 'link', 'del', dev])
                else:
                    print("No prefix provided for cleaning network devices")
    
        # clean_host_netdev("br")
        clean_host_netdev("tap")
        # clean_host_netdev("veth")
    
    @staticmethod
    def start_tap_netdev(ip_addr: str, jobindex: str):
        """Start and configure tap network devices"""
        QemuNetworkManager.stop_tap_netdev()
        
        # ip0 = "192.168.0"
        # ip0 = "192.168.1"
        
        ip0 = QemuNetworkManager.get_subnet_prefix(ip_addr)
        
        # Configure tap0
        subprocess.run(['tunctl', '-t', f'tap_{jobindex}'])
        subprocess.run(['ip', 'addr', 'add', f"{ip0}.2/24", "dev", f'tap_{jobindex}'])
        subprocess.run(['ip', 'link', 'set', f'tap_{jobindex}', "up"])
        
        print(" ".join(['tunctl', '-t', f'tap_{jobindex}']))
        print(" ".join(['ip', 'addr', 'add', f"{ip0}.2/24", "dev", f'tap_{jobindex}']))
        print(" ".join(['ip', 'link', 'set', f'tap_{jobindex}', "up"]))
        # # Configure tap1
        # subprocess.run(['tunctl', '-t', 'tap1'])
        # subprocess.run(['ip', 'addr', 'add', f"{ip1}.2/24", "dev", "tap1"])
        # subprocess.run(['ip', 'link', 'set', "tap1", "up"])
    
    @staticmethod
    def is_same_subnet(ip1: str, ip2: str, prefix: int = 24) -> bool:
        """Check if two IP addresses are in the same subnet"""
        if not ip1 or not ip2:
            return False
        
        ip1_parts = ip1.split('.')
        ip2_parts = ip2.split('.')
        
        return ip1_parts[:3] == ip2_parts[:3]
    
    @staticmethod
    def get_subnet_prefix(ip: str) -> str:
        """Extract subnet prefix from IP address"""
        return '.'.join(ip.split('.')[:3])


class QemuShell:
    """Manages shell interaction with QEMU VM"""
    
    def __init__(self, job_index: str, arch):
        self.job_index = job_index
        self.session = None
        self.socat_session = None
        self.arch = arch
    
    def socat_read_until(self, until: bytes) -> bytes:
        """Read from socat session until specified pattern"""
        if not self.socat_session:
            return b""
        
        r = b""
        while until not in r:
            buf = self.socat_session.recv(timeout=5)
            if not buf:
                break
            r += buf
        return r
    
    def socat_sendall(self, buf: bytes) -> bool:
        """Send data to socat session"""
        if not self.socat_session:
            return False
        
        buf = buf.decode("utf-8").strip("\n")
        for c in buf:
            self.socat_session.send(c.encode("utf-8"))
            time.sleep(0.1)
        self.socat_session.sendline(b"")
        return True
    
    def socat_send_recv(self, buf: bytes, timeout: int = 5) -> bytes:
        """Send data and read response until prompt"""
        if not self.socat_session:
            return b""
        
        # Clear any pending output
        self.socat_read_until(b"#")
        
        # Send command
        self.socat_sendall(buf)
        
        # Read response
        r = self.socat_read_until(b"#")
        
        # Handle special cases
        if b"No such" in r or b"not found" in r:
            self.socat_sendall(b"\n")
            r = self.socat_read_until(b"#")
        
        if r.endswith(b">"):
            self.socat_sendall(b"\`")
            r = self.socat_read_until(b"#")
            self.socat_sendall(b"\n")
            r = self.socat_read_until(b"#")
        
        return r
    
    def ensure_socat_session(self) -> bool:
        """Ensure there's a working socat session"""
        
        if self.socat_session:
            try:
                self.socat_sendall(b"\n")
                if self.socat_read_until(b"#"):
                    return True
            except:
                pass
        
        try:
            print("Creating new socat session...")
            import pwn
            
            os.environ["TERM"] = "xterm"
            from pwn import context
            context.terminal = None

            try:
                # For armel architecture, use script to log output to a file
                if hasattr(self, 'arch') and self.arch == 'armel':
                    # Use shell=True to properly handle the quoted command
                    cmd = f'script -f /tmp/qemu.final.serial.log -c "socat UNIX-CONNECT:/tmp/qemu.{self.job_index}.S1 STDIO"'
                    print(f"Running command: {cmd}")
                    self.socat_session = pwn.process(cmd, shell=True)
                else:
                    # For other architectures, use the original approach
                    self.socat_session = pwn.process(["socat", "-", f"UNIX-CLIENT:/tmp/qemu.{self.job_index}.S1"])
            except Exception as e:
                print(f"Failed to create socat session: {e}")
                self.socat_session = None
                return False
            
            time.sleep(0.5)
            self.socat_sendall(b"\n")
            time.sleep(0.5)
            r = self.socat_read_until(b"#")
            return b"#" in r
        except Exception as e:
            print(f"Failed to create socat session: {e}")
            self.socat_session = None
            return False


class QemuSysRunner(RehostingEnv):
    """Main class for running QEMU system emulation"""
    
    def __init__(self, network_config, base_path, fs_path, bin_path, qemu_arch, name, debug, hash, brand,
                 rehost_type, entry, checker, kill_hang_process, enable_create, enable_fix_bg_process,
                 fix_record, rsfpath, enable_basic_procfs, args, no_cmdline, no_ipc, enable_fix_in_peer,
                 enable_3_3, filesystem, jobindex, firmae_path, FIRMWELL_EXECUTE):
        
        super().__init__("system", filesystem)
        
        self.firmae_path = firmae_path
        # Initialize basic attributes
        self._init_basic_attrs(base_path, fs_path, bin_path, name, debug, hash, brand,
                               rehost_type, entry, checker, kill_hang_process, enable_create,
                               enable_fix_bg_process, fix_record, enable_basic_procfs, args,
                               enable_fix_in_peer, enable_3_3, no_cmdline, no_ipc,
                               rsfpath, filesystem, jobindex)
        
        # Initialize architecture-specific settings
        self._init_arch_settings(qemu_arch)
        
        # Path for Debian-based QEMU system files
        self.debian_arch = self.arch
        if "mipseb" in self.arch:
            self.debian_arch = "mips"
        if "armel" in self.arch:
            self.debian_arch = "armhf"
        # self.debian_arch_path = os.path.join("/qemu_system_files_bak", self.debian_arch)
        
        # Initialize paths and network
        self._init_paths_and_network(network_config)
        
        # Initialize shell interface
        self.shell = QemuShell(self.jobindex, self.arch)
        
        # Kill any existing QEMU processes
        self.kill_qemu()
        
        # if len(self.entry.init_bash) > 0:
        #     self.debian_flag = True
        # else:
        #     self.debian_flag = False
        self.FIRMWELL_EXECUTE = FIRMWELL_EXECUTE
    
    def __del__(self):
        """Cleanup and stop QEMU VM"""
        try:
            # Check if sys.modules is None (indicating Python shutdown)
            import sys
            if sys.modules is None or sys is None:
                return
            
            # Check if subprocess module is still available
            if 'subprocess' in sys.modules:
                # Only call stop_rehosting_env if we're not in interpreter shutdown
                self.stop_rehosting_env()
        except (ImportError, AttributeError, TypeError):
            # If any exception occurs during shutdown, just return silently
            pass
    
    def _init_basic_attrs(self, base_path, fs_path, bin_path, name, debug, hash, brand,
                          rehost_type, entry, checker, kill_hang_process, enable_create,
                          enable_fix_bg_process, fix_record, enable_basic_procfs, args,
                          enable_fix_in_peer, enable_3_3, no_cmdline, no_ipc,
                          rsfpath, filesystem, jobindex):
        """Initialize basic attributes"""
        self.base_path = base_path
        self.fs_path = fs_path
        self.bin_path = bin_path
        self.name = name
        self.debug = debug
        self.hash = hash
        self.brand = brand
        self.rehost_type = rehost_type
        self.entry = entry
        self.checker = checker
        self.httpd_path = self.bin_path.replace(self.fs_path, "")
        self.FileSystem = filesystem
        self.kill_hang_process = kill_hang_process
        self.enable_create = enable_create
        self.enable_fix_bg_process = enable_fix_bg_process
        self.fix_record = fix_record
        self.enable_basic_procfs = enable_basic_procfs
        self.args = args
        self.enable_fix_in_peer = enable_fix_in_peer
        self.enable_3_3 = enable_3_3
        self.no_cmdline = no_cmdline
        self.no_ipc = no_ipc
        self.ipc_process = ""
        self.rsfpath = rsfpath
        self.jobindex = jobindex
        
        self.FIRMWELL_EXECUTE = False
        self.httpd_cmdline = ""
        self.final_file_list = list()
        self.envp_init = ""
        self.container = None
        
        self.ssh = None
        self.pexpect_session = None  # pexpect session for Debian-based QEMU
    
    def _init_arch_settings(self, qemu_arch):
        """Initialize architecture-specific settings"""
        if "qemu-mips-static" in qemu_arch:
            self.arch = "mipseb"
            self.qemu_arch = "qemu-system-mips"
        elif "qemu-mipsel-static" in qemu_arch:
            self.arch = "mipsel"
            self.qemu_arch = "qemu-system-mipsel"
        elif "qemu-arm-static" in qemu_arch:
            self.arch = "armel"
            self.qemu_arch = "qemu-system-arm"
        else:
            raise ValueError("Unsupported QEMU architecture")
    
    def _init_paths_and_network(self, network_config):
        """Initialize paths and network settings"""
        self.binary_path = "/qemu_system_files"
        self.tarball_path = f"/tmp/{self.jobindex}.tar.gz"
        self.timeout = 360 if self.debug else 240
        self.ip_addr = network_config['br0']
    
    @staticmethod
    def kill_qemu():
        """Kill all running QEMU processes"""
        print("killing qemu...")
        cmd = "kill -9 $(ps aux | grep 'qemu-system' | grep -v 'grep' | awk '{print $2}') 2>/dev/null"
        subprocess.run(cmd, shell=True)
        time.sleep(2)
        
        # if os.path.exists("/tmp/qemu.final.serial.log"):
        #     with open("/tmp/qemu.final.serial.log", 'r') as f:
        #         print(f.readlines()[-50:])
        
        QemuNetworkManager.stop_tap_netdev()
    
    def check_container_status(self):
        pass
    
    def start_rehosting_env(self, dest=None, ports=None, potential_urls=None, mac=None,
                            enable_basic_procfs=False, use_ipv6=False) -> bool:
        """Start the QEMU environment"""

        max_restart_attempts = 2
        restart_count = 0
        
        while restart_count <= max_restart_attempts:
            target_ip = self.ip_addr[0] if isinstance(self.ip_addr, list) else self.ip_addr
            expected_subnet = QemuNetworkManager.get_subnet_prefix(target_ip)
            if self._start_qemu_instance(target_ip, expected_subnet, restart_count):
                return True
            restart_count += 1
        
        print("Timeout reached, QEMU startup failed.")
        return False
    
    def _start_qemu_instance(self, target_ip: str, expected_subnet: str, restart_count: int) -> bool:
        """Start a single QEMU instance"""
        ip_addr = self.ip_addr[0] if isinstance(self.ip_addr, list) else self.ip_addr
        
        if self.entry.init_binary in ["/bin/busybox", "/sbin/rc"]:
            self.entry.init_binary = "/sbin/init"
        
        QemuNetworkManager.start_tap_netdev(ip_addr, self.jobindex)
        
        # Setup and start QEMU
        
        self._setup_qemu_command()
        print("\n\n\n")
        print(f"Starting QEMU with command")
        print(f"{self.qemu_cmd}")
        
        # if self.debian_flag:
        #
        #     if isinstance(self.ip_addr, list):
        #         target_ip = self.ip_addr[0]
        #     else:
        #         target_ip = self.ip_addr
        #     res = self.start_debian_vm(target_ip)
        #     if not res:
        #         print("Failed to start Debian-based VM")
        #         return False
        # else:
        
        # if self.arch == "armel":
        self.log_file = open("/tmp/qemu.final.serial.log", "w")
        self.session = subprocess.Popen(self.qemu_cmd, shell=True, stdout=self.log_file, stderr=self.log_file)
        # else:
        #     self.session = subprocess.Popen(self.qemu_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for QEMU to start
        # time.sleep(30 if self.debug else 120)
        time.sleep(10)


        with open("/tmp/qemu.final.serial.log", "r") as f:
            print("/tmp/qemu.final.serial.log:")
            lines = f.readlines()
            print("".join(lines[-50:]))

            
        # Wait for connection and configure network
        return self._wait_for_connection_and_configure(target_ip, expected_subnet, restart_count)
    
    def _setup_qemu_command(self):
        """Setup QEMU command based on architecture and configuration"""
        # Use SysRunner approach if init_binary is provided
        # if self.debian_flag:
        #     if "mips" in self.arch:
        #         kernel = os.path.join(self.debian_arch_path, "vmlinux-3.2.0-4-4kc-malta")
        #         hda = os.path.join(self.debian_arch_path, f"debian_wheezy_{self.debian_arch}_standard.qcow2")
        #         self.qemu_cmd = (
        #             f'{self.qemu_arch} -m 2048 -M malta -kernel {kernel} -hda {hda} '
        #             f'-append "root=/dev/sda1 console=tty0" '
        #             f'-net nic -net tap,ifname=tap_{self.jobindex},script=no,downscript=no '
        #             f'-nographic'
        #         )
        #     elif "arm" in self.arch:
        #         kernel = os.path.join(self.debian_arch_path, "kernel")
        #         initrd = os.path.join(self.debian_arch_path, "initrd")
        #         hda = os.path.join(self.debian_arch_path, "image.qcow2")
        #         self.qemu_cmd = (
        #             f'qemu-system-arm -machine virt -cpu cortex-a15 -m 2G '
        #             f'-kernel {kernel} -initrd {initrd} '
        #             f'-append "root=LABEL=rootfs console=ttyAMA0" '
        #             f'-device virtio-blk-device,drive=hd -drive file={hda},if=none,id=hd '
        #             f'-device virtio-net-device,netdev=net0 -netdev tap,id=net0,ifname=tap_{self.jobindex},script=no,downscript=no '
        #             f'-nographic'
        #         )
        #     else:
        #         raise ValueError(f"Unsupported architecture: {self.arch} for Debian-based VM")
        # else:
        #     # run from init
        
        image = self.make_image()
        
        if "mipseb" in self.arch:
            self._setup_mipseb_command(image)
        elif "mipsel" in self.arch:
            self._setup_mipsel_command(image)
        elif "arm" in self.arch:
            self._setup_arm_command(image)
        else:
            raise ValueError("Unsupported architecture")
    
    def _setup_mipseb_command(self, image: str):
        """Setup QEMU command for MIPS big-endian"""
        kernel = os.path.join(self.binary_path, "vmlinux.mipseb.4")
        
        if len(self.entry.init_bash) > 0:
            rdinit = "/firmadyne/preInit.sh"
        else:
            rdinit = self.entry.init_binary
        
        # if len(self.entry.init_bash) > 0:
        #     # rdinit = "/firmadyne/preInit.sh"
        #     init = "/firmadyne/sh"
        # else:
        #     init = self.entry.init_binary
        
        self.qemu_cmd = (
            f'{self.qemu_arch} '
            f'-m 512 '
            f'-M malta '
            f'-kernel {kernel} '
            f'-drive if=ide,format=raw,file={image} '
            f'-append "root=/dev/sda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 '
            # f'rdinit={self.entry.init_binary} rw debug print-fatal-signals=1 user_debug=31 '
            f'init={rdinit} rw debug print-fatal-signals=1 user_debug=31 '
            f'firmadyne.syscall=32 firmadyne.execute=1 user_debug=31 firmadyne.reboot=1 '
            f'firmadyne.procfs=1" '
            f'-serial file:/tmp/qemu.final.serial.log -serial unix:/tmp/qemu.{self.jobindex}.S1,server,nowait '
            f'-monitor unix:/tmp/qemu.{self.jobindex},server,nowait '
            # f'-chardev socket,id=char1,path=/tmp/qemu.{self.jobindex}.S1,server,nowait '
            # f'-serial chardev:char1 '
            # f'-chardev file,id=char0,path=/tmp/qemu.final.serial.log '
            # f'-serial chardev:char0 '
            f'-device e1000,netdev=net0 -netdev tap,id=net0,ifname=tap_{self.jobindex},script=no '
            f'-device e1000,netdev=net1 -netdev user,id=net1 '
            f'-device e1000,netdev=net2 -netdev user,id=net2 '
            f'-device e1000,netdev=net3 -netdev user,id=net3 '
            f'-device e1000,netdev=net4 -netdev user,id=net4 '
            f'-display none'
        )
    
    def _setup_mipsel_command(self, image: str):
        """Setup QEMU command for MIPS little-endian"""
        kernel = os.path.join(self.binary_path, "vmlinux.mipsel.4")
        
        if len(self.entry.init_bash) > 0:
            rdinit = "/firmadyne/preInit.sh"
        else:
            rdinit = self.entry.init_binary
        
        # if len(self.entry.init_bash) > 0:
        #     # rdinit = "/firmadyne/preInit.sh"
        #     init = "/firmadyne/sh"
        # else:
        #     init = self.entry.init_binary
        
        self.qemu_cmd = (
            f'{self.qemu_arch} '
            f'-m 512 '
            f'-M malta '
            f'-kernel {kernel} '
            f'-drive if=ide,format=raw,file={image} '
            f'-append "root=/dev/sda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 '
            f'init={rdinit} rw debug print-fatal-signals=1 user_debug=31 '
            f'firmadyne.syscall=32 firmadyne.execute=1 user_debug=31 firmadyne.reboot=1 '
            f'firmadyne.procfs=1" '
            f'-serial file:/tmp/qemu.final.serial.log -serial unix:/tmp/qemu.{self.jobindex}.S1,server,nowait '
            f'-monitor unix:/tmp/qemu.{self.jobindex},server,nowait '
            # f'-chardev socket,id=char1,path=/tmp/qemu.{self.jobindex}.S1,server,nowait '
            # f'-serial chardev:char1 '
            # f'-chardev file,id=char0,path=/tmp/qemu.final.serial.log '
            # f'-serial chardev:char0 '
            f'-device e1000,netdev=net0 -netdev tap,id=net0,ifname=tap_{self.jobindex},script=no '
            f'-device e1000,netdev=net1 -netdev user,id=net1 '
            f'-device e1000,netdev=net2 -netdev user,id=net2 '
            f'-device e1000,netdev=net3 -netdev user,id=net3 '
            f'-device e1000,netdev=net4 -netdev user,id=net4 '
            f'-display none'
        )
    
    def _setup_arm_command(self, image: str):
        """Setup QEMU command for ARM"""
        kernel = os.path.join(self.binary_path, "zImage.armel")
        
        if len(self.entry.init_bash) > 0:
            # rdinit = "/firmadyne/preInit.sh"
            init = "/firmadyne/sh"
        else:
            init = self.entry.init_binary
        
        # self.qemu_cmd = (
        #     f'{self.qemu_arch} '
        #     f'-m 1024 '
        #     f'-M virt '
        #     f'-kernel {kernel} '
        #     f'-drive if=none,format=raw,file={image},id=rootfs '
        #     f'-device virtio-blk-device,drive=rootfs '
        #     f'-append "root=/dev/vda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 '
        #     f'init={init} rw debug print-fatal-signals=1 user_debug=31 '
        #     f'firmadyne.syscall=32 firmadyne.execute=1 user_debug=31 firmadyne.reboot=1 '
        #     f'firmadyne.procfs=1 firmadyne.devfs=0" ' # disable firmadyne custom devfs
        #     f'-serial unix:/tmp/qemu.{self.jobindex}.S1,server,nowait '
        #     f'-serial file:/tmp/qemu.final.serial.log '
        #     f'-monitor unix:/tmp/qemu.{self.jobindex},server,nowait '
        #     f'-device virtio-net-device,netdev=net0 -netdev tap,id=net0,ifname=tap_{self.jobindex},script=no '
        #     f'-device virtio-net-device,netdev=net1 -netdev socket,id=net1,listen=:2001 '
        #     f'-device virtio-net-device,netdev=net2 -netdev socket,id=net2,listen=:2002 '
        #     f'-device virtio-net-device,netdev=net3 -netdev socket,id=net3,listen=:2003 '
        #     f'-display none'
        # )
        
        self.qemu_cmd = (
            f'{self.qemu_arch} '
            f'-m 512 '
            f'-M virt '
            f'-kernel {kernel} '
            f'-drive if=none,format=raw,file={image},id=rootfs '
            f'-device virtio-blk-device,drive=rootfs '
            f'-append "root=/dev/vda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 '
            f'init={init} rw debug print-fatal-signals=1 user_debug=31 '
            f'firmadyne.syscall=32 firmadyne.execute=1 user_debug=31 firmadyne.reboot=1 '
            f'firmadyne.procfs=1 firmadyne.devfs=0" '  # disable firmadyne custom devfs
            f'-serial unix:/tmp/qemu.{self.jobindex}.S1,server,nowait '
            f'-chardev stdio,id=char0,logfile=/tmp/qemu.final.serial.log,signal=off '
            f'-serial chardev:char0 '
            # f'-device virtio-net-device,netdev=net0 -netdev tap,id=net0,ifname=tap_{self.jobindex},script=no '
            # f'-device virtio-net-device,netdev=net1 -netdev socket,id=net1,listen=:2001 '
            # f'-device virtio-net-device,netdev=net2 -netdev socket,id=net2,listen=:2002 '
            # f'-device virtio-net-device,netdev=net3 -netdev socket,id=net3,listen=:2003 '
            f'-device virtio-net-device,netdev=net0 -netdev tap,id=net0,ifname=tap_{self.jobindex},script=no '
            f'-display none'
        )
    
    def _wait_for_connection_and_configure(self, target_ip: str, expected_subnet: str,
                                           restart_count: int) -> bool:
        """Wait for QEMU to start and configure network"""
        
        start_time = time.time()
        connected = False
        
        while time.time() - start_time < self.timeout:
            # if self.shell.ensure_socat_session() or self.debian_flag:
            if self.shell.ensure_socat_session():
                connected = True
                print("Successfully connected to QEMU via socat.")
                
                if len(self.entry.init_bash) > 0:
                    self.exec(f"{BUSYBOX} mount -t proc proc /proc")
                    self.exec(f"{BUSYBOX} mount -t sysfs sysfs /sys")
                    
                    if self.entry.init_bash_args.startswith(">"):  # >/dev/console 2>&1
                        self.exec(f"{self.entry.init_bash} > /dev/null 2>&1 & \n")
                    else:
                        if "sysinit" in self.entry.init_bash: # linksys
                            self.exec(f"{self.entry.init_bash} > /dev/null 2>&1 & \n")
                            time.sleep(30)
                            self.exec(f"/etc/system/wait > /dev/null 2>&1 & \n")
                            time.sleep(30)
                            self.exec(f"/etc/system/once> /dev/null 2&1 & \n")
                            time.sleep(60)
                            self.exec(f"/etc/init.d/service_httpd.sh httpd-start> /dev/null 2&1 & \n")
                            time.sleep(120)
                        else:
                            self.exec(f"{self.entry.init_bash} {self.entry.init_bash_args} > /dev/null 2>&1 & \n")
                
                # Test basic command
                print("Testing command execution...")
                # result = self.exec("/firmadyne/busybox ls /", noprint=False)
                result = self.exec("ls /", noprint=False)
                if result:
                    print("QEMU system setup complete.")
                    # self.exec("/firmadyne/sh /firmadyne/debug.sh & ")
                    
                    # Configure network
                    if self._configure_network(target_ip, expected_subnet, restart_count):
                        self.FIRMWELL_EXECUTE = True # sys mode, connect to guest network
                        return True  # back to Rehosting
                    else:
                        return False  # restart
            
            if not connected:
                print(f"Waiting for QEMU to start... ({int(time.time() - start_time)}s)")
                self.shell.socat_session = None
                time.sleep(5)
            else:
                time.sleep(5)
                self.shell.socat_session = None
        
        return False
    
    def start_debian_vm(self, target_ip: str) -> bool:
        """Wait for Debian-based VM to start and configure network"""
        if self.debug:
            timeout = 300
        else:
            timeout = 600
        
        try:
            self.pexpect_session = pexpect.spawn(self.qemu_cmd)
            
            self.pexpect_session.expect("login:", timeout=timeout)
            self.pexpect_session.sendline("root")
            
            self.pexpect_session.expect("Password:")
            self.pexpect_session.sendline("root")
            self.pexpect_session.expect(":~# ")
            
            self.pexpect_session.sendline("stty rows 24 cols 120")  # Avoid output truncation
            self.pexpect_session.expect(":~# ")
            
            # self.qemu_exec_command("brctl addif br0 eth0")
            # self.qemu_exec_command(f"ip addr add {target_ip}/24 dev br0")
            # self.qemu_exec_command("ip link set br0 up")
            # self.qemu_exec_command("ip addr add 0.0.0.0/24 dev eth0")
            # self.qemu_exec_command("ip link set eth0 up")
            
            self.qemu_exec_command("ip addr flush dev eth0")
            self.qemu_exec_command("ip link add name br0 type bridge")
            self.qemu_exec_command("ip link set eth0 master br0")
            self.qemu_exec_command(f"ip addr add {target_ip}/24 dev br0")
            self.qemu_exec_command("ip link set br0 up")
            self.qemu_exec_command("ip addr add 0.0.0.0/24 dev eth0")
            self.qemu_exec_command("ip link set eth0 up")
            
            # Connect SSH client
            self.ssh = SSHClient(target_ip)
            if self.ssh.connect():
                # Upload firmware
                self._upload_firmware()
                
                # self.qemu_exec_command("chroot /fs /bin/sh") # Enter chroot environment
                
                self.pexpect_session.sendline("mount -t proc proc /fs/proc")
                self.pexpect_session.expect("# ", timeout=30)
                
                self.pexpect_session.sendline("mount -t sysfs sysfs /fs/sys")
                self.pexpect_session.expect("# ", timeout=30)
                
                self.pexpect_session.sendline("chroot /fs /firmadyne/busybox sh")
                self.pexpect_session.expect("# ", timeout=30)
                
                # run init bash
                cmd = f"LD_PRELOAD=libnvram-faker.so {self.entry.init_bash} {self.entry.init_bash_args} > /dev/null 2>&1 &"
                self.pexpect_session.sendline(cmd)
                self.pexpect_session.expect("# ", timeout=30)
                
                time.sleep(30)  # wait for init
                
                return True
            
            return False
        
        except Exception as e:
            print(f"Error connecting to Debian VM: {e}")
    
    def _upload_firmware(self):
        """Upload firmware to the Debian-based VM"""
        # Remove problematic files
        # mtdblock5 = os.path.join(self.fs_path, 'dev', 'mtdblock5')
        # if os.path.exists(mtdblock5):
        #     os.remove(mtdblock5)
        
        for path in Files.find_file_paths(self.fs_path, "killall"):
            os.rename(path, path + ".bak")
        
        # copy firmadyne busybox
        firmadyne = os.path.join(self.fs_path, "firmadyne")
        if not os.path.exists(firmadyne):
            os.mkdir(firmadyne)
        firmadyne_busybox_dst = os.path.join(firmadyne, "busybox")
        firmadyne_busybox_src = os.path.join("/qemu_system_files", f"busybox.{self.arch}")
        if not os.path.exists(firmadyne_busybox_dst):
            shutil.copy(firmadyne_busybox_src, firmadyne_busybox_dst)
            os.chmod(firmadyne_busybox_dst, 0o777)
        
        firmadyne_stracex_dst = os.path.join(firmadyne, "strace")
        firmadyne_strace_src = os.path.join("/qemu_system_files", f"strace.{self.arch}")
        if not os.path.exists(firmadyne_stracex_dst):
            shutil.copy(firmadyne_strace_src, firmadyne_stracex_dst)
            os.chmod(firmadyne_stracex_dst, 0o777)
        
        # Create firmware tarball
        tar_name = self.name + '.tar.gz'
        tar_file = os.path.join('/tmp', tar_name)
        tar_cmd = f"tar -czvf {tar_file} ./"
        
        subprocess.run(tar_cmd, shell=True, cwd=self.fs_path,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Upload firmware and extract it
        self.ssh_exec_command("mkdir -p /fs")
        self.ssh.upload_file(tar_file, f"/fs/{tar_name}")
        self.ssh_exec_command(f"tar -zxvf /fs/{tar_name} -C /fs")
        
        time.sleep(10)
        self.ssh_exec_command(f"rm /fs/{tar_name}")
        
        # # Upload additional tools
        # self.ssh.upload_file(os.path.join(self.debian_arch_path, 'strace'), "/fs/strace")
        # self.ssh.upload_file(os.path.join("/fw/tools/scripts/kill20.sh"), "/fs/kill20.sh")
        # self.qemu_exec_command("chmod +x /fs/kill20.sh")
    
    def qemu_exec_command(self, cmd, detach=False):
        """Execute command in Debian-based QEMU VM via pexpect"""
        # First, replace irrelevant output text
        self.pexpect_session.sendline("=======")
        self.pexpect_session.expect(":~# ", timeout=30)
        
        garbage_output = self.pexpect_session.before
        left, right = garbage_output.decode('utf-8', errors='ignore').split("-bash: =======: command not found")
        left = left.replace("=======", "")
        right = right.replace("=======", "")
        
        if detach:
            cmd = f"{cmd} > /dev/null 2>&1 &"
        
        self.pexpect_session.sendline(cmd)
        self.pexpect_session.expect(":~# ", timeout=30)
        output = self.pexpect_session.before.decode('utf-8', errors='ignore').replace(cmd, "", 1).replace(left, "",
                                                                                                          1).replace(
            right, "", 1)
        
        print(f"[qemu] {cmd}")
        return output
    
    def ssh_exec_command(self, cmd, detach=False):
        """Execute command via SSH in Debian-based QEMU VM"""
        if self.ssh:
            return self.ssh.exec_command(cmd, detach)
        return None
    
    def _configure_network(self, target_ip: str, expected_subnet: str, restart_count: int) -> bool:
        """Configure network settings in the VM"""
        network_info = NetworkUtil.get_interfaces_ips(self.exec("ip addr"))
        print(f"Current network info: {network_info}")
        
        # Check network configuration
        subnet_mismatch = False
        actual_subnet = None
        
        if 'br0' in network_info and network_info['br0']:
            found_matching_subnet = False
            
            for br0_ip in network_info['br0']:
                if not (br0_ip.startswith('192.168.') or
                        br0_ip.startswith('10.') or
                        (br0_ip.startswith('172.') and 16 <= int(br0_ip.split('.')[1]) <= 31)):
                    continue
                
                if QemuNetworkManager.is_same_subnet(br0_ip, target_ip):
                    found_matching_subnet = True
                    break
                else:
                    actual_subnet = QemuNetworkManager.get_subnet_prefix(br0_ip)
            
            if not found_matching_subnet and actual_subnet:
                subnet_mismatch = True
        
        # Handle subnet mismatch
        if subnet_mismatch and restart_count < 2:
            print(f"VM using different subnet: {actual_subnet} vs expected {expected_subnet}")
            print(f"Reconfiguring host interface (attempt {restart_count + 1}/2)...")
            
            self.kill_qemu()
            self.shell.socat_session = None
            
            host_ip = f"{actual_subnet}.2"
            subprocess.run(['ip', 'addr', 'flush', 'dev', f'tap_{self.jobindex}'])
            subprocess.run(['ip', 'addr', 'add', f"{host_ip}/24", "dev", f'tap_{self.jobindex}'])
            subprocess.run(['ip', 'link', 'set', f'tap_{self.jobindex}', "up"])
            
            target_ip = f"{actual_subnet}.1"
            if isinstance(self.ip_addr, list):
                self.ip_addr[0] = target_ip
            else:
                self.ip_addr = target_ip
            
            print(f"Changed target IP: {expected_subnet}.x -> {actual_subnet}.x")
            return False
        
        # Configure VM networking
        print(f"Configuring VM networking with IP {target_ip}")
        self.exec("ip addr flush dev eth0")
        
        if 'br0' not in network_info:
            self.exec("ip link add name br0 type bridge")
            self.exec("ip link set eth0 master br0")
        
        self.exec("brctl addif br0 eth0")
        self.exec(f"ip addr add {target_ip}/24 dev br0")
        self.exec("ip link set br0 up")
        self.exec("ip addr add 0.0.0.0/24 dev eth0")
        self.exec("ip link set eth0 up")
        
        
        self.exec("iptables flush")
        self.exec("iptables -F")
        self.exec("iptables -P INPUT ACCEPT") # CPE605_UN_v1.0_20201028
        
        
        
        # Test connectivity
        print(f"Testing connectivity to VM at {target_ip}...")
        try:
            ping_result = subprocess.run(['ping', '-c', '3', '-W', '2', target_ip],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            if ping_result.returncode == 0:
                print("✓ Successfully pinged VM from host")
                return True
            else:
                print(f"✗ Failed to ping VM at {target_ip} from host")
                return False
        except Exception as e:
            print(f"Error pinging VM: {e}")
            return False
    
    def exec(self, cmd: str, **kwargs) -> str:
        """
        Execute a command in the QEMU VM with appropriate adaptations for QEMU system mode.

        Args:
            cmd (str): Command to execute
            **kwargs: Additional arguments (detach, noprint, timeout)

        Returns:
            str: Command output
        """
        detach = kwargs.get('detach', False)
        noprint = kwargs.get('noprint', False)
        # timeout = kwargs.get('timeout', 30)
        
        if not noprint:
            print(f"[qemu exec] {cmd}")
        
        # Remove any /fs prefix - system mode doesn't need it
        if cmd.startswith("/fs"):
            cmd = cmd[3:]
        elif "/fs/" in cmd:
            cmd = cmd.replace("/fs/", "/")
        
        # Handle bash -c or sh -c patterns
        if cmd.startswith("bash -c "):
            cmd = cmd.replace("bash -c ", "", 1)
            # Remove quotes if they're around the command
            if cmd.startswith('"') and cmd.endswith('"'):
                cmd = cmd[1:-1]
            cmd = f"/firmadyne/sh -c '{cmd}'"
        elif cmd.startswith("sh -c "):
            cmd = cmd.replace("sh -c ", "", 1)
            # Remove quotes if they're around the command
            if cmd.startswith('"') and cmd.endswith('"'):
                cmd = cmd[1:-1]
            cmd = f"/firmadyne/sh -c '{cmd}'"
        else:
            # Prefix with busybox for basic commands, unless it already has a path
            if not cmd.startswith("/") and "=" not in cmd.split()[0] and "iptables" not in cmd:
                cmd = f"/firmadyne/busybox {cmd}"
        
        if detach:
            cmd = f"{cmd} > /dev/null 2>&1 &"
        
        # # Use SSH/pexpect approach if using Debian-based VM
        # if self.debian_flag:
        #     # if cmd.startswith("chroot /fs"):
        #     # For chroot commands in Debian VM, execute directly without chroot prefix
        #     #     cmd = cmd.replace("chroot /fs ", "")
        #     #     return self.ssh_exec_command(cmd, detach)
        #     # else:
        #     #     # For non-chroot commands
        #     #     return self.qemu_exec_command(cmd, detach)
        #
        #     # output = self.qemu_exec_command(cmd, detach)
        #     self.pexpect_session.sendline("=======")
        #     self.pexpect_session.expect("# ", timeout=30)
        #
        #     garbage_output = self.pexpect_session.before
        #     left, right = garbage_output.decode('utf-8', errors='ignore').split("sh: =======: not found")
        #     left = left.replace("=======", "")
        #     right = right.replace("=======", "")
        #
        #     self.pexpect_session.sendline(cmd)
        #     self.pexpect_session.expect("# ", timeout=30)
        #     output = self.pexpect_session.before.decode('utf-8', errors='ignore').replace(cmd, "", 1).replace(left, "",
        #                                                                                                       1).replace(
        #         right, "", 1)
        #     # output = self.pexpect_session.before.decode('utf-8', errors='ignore')
        #
        #     return output
        #
        # else:
        
        if not self.shell.ensure_socat_session():  # TODO: filt armel log
            print("Failed to establish socat session for command execution")
            return ""
        
        # Prepare command for sending
        if isinstance(cmd, str):
            cmd = cmd.encode('utf-8')
        # if not cmd.endswith(b'\r\n'):
        #     cmd += b'\r\n'
        if not cmd.endswith(b'\n'):
            cmd += b'\n'
        print("final cmd", cmd)
        # Send and receive response
        r = self.shell.socat_send_recv(cmd)
        cleaned_output = ""
        
        if r:
            raw_output = r.decode('utf-8', errors='ignore')
            ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
            cleaned_output = ansi_escape.sub('', raw_output)
            cleaned_output = cleaned_output.replace("\r", "")  # remove carriage return
            cleaned_output = cleaned_output.replace(cmd.decode('utf-8').replace("\r", ""), "").strip()  # remove command
            cleaned_output = cleaned_output.replace("/ # ", "", -1).strip()  # remove prompt
        
        # Filter out multi-line kernel log followed by ANALYZE patterns
        # cleaned_output = re.sub(r'\[\s*\d+\.\d+\]\s*\n+\[ANALYZE\].*\nenvp:.*\n', '\n', cleaned_output)
        cleaned_output = re.sub(
            r'\[\s*\d+\.\d+\]\s*\n+\[ANALYZE\].*?envp:.*?\n',
            '\n',
            cleaned_output,
            flags=re.DOTALL
        )
        
        # Filter out kernel log messages like [34.766690] patterns
        cleaned_output = re.sub(r'\[\s*\d+\.\d+\].*\n', '\n', cleaned_output)
        
        # Remove any consecutive empty lines
        cleaned_output = re.sub(r'\n\s*\n+', '\n', cleaned_output)
        # Trim leading/trailing whitespace
        cleaned_output = cleaned_output.strip()
        cleaned_output = cleaned_output.replace("/ #", "", -1).strip()  # remove prompt, last line
        print("[cleaned_output]", cleaned_output)
        return cleaned_output
    
    def make_tarball(self, fs_path: str):
        """Create tarball of filesystem"""
        if not os.path.exists(self.tarball_path):
            subprocess.run(['tar', '-czf', self.tarball_path, '-C', fs_path, '.'])
    
    def mount_image(self, target_dir: str) -> str:
        """Mount QEMU image and return loop device"""
        print('[mountImage] ')
        
        try:
            loop_file = sb.check_output(['bash', '-c',
                                         f'source {self.firmae_path}/firmae.config && add_partition %s/image.raw' % target_dir]).decode().strip()
        except sb.CalledProcessError as e:
            print(f"[add_partition error]: {e.output.decode().strip()}")
            raise
        
        print('[loopFile]', loop_file)
        
        try:
            mount_result = sb.run(f'mount {loop_file} {target_dir}/image',
                                  shell=True, capture_output=True, text=True)
            print(f"[mount stdout]: {mount_result.stdout}")
            print(f"[mount stderr]: {mount_result.stderr}")
        except Exception as e:
            print(f"[mount error]: {str(e)}")
            raise
        
        time.sleep(1)
        return loop_file
    
    def umount_image(self, target_dir: str, loop_file: str):
        """Unmount QEMU image and clean up loop device"""
        print('[umountImage] ')
        
        try:
            umount_result = sb.run(f'umount {target_dir}/image',
                                   shell=True, capture_output=True, text=True)
            print(f"[umount stdout]: {umount_result.stdout}")
            print(f"[umount stderr]: {umount_result.stderr}")
        except Exception as e:
            print(f"[umount error]: {str(e)}")
        
        try:
            del_result = sb.check_output(['bash', '-c',
                                          f'source {self.firmae_path}/firmae.config && del_partition {loop_file.rsplit("p", 1)[0]}'],
                                         stderr=sb.STDOUT)
            print(f"[del_partition stdout/stderr]: {del_result.decode().strip()}")
        except sb.CalledProcessError as e:
            print(f"[del_partition error]: {e.output.decode().strip()}")
    
    def make_image(self) -> str:
        """Create QEMU image from filesystem"""
        make_image_script = "/fw/firmwell/tools/scripts/makeImage.sh"
        work_dir = os.path.join(self.firmae_path, "scratch", f"{self.jobindex}")
        os.makedirs(work_dir, exist_ok=True)
        
        image_dir = os.path.join(work_dir, "image")
        image = os.path.join(work_dir, "image.raw")
        
        if os.path.exists(image):
            return image
        
        if os.path.exists(self.tarball_path):
            os.remove(self.tarball_path)
        
        if not os.path.exists(self.tarball_path):
            self.make_tarball(self.fs_path)
        
        print(f"cmd: bash {make_image_script} {self.tarball_path} {work_dir} {self.arch}")
        subprocess.run(['bash', make_image_script, self.tarball_path, work_dir, self.arch])
        
        if not os.path.exists(image):
            print(f"[qemu] {make_image_script} failed")
            exit(0)
        
        # Setup debug shell
        # os.makedirs(f"/tmp/{self.jobindex}/image", exist_ok=True)
        loopfile = self.mount_image(work_dir)
        
        debug_sh = os.path.join(work_dir, "image", "firmadyne", "debug.sh")
        with open(debug_sh, 'w') as f:
            f.write("#!/bin/sh\n")
            f.write("/firmadyne/busybox nc -lp 31337 -e /firmadyne/busybox sh &\n")
            f.write("/firmadyne/busybox nc -lp 31338 -e /bin/sh &\n")
        os.chmod(debug_sh, 0o777)
        
        # setup preInit.sh
        preInitsh_src = "/fw/firmwell/greenhouse_files/preInit.sh"
        preInitsh_dst = os.path.join(work_dir, "image", "firmadyne", "preInit.sh")
        with open(preInitsh_src, 'r') as f:
            preInitsh_content = f.read()
        
        # if len(self.entry.init_bash) > 0:
        #     with open(preInitsh_dst, 'w') as f:
        #         f.write(preInitsh_content)
        #
        #         # updata, dont run init bash, cant get shell
        #         # if self.entry.init_bash_args.startswith(">"):  # >/dev/console 2>&1
        #         #     f.write(f"{self.entry.init_bash} \n")
        #         # else:
        #         #     f.write(f"{self.entry.init_bash} {self.entry.init_bash_args}\n")
        #
        #         f.write("/firmadyne/debug.sh\n")
        #         f.write('/firmadyne/busybox sleep 36000\n')
        
        with open(preInitsh_dst, 'w') as f:
            f.write(preInitsh_content)
            
            # updata, dont run init bash, cant get shell
            # if self.entry.init_bash_args.startswith(">"):  # >/dev/console 2>&1
            #     f.write(f"{self.entry.init_bash} \n")
            # else:
            #     f.write(f"{self.entry.init_bash} {self.entry.init_bash_args}\n")
            f.write("/firmadyne/sh")
            f.write("/firmadyne/debug.sh\n")
            f.write('/firmadyne/busybox sleep 36000\n')
        os.chmod(preInitsh_dst, 0o777)
        self.umount_image(work_dir, loopfile)
        
        return image
    
    def stop_rehosting_env(self) -> bool:
        """Stop the QEMU environment"""
        self.kill_qemu()
        return True
    
    def read_file(self, path: str) -> str:
        """Read file content from VM filesystem"""
        try:
            content = self.exec(f"/firmadyne/busybox cat {path}")
            return content
        except Exception as e:
            print(f"Failed to read file: {e}")
            return ""
    
    def file_exist_in_container(self, path: str) -> bool:
        """Check if a file exists in the VM"""
        result = self.exec(f"test -f {path} && echo 'exists' || echo 'not exists'")
        return "exists" in result
    
    def remove_docker(self) -> bool:
        """Cleanup and stop QEMU VM"""
        if self.shell.socat_session:
            try:
                self.shell.socat_session.close()
            except:
                pass
            self.shell.socat_session = None
        
        self.kill_qemu()
        return True
    
    def exec_run_lock(self, cmd: str, detach: bool = False, noprint: bool = False) -> str:
        """Execute command with lock (for compatibility)"""
        return self.exec(cmd, detach=detach, noprint=noprint)
    
    def docker_cp_to_container(self, host_filepath: str, vm_path: str = None) -> bool:
        """Copy file from host to VM"""
        file_name = os.path.basename(host_filepath)
        if not vm_path:
            vm_path = f"/firmadyne/{file_name}"
        
        if not os.path.exists(host_filepath):
            print(f"[ERROR] Host file {host_filepath} does not exist")
            return False
        
        try:
            print(f"[*] Starting netcat server in VM on port 31339")
            vm_cmd = f'/firmadyne/busybox nc -lp 31339 > {vm_path} &'
            if hasattr(self, 'netcat_sock'):
                self.netcat_sock.sendall(f"{vm_cmd}\n".encode())
            else:
                self.shell.socat_sendall(vm_cmd.encode())
            
            time.sleep(2)
            
            print(f"[*] Transferring {host_filepath} to VM at {vm_path}")
            transfer_cmd = f'cat {host_filepath} | nc {self.ip_addr[0]} 31339'
            subprocess.Popen(transfer_cmd, shell=True)
            
            retries = 0
            max_retries = 60
            while retries < max_retries:
                time.sleep(1)
                ps_output = self.exec("ps | grep nc")
                if "31339" not in ps_output:
                    break
                retries += 1
            
            if retries >= max_retries:
                print(f"[WARNING] Transfer timed out, but file may still be transferred")
            
            check_cmd = f"test -f {vm_path} && echo 'exists' || echo 'not exists'"
            if "exists" in self.exec(check_cmd):
                print(f"[*] Transfer complete: {host_filepath} → {vm_path}")
                return True
            else:
                print(f"[ERROR] File transfer failed: {vm_path} not found in VM")
                return False
        
        except Exception as e:
            print(f"[ERROR] File transfer failed: {e}")
            return False
    
    def docker_cp_to_host(self, vm_filepath: str, host_path: str = None) -> Optional[str]:
        """Copy file from VM to host"""
        file_name = os.path.basename(vm_filepath)
        if not host_path:
            host_path = os.path.join(os.getcwd(), file_name)
        
        check_cmd = f"test -f {vm_filepath} && echo 'exists' || echo 'not exists'"
        if "exists" not in self.exec(check_cmd):
            print(f"[ERROR] VM file {vm_filepath} does not exist")
            return None
        
        try:
            local_port = random.randint(31340, 31999)
            
            print(f"[*] Starting netcat server on host on port {local_port}")
            nc_listener = subprocess.Popen(
                f"nc -l {local_port} > {host_path}",
                shell=True
            )
            
            time.sleep(1)
            
            tap_prefix = NetworkUtil.get_ip_prefix(self.ip_addr[0])
            host_ip = f"{tap_prefix}.2"
            
            print(f"[*] Transferring {vm_filepath} from VM to host at {host_path}")
            vm_cmd = f'/firmadyne/busybox cat {vm_filepath} | /firmadyne/busybox nc {host_ip} {local_port}'
            self.exec(vm_cmd)
            
            retries = 0
            max_retries = 10
            while retries < max_retries:
                time.sleep(1)
                if os.path.exists(host_path) and os.path.getsize(host_path) > 0:
                    break
                retries += 1
            
            nc_listener.terminate()
            
            if os.path.exists(host_path) and os.path.getsize(host_path) > 0:
                print(f"[*] Transfer complete: {vm_filepath} → {host_path}")
                return host_path
            else:
                print(f"[ERROR] File transfer failed: {host_path} not found or empty")
                return None
        
        except Exception as e:
            print(f"[ERROR] File transfer failed: {e}")
            return None

