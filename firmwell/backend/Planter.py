from telnetlib import IP
from . import *
import json
import glob

import os, shutil, stat, getpass
import subprocess
from subprocess import Popen, PIPE
import pathlib
import re
import time
import ipaddress
import string
import lzma
import struct
import ifaddr

from .new_utils import *


WEBROOTS = ["www", "www.eng" "web", "webs"]
WEB_EXTS = ["html", "htm", "xhtm", "jhtm", "cgi", "xml", "js", "wss", "php", "php4", "php3", "phtml",
            "rss", "svg", "dll", "asp", "aspx", "axd", "asx", "asmx", "ashx", "cfm", "swf"]
BACKUP_TAGS = ["bak", "bak2", "bkup"]
POTENTIAL_HTTPSERV = ["httpd", "uhttpd", "lighttpd", "jjhttpd", "shttpd", "thttpd","minihttpd", "mini_httpd", \
                    "mini_httpds", "dhttpd", "alphapd", "goahead", "boa", "appweb", "shgw_httpd", \
                    "tenda_httpd", "funjsq_httpd", "webs", "hunt_server", "hydra"]
POTENTIAL_UPNPSERV = ["miniupnpd", "miniupnpc", "mini_upnpd", "miniupnpd_ap", "miniupnpd_wsc", \
                      "upnp", "upnpc", "upnpd", "upnpc-static", "upnprenderer", \
                      "bcmupnp", "wscupnpd", "upnp_app", "upnp_igd", "upnp_tv_devices"]
POTENTIAL_DNSSERV = ["ddnsd", "dnsmasq"]




POTENTIAL_DHCPSERV = ["udhcpd", "dnsmasq"]
BACKGROUND_SCRIPTS = {"xmldb" : "-n gh_xml_root_node -t", "userconfig" : ""}
GH_BUSYBOX = "busybox"
GH_IP = "ip"
GREENHOUSE = "greenhouse"
NVRAM_FOLDER = "libnvram_faker"
NVRAM_FAKER_LIB = "libnvram-faker.so"
NVRAM_INIT = "nvram.ini"
NVRAM_KEY_VALUE_FOLDER = "gh_nvram"
NVRAM_IP_KEYS = ["ip_addr", "ipaddr"]
RAND = "8467206204610564372101238468369273619216273019100147216372162374"*100 # "random number" string for 'entropy'
ZERO = "0"*100
MUSL_LD_DEFAULT = "/lib:/usr/local/lib:/usr/lib"
ARCH_MAP = {"arm": "qemu-arm-static",
            "armeb": "qemu-armeb-static",
             "x86": "qemu-i386-static",
            "x86_64": "qemu-x86_64-static",
             "mips": "qemu-mips-static",
             "mipsel": "qemu-mipsel-static",
            "ppc": "qemu-ppc-static",
            }
RESERVED_IPS = ["0.0.0.0", "127.0.0.1", "1.1.1.1", "1.0.0.1"]
PORTS_BLACKLIST = ['0', '22']
MAC_NVRAM_KEYS = ["lan_hwaddr"]

EXTRACT_PATH = '/tmp/scratch'

import r2pipe

def get_nvram_dict(libnvram_path):
    # Analyze the binary
    
    # Open the binary file with radare2
    r2 = r2pipe.open(libnvram_path)
    
    # Analyze the binary
    r2.cmd('aaa')
    
    def get_data_by_addr(addr):
        # Seek to the target address
        r2.cmd(f's {addr}')
        
        # Read 4 bytes from this location (this is where the pointer is stored)
        pointer_data = r2.cmdj('pxj 4')
        
        # Convert the read bytes into an integer (little-endian)
        pointer_address = pointer_data[0] + (pointer_data[1] << 8) + (pointer_data[2] << 16) + (pointer_data[3] << 24)
        
        # Seek to the address where the pointer points (to possibly .rodata)
        r2.cmd(f's {pointer_address}')
        
        # Print the string at this location
        string_data = r2.cmd('psz')
        
        return string_data.strip()
    
    # Get the address of the symbol 'router_defaults'
    # Use `isj` to list symbol information in JSON format and filter it
    symbols = r2.cmdj('isj')
    
    # Find the address of 'router_defaults'
    router_defaults_addr = None
    
    if symbols is None:
        return
    for sym in symbols:
        if sym['name'] == 'router_defaults':
            router_defaults_addr = sym['vaddr']
            break
    
    if router_defaults_addr is None:
        return None
    
    res = dict()
    
    if router_defaults_addr is not None:
        # Seek to the address of 'router_defaults'
        for i in range(0, 0x1000):
            # Calculate the address of the offset +12 from 'router_defaults'
            router_defaults_addr = router_defaults_addr + 12
            key = router_defaults_addr
            value = key + 4
            
            key_data = get_data_by_addr(key)
            value_data = get_data_by_addr(value)
            
            res[get_data_by_addr(key)] = get_data_by_addr(value)
            
            if key_data.strip() == "ELF" or key_data == "blank_state":
                break
    
    else:
        print("Symbol 'router_defaults' not found.")
    
    # Close the r2pipe connection
    r2.quit()
    
    return res

from elftools.elf.elffile import ELFFile

def read_dynamic_symbol_table(elf_path):
    symbols = set()
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)

        try:
            dynsym = elffile.get_section_by_name('.dynsym')

            for symbol in dynsym.iter_symbols():
                symbols.add(symbol.name)
        except:
            pass

    return symbols


def symbolic_link_fix(lib):
    import os
    from collections import defaultdict
    import re

    def get_prefix(name):
        return re.sub(r'-[0-9].*|\.[a-z0-9].*', '', name)

    groups = defaultdict(list)
    filenames = os.listdir(lib)
    filenames.sort()

    for filename in filenames:
        if filename.startswith("ld-"): # ld-2.5.so -> ld-linux.so.3
            groups["ld-"].append(filename)
            continue
        prefix = get_prefix(filename)
        groups[prefix].append(filename)

    curr_dir = os.getcwd()
    os.chdir(lib)

    for prefix, files in groups.items():
        if len(files) >= 2:
            file_sizes = {filename: os.path.getsize(filename) for filename in files}

            # Find the largest file in the group
            max_file = max(file_sizes, key=file_sizes.get)
            max_size = file_sizes[max_file]

            for filename, size in file_sizes.items():
                if size < 30 and not os.path.islink(filename):
                    os.remove(filename)
                    os.symlink(max_file, filename)
                    print(f"Removed {filename} and created a symlink to {max_file}.")

    os.chdir(curr_dir)

class Fixer():
    def __init__(self, qemu_src_path, gh_path, scripts_path, brand, name, fixbash, args):
        self.qemu_src_path = qemu_src_path
        self.qemu_run_path = ""
        self.scripts_path = scripts_path
        self.gh_path = gh_path
        self.nvram_faker_path = os.path.join(self.gh_path, NVRAM_FOLDER)
        self.nvram_init_path = ""
        self.nvram_key_value_path = ""
        self.nvram_map = dict()
        self.nvram_brand_map = dict()
        self.qemu_arch = None
        self.arch = None
        self.brand = brand
        self.name = name
        self.clib = "glibc" # default

        self.potential_http_set = set()

        self.fixbash=fixbash
        self.args = args

    def initial_setup(self, fs_path, binary_path, enable_nvram_faker, enable_nvram_sematic, enable_fix_dev, no_start_with_nvram, no_basic_dev):
        full_path = os.path.join(fs_path, binary_path)
        full_path = str(pathlib.Path(full_path).resolve()) # handle symlinks

        if full_path != fs_path:
            print("Checking binary at ", full_path)
            sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
            stdout = sp.stdout
            print("    - ", stdout)
        else:
            busybox = os.path.join(fs_path, 'bin', 'busybox')
            print("Checking binary at ", busybox)
            sp = subprocess.run(["file", busybox], stdout=PIPE, stderr=PIPE)
            stdout = sp.stdout
            print("    - ", stdout)
        self.arch = Fixer.get_arch_from_file_command(stdout)
        self.clibc = Fixer.get_clib_from_file_command(stdout)
        if self.arch is None:
            print("    - ERROR: unsupported arch", stdout)
            return False
        self.qemu_arch = ARCH_MAP[self.arch]

        # copy relevant qemu static
        self.qemu_run_path = self.copy_qemu_user_static(self.arch, fs_path)

        #chmod +rw entire directory so its editable
        sp = subprocess.run(["chmod", "-R", "a+rwx", fs_path])

        # copy statically compiled helper binaries
        greenhousePath = os.path.join(fs_path, GREENHOUSE)
        iproutePath = os.path.join(self.gh_path, GH_IP)
        
        busyboxPath = os.path.join(self.gh_path, f"{GH_BUSYBOX}_x86")
        iprouteDest = os.path.join(fs_path, GREENHOUSE, GH_IP)
        busyboxDest = os.path.join(fs_path, GREENHOUSE, GH_BUSYBOX)
        bashxPath = os.path.join(self.gh_path, "bash")
        bashDest = os.path.join(fs_path, GREENHOUSE, "bash")
        Files.mkdir(greenhousePath)
        Files.copy_file(iproutePath, iprouteDest)
        Files.copy_file(busyboxPath, busyboxDest)
        Files.copy_file(bashxPath, bashDest)
        Files.touch_file(os.path.join(fs_path, "GREENHOUSE_WEB_CANARY"), root=fs_path) # create index page 'canary'

        #chmod +x
        sp = subprocess.run(["chmod", "+x", self.qemu_run_path])
        sp = subprocess.run(["chmod", "+x", full_path])

        # initial environment setup
        
        # make sure proc and sys dir exist
        def ensure_directory(path):
            if os.path.islink(path):
                target = os.path.realpath(path)

                if target.startswith("/"):
                    dst = os.path.join(fs_path, target.replace("/", "", 1))
                else:
                    dst = os.path.join(fs_path, target)
                
                os.makedirs(dst, exist_ok=True)
            else:
                os.makedirs(path, exist_ok=True)
        
        ensure_directory(os.path.join(fs_path, "proc"))
        ensure_directory(os.path.join(fs_path, "sys"))
        
        if self.find_file("xmldump", fs_path):
            Files.mkdir(os.path.join(fs_path, "var", "tmp"), root=fs_path)
            Files.mkdir(os.path.join(fs_path, "var", "run"), root=fs_path)

        if not no_basic_dev:
            self.setup_devfiles(fs_path)

        self.setup_scripts(fs_path)
        self.remove_reboots(fs_path)
        if enable_nvram_faker: # use nvramfaker
            try:
                self.setup_custom_libraries(fs_path, enable_nvram_sematic, no_start_with_nvram)
            except Exception as e:
                print("error setup_custom_libraries", e)
                pass

        self.load_factory_default(fs_path)
        self.propgate_contents(fs_path)

        return True
    
    def load_factory_default(self, fs_path):
        res = None
        lib_path = os.path.join(fs_path, "lib")
        real_libnvram_path = os.path.join(lib_path, "libnvram.so.bak")
        if os.path.exists(real_libnvram_path):
            res = get_nvram_dict(real_libnvram_path)
        
        lib_path = os.path.join(fs_path, "usr", "lib")
        real_libnvram_path = os.path.join(lib_path, "libnvram.so.bak")
        if os.path.exists(real_libnvram_path):
            res = get_nvram_dict(real_libnvram_path)
        
        if res is None:
            return
        
        
        if 'blank_state' in res:
            blank_state = res['blank_state']
            
            print("[blank_state]:", blank_state)
            
            if blank_state == "0" or blank_state == "1":
            
                with open(os.path.join(fs_path, "gh_nvram", "blank_state"), 'w') as f:
                    f.write(blank_state)

    def setup_scripts(self, fs_path):
        setup_dev_path = os.path.join(self.gh_path, "setup_dev.sh")
        setup_dev_dest = os.path.join(fs_path, "setup_dev.sh")
        Files.copy_file(setup_dev_path, setup_dev_dest)

        sanitize_dev_path = os.path.join(self.gh_path, "sanitize_dev.sh")
        setup_dev_dest = os.path.join(fs_path, "sanitize_dev.sh")
        Files.copy_file(sanitize_dev_path, setup_dev_dest)

        watch_dog_src_path = os.path.join(self.gh_path, "fw_watchdog.sh")
        watch_dog_dst_path = os.path.join(fs_path, "fw_watchdog.sh")
        Files.copy_file(watch_dog_src_path, watch_dog_dst_path)

        org_mode = os.stat(setup_dev_dest)
        os.chmod(setup_dev_dest, org_mode.st_mode | stat.S_IXUSR)

        src_path = os.path.join(self.gh_path, "create_mtd.sh")
        dst_path = os.path.join(fs_path, "create_mtd.sh")
        Files.copy_file(src_path, dst_path)

        src_path = os.path.join(self.gh_path, "clean_fs.sh")
        dst_path = os.path.join(fs_path, "clean_fs.sh")
        Files.copy_file(src_path, dst_path)

    def setup_devfiles(self, fs_path):
        # setup dev files
        print("    - setup /dev files")
        Files.rm_target(os.path.join(fs_path, "dev", "null"))
        Files.rm_target(os.path.join(fs_path, "dev", "urandom"))
        Files.rm_target(os.path.join(fs_path, "dev", "random"))
        Files.rm_target(os.path.join(fs_path, "dev", "zero"))
        Files.touch_file(os.path.join(fs_path, "dev", "null"), root=fs_path, silent=True) # empty file
        
        Files.write_file(os.path.join(fs_path, "dev", "urandom"), RAND, root=fs_path, silent=True) # 'random' bytes for entropy
        Files.write_file(os.path.join(fs_path, "dev", "random"), RAND, root=fs_path, silent=True) # 'random' bytes for entropy
        Files.write_file(os.path.join(fs_path, "dev", "zero"), ZERO, root=fs_path, silent=True) # 'random' bytes for entropy

        # for gh fuzz
        Files.copy_directory(os.path.join(fs_path, "dev"), os.path.join(fs_path, "ghdev"), via_cp=True)
        Files.mkdir(os.path.join(fs_path, "ghtmp"))
        Files.mkdir(os.path.join(fs_path, "ghproc"))
        
        Files.touch_file(os.path.join(fs_path, "dev", "console"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "si"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "ttyS0"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "ttyS1"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "ttyS2"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "ttyS3"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "tty0"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "tty2"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "tty"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", "tty5"), root=fs_path, silent=True)

        Files.mkdir(os.path.join(fs_path, 'dev', 'tts'))
        Files.touch_file(os.path.join(fs_path, "dev", 'tts', "0"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", 'tts', "1"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", 'tts', "2"), root=fs_path, silent=True)
        Files.touch_file(os.path.join(fs_path, "dev", 'tts', "3"), root=fs_path, silent=True)



    def remove_reboots(self, fs_path):
        # setup dev files
        print("    - removing reboot and shutdown scripts")
        reboot_files = self.find_files("reboot", fs_path, resolve_symlinks=False)
        shutdown_files = self.find_files("shutdown", fs_path, resolve_symlinks=False)
        dummy_script_path = os.path.join(self.gh_path, "dummy.sh")

        for rf in reboot_files:
            if "htm" in rf:
                continue
            Files.rm_target(rf)
            Files.copy_file(dummy_script_path, rf)

        for sf in shutdown_files:
            if "htm" in rf:
                continue
            Files.rm_target(sf)
            Files.copy_file(dummy_script_path, sf)


    def propgate_contents(self, fs_path):
        #NOTE: currently mostly found in tendas
        webroot_path = os.path.join(fs_path, "webroot_ro")
        if os.path.exists(webroot_path):
            dest = os.path.join(fs_path, "var")
            if not os.path.exists(dest):
                Files.mkdir(dest, root=fs_path)
            dest = os.path.join(dest, "webroot")
            if os.path.exists(dest):
                shutil.rmtree(dest)
            shutil.copytree(webroot_path, dest, symlinks=True)
            print("Created", dest)

    def find_library(self, libname, fs_path, resolve_symlinks=True, skip=[]):
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f.startswith(libname):
                    lib_path = os.path.join(root, f)
                    if os.path.islink(lib_path):
                        if resolve_symlinks:
                            lib_path = str(pathlib.Path(lib_path).resolve()) # handle symlinks
                        if not lib_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while lib_path.startswith("/") or lib_path.endswith("/"):
                                lib_path = lib_path.strip("/")
                            lib_path = os.path.join(fs_path, lib_path)
                    if lib_path in skip:
                        continue
                    if not os.path.exists(lib_path):
                        continue
                    return lib_path
        return ""

    def find_file(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f == filename:
                    file_path = os.path.join(root, f)
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    return file_path
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            return file_path
        return ""

    def find_webroot(self, fs_path):
        for root, dirs, files in os.walk(fs_path):
            for d in dirs:
                if d in WEBROOTS:
                    path = os.path.join(root, d)
                    relative_path = os.path.join("/", os.path.relpath(path, fs_path))
                    return relative_path
        return ""
    
    def find_files_with_extension(self, basename, extensions, fs_path, resolve_symlinks=True, skip=[]):
        found = []
        targets = [basename+"."+ext for ext in extensions]
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                for t in targets:
                    if f == t:
                        file_path = os.path.join(root, f)
                        if os.path.dirname(file_path) == fs_path:
                            continue # skip files in 'root' dir
                        if os.path.islink(file_path):
                            if resolve_symlinks:
                                file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                            if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                while file_path.startswith("/") or file_path.endswith("/"):
                                    file_path = file_path.strip("/")
                                file_path = os.path.join(fs_path, file_path)
                        if file_path in skip or file_path in found:
                            continue
                        if not os.path.exists(file_path):
                            continue
                        found.append(file_path)
        return found


    def find_files(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        found = []
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if filename in f:
                    file_path = os.path.join(root, f)
                    if os.path.dirname(file_path) == fs_path:
                        continue # skip files in 'root' dir
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip or file_path in found:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    found.append(file_path)
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.dirname(file_path) == fs_path:
                                continue # skip files in 'root' dir
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip or file_path in found:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            found.append(file_path)
        return found


    def find_files_ending_with(self, filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
        found = []
        for root, dirs, files in os.walk(fs_path):
            for f in files:
                if f.endswith(filename):
                    file_path = os.path.join(root, f)
                    if os.path.dirname(file_path) == fs_path:
                        continue # skip files in 'root' dir
                    if os.path.islink(file_path):
                        if resolve_symlinks:
                            file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                        if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                            while file_path.startswith("/") or file_path.endswith("/"):
                                file_path = file_path.strip("/")
                            file_path = os.path.join(fs_path, file_path)
                    if file_path in skip or file_path in found:
                        continue
                    if not os.path.exists(file_path):
                        continue
                    found.append(file_path)
                if include_backups:
                    for tag in BACKUP_TAGS:
                        if f.lower().endswith(filename.lower()+"."+tag):
                            file_path = os.path.join(root, f)
                            if os.path.dirname(file_path) == fs_path:
                                continue # skip files in 'root' dir
                            if os.path.islink(file_path):
                                if resolve_symlinks:
                                    file_path = str(pathlib.Path(file_path).resolve()) # handle symlinks
                                if not file_path.startswith(fs_path): # handle symlinks that resolve to outside root folder
                                    while file_path.startswith("/") or file_path.endswith("/"):
                                        file_path = file_path.strip("/")
                                    file_path = os.path.join(fs_path, file_path)
                            if file_path in skip or file_path in found:
                                continue
                            if not os.path.exists(file_path):
                                continue
                            found.append(file_path)
        return found

    def get_clib_from_file_command(outline):
        if b"uClibc" in outline:
            return "uclibc"
        elif b"GNU/Linux" in outline:
            return "glibc"
        elif b"musl" in outline:
            return "musl"
        return "glibc" #default


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
        return None

    def copy_qemu_user_static(self, arch, fs_path):
        qemu_binary = ARCH_MAP[arch]
        path = os.path.join(self.qemu_src_path, qemu_binary)
        # if self.args.greenhouse_fix:
        #     path = os.path.join("/fw", "eval", "Greenhouse", "qemu", qemu_binary)
        target_path = os.path.join(fs_path, qemu_binary)

        print("    - Copying %s to %s" % (path, target_path))
        Files.copy_file(path, target_path)
        return target_path

    def setup_custom_libraries(self, fs_path, enable_nvram_sematic, no_start_with_nvram):
        """Install the NVRAM faker library and initialize NVRAM key-value store."""
        self.nvram_init_path = os.path.join(fs_path, NVRAM_INIT)
        self.nvram_key_value_path = os.path.join(fs_path, NVRAM_KEY_VALUE_FOLDER)
        nvram_ref_path = os.path.join(self.nvram_faker_path, "conf", NVRAM_INIT)
        nvram_brand_path = os.path.join(self.nvram_faker_path, "conf", self.brand, NVRAM_INIT)
        Files.touch_file(self.nvram_init_path, root=fs_path)
        if not os.path.exists(self.nvram_key_value_path):
            Files.mkdir(self.nvram_key_value_path, root=fs_path)
            subprocess.run(["chmod", "-R", "a+rw", self.nvram_key_value_path])
            
        target_nvram_faker_path = os.path.join(self.nvram_faker_path, "lib", self.arch, self.clibc, "libnvram-faker.so")

        replace_real_nvram_flag = True

        # copy in libnvram.so
        print("Using ", target_nvram_faker_path)
        subprocess.run(["chmod", "+x", target_nvram_faker_path])


        # backup and replace the original libnvram in case hook does not work
        lib_path = os.path.join(fs_path, "lib")
        real_libnvram_path = os.path.join(lib_path, "libnvram.so")
        shutil.copy(target_nvram_faker_path, lib_path) # copy to
        if os.path.exists(real_libnvram_path):
            if replace_real_nvram_flag:
                os.rename(real_libnvram_path, real_libnvram_path+".bak")
                shutil.copy(target_nvram_faker_path, real_libnvram_path)

        lib_path = os.path.join(fs_path, "usr/lib")
        if os.path.exists(lib_path):
            real_libnvram_path = os.path.join(lib_path, "libnvram.so")
            if os.path.exists(real_libnvram_path):
                shutil.copy(target_nvram_faker_path, lib_path)
                if replace_real_nvram_flag:
                    os.rename(real_libnvram_path, real_libnvram_path+".bak")
                    shutil.copy(target_nvram_faker_path, real_libnvram_path)

        # read in reference nvram values
        if nvram_ref_path != "" and os.path.exists(nvram_ref_path):
            with open(nvram_ref_path, "r") as nvramIniFile:
                for line in nvramIniFile:
                    line = line.strip()
                    if len(line) > 0:
                        array = line.split("=")
                        key = array[0].strip()
                        value = array[1].strip()
                        self.nvram_map[key] = value
        # Read all nvram.ini files from conf directory recursively
        conf_dir = os.path.join(self.nvram_faker_path, "conf")
        if os.path.exists(conf_dir):
            for root, dirs, files in os.walk(conf_dir):
                for filename in files:
                    if filename.endswith("nvram.ini"):
                        nvram_file = os.path.join(root, filename)
                        with open(nvram_file, "r") as nvramIniFile:
                            for line in nvramIniFile:
                                line = line.strip()
                                if len(line) > 0:
                                    array = line.split("=")
                                    key = array[0].strip()
                                    value = array[1].strip()
                                    # Only add if key doesn't exist in nvram_map
                                    if key not in self.nvram_map:
                                        self.nvram_map[key] = value

        if nvram_brand_path != "" and os.path.exists(nvram_brand_path):
            with open(nvram_brand_path, "r") as nvramIniFile:
                for line in nvramIniFile:
                    line = line.strip()
                    if len(line) > 0:
                        array = line.split("=")
                        key = array[0].strip()
                        value = array[1].strip()
                        self.nvram_brand_map[key] = value

        if enable_nvram_sematic and not no_start_with_nvram:
            if os.path.exists(nvram_brand_path):
                Files.copy_file(nvram_brand_path, self.nvram_init_path)

                with open(self.nvram_init_path, "w") as nvramFile:
                    for key in self.nvram_brand_map.keys():
                        nvramFile.write(key + "\n")
                nvramFile.close()

                # copy nvram key/value to /gh_nvram
                for k, v in self.nvram_brand_map.items():
                    with open(os.path.join(self.nvram_key_value_path, k), 'w') as f:
                        f.write(v)
                    f.close()

    def update_nvram_map(self, new_values):
        if not new_values:
            print("    - invalid new_values for nvram_map: ", new_values)
            return

        print("    - updating nvram_map")
        for key, value in new_values.items():
            self.nvram_brand_map[key] = value

    def write_nvram(self, keys, changelog=[]):
        for key in keys:
            key = key.strip().strip("/")
            if len(key) <= 0:
                print("    ! skipping empty key")
                continue
            if "/" in key:
                key = key.replace("/", "_")
            key_path = os.path.join(self.nvram_key_value_path , key)
            value = "0"
            if key in self.nvram_brand_map.keys():
                value = self.nvram_brand_map[key]
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % key)
                changelog.append("[ROADBLOCK] requires NVRAM VALUE: %s" %  value)
            elif key in self.nvram_map.keys():
                value = self.nvram_map[key]
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % key)
                changelog.append("[ROADBLOCK] requires NVRAM VALUE: %s" %  value)
            else:
                entry = "%s=\n" % (key)
                changelog.append("[ROADBLOCK] requires NVRAM KEY: %s"  % entry)
            if "toa-sta" in key:
                continue
            print("    - adding nvram key: %s=%s" % (key, value))
            if os.path.isdir(key_path):
                print("    ! skipping invalid key", key)
                continue
            with open(key_path, "w") as keyFile:
                keyFile.write(value)
            keyFile.close()
        subprocess.run(["chmod", "-R", "a+rw", self.nvram_key_value_path])

        keylog = []
        with open(self.nvram_init_path, "r") as nvramFile:
            for line in nvramFile:
                line = line.strip()
                if line not in keylog:
                    keylog.append(line)
            for key in keys:
                if key not in keylog:
                    keylog.append(key)
        nvramFile.close()


        with open(self.nvram_init_path, "w") as nvramFile:
            for key in keylog:
                nvramFile.write(key+"\n")
        nvramFile.close()

    def check_ip(self, ip):
        if len(ip) > 0:
            try:
                ipaddress.ip_address(ip)
                return True
            except ValueError:
                pass
        return False

    def get_ips_from_nvram(self):
        nvramIPfiles = []
        nvram_ips = []
        with open(self.nvram_init_path, "r") as nvramFile:
            for line in nvramFile:
                for iptag in NVRAM_IP_KEYS:
                    if iptag in line:
                        nvramIPfiles.append(line.strip())
        nvramFile.close()

        for key in nvramIPfiles:
            path = os.path.join(self.nvram_key_value_path, key)
            nvramVal = ""
            with open(path, "r") as nvramFile:
                nvramVal = nvramFile.read().strip()
            if len(nvramVal) > 0 and nvramVal not in nvram_ips and self.check_ip(nvramVal):
                nvram_ips.append(nvramVal)

        return nvram_ips



class Planter():
    def __init__(self, gh_path, scripts_path, qemu_src_path, brand, unpack_enhance, args):
        self.gh_path = gh_path
        self.gh_templates_path = os.path.join(self.gh_path, "templates")
        self.scripts_path = scripts_path
        self.qemu_src_path = qemu_src_path
        self.fixer = None
        self.brand = brand
        self.unpack_enhance = unpack_enhance
        self.indicators = ["/bin/sh", "/bin/busybox", "/sbin/lighttpd", "/sbin/xmldb", "/sbin/httpd", "shttpd"]
        
        self.args = args

    def identify_target_folder(self, extracted_path):
        found_fs = ""
        for root, dirs, subdirs in os.walk(extracted_path):
            dirs_sorted = sorted(dirs)
            for d in dirs_sorted:
                target_path = os.path.join(root, d)
                for target_root, target_dirs, target_files in os.walk(target_path):
                    for td in sorted(target_dirs):
                        if "bin" in td:
                            binfolder_path = os.path.join(target_root, td)
                            binfolder_path = os.path.realpath(binfolder_path)
                            if not binfolder_path.startswith(extracted_path):
                                continue
                            bin_files = os.listdir(binfolder_path)
                            for f in sorted(bin_files):
                                bin_path = os.path.join(target_root, td, f)
                                for indicator in self.indicators:
                                    if bin_path.endswith(indicator):
                                        full_path = str(pathlib.Path(bin_path).resolve()) # handle symlinks
                                        print("Checking arch of binary at ", full_path)
                                        if not os.path.exists(full_path):
                                            print("    - does not exist, skipping...")
                                            continue
                                        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
                                        stdout = sp.stdout
                                        print("    - ", stdout)
                                        arch = Fixer.get_arch_from_file_command(stdout)
                                        if arch in ARCH_MAP.keys():
                                            found_fs = target_root
                                            return found_fs
        return ""

    def identify_target_folder_enhance(self, extracted_path):
        def fix_img_unpack(fs_path, extracted_path_):
            for i in os.listdir(fs_path):
                path = os.path.join(fs_path, i)

                if os.path.isdir(path) and len(os.listdir(path)) == 0:  # find empty dir
                    # sqfs.img
                    img_name = os.path.basename(path) + ".img"  # find .img file
                    img_path = path + ".img"  # find .img file
                    if os.path.exists(img_path):
                        imt_extract_path = os.path.join(fs_path, "_" + img_name + ".extracted")
                        if os.path.exists(imt_extract_path):
                            src = os.path.join(imt_extract_path, "squashfs-root")
                            dst = path
                            cmd = f"cp -r {src}/* {dst}/"
                            stdout = subprocess.run(cmd, shell=True, text=True, capture_output=True).stdout
                            print(stdout)
                            stdout = subprocess.run(f"rm -rf {imt_extract_path}", shell=True, text=True, capture_output=True).stdout
                        else:  # TODO: use binwalk unpack
                            pass
                    # seme dirs is empty, but same name dir in other binwalk dirs, copy it
                    # hunt, dlink/DCS_6004L_REVA_FIRMWARE_1.01.14_WW.ZIP
                    dir_name = os.path.basename(path)
                    if "hunt" in dir_name or "www" in dir_name: # maybe we can remove this check
                        hunt_dirs = [os.path.join(extracted_path_, get_rel_path(i)) for i in find_directories_name(extracted_path, dir_name)]
                        if path in hunt_dirs:
                            hunt_dirs.remove(path)
                        if len(hunt_dirs) > 0:
                            for src in hunt_dirs:
                                cmd = f"rsync -av --ignore-existing {src}/ {path}/"
                                print(cmd)
                                stdout = subprocess.run(cmd, shell=True, text=True, capture_output=True).stdout
                                print(stdout)

        extracted_path_ = extracted_path # for fix_img_path
        found_fs = ""
        for root, dirs, subdirs in os.walk(extracted_path):
            dirs_sorted = sorted(dirs)
            for d in dirs_sorted:
                target_path = os.path.join(root, d)
                for target_root, target_dirs, target_files in os.walk(target_path):
                    for td in sorted(target_dirs):
                        if "sqfs.img.extracted" in target_root or "modsqfs.img.extracted" in target_root:
                            continue

                        if "bin" in td:  # FVS318G_v3.0.8_12
                            binfolder_path = os.path.join(target_root, td)
                            binfolder_path = os.path.realpath(binfolder_path)
                            if not binfolder_path.startswith(extracted_path):
                                continue
                            if "_busybox.extracted" in os.listdir(binfolder_path):
                                continue
                            file_list = [os.path.basename(i) for i in get_all_filenames(target_root)]
                            if not "hunt" in dirs_sorted:
                                if not any(file in POTENTIAL_HTTPSERV for file in file_list):
                                    if not any(file in ['main', 'webs', 'cfm'] for file in file_list):  # potential binary
                                        continue

                            bin_files = os.listdir(binfolder_path)
                            for f in sorted(bin_files):
                                bin_path = os.path.join(target_root, td, f)
                                for indicator in self.indicators:
                                    if bin_path.endswith(indicator):
                                        full_path = str(pathlib.Path(bin_path).resolve()) # handle symlinks
                                        print("Checking arch of binary at ", full_path.replace(target_path, ""))
                                        if not os.path.exists(full_path):
                                            print("    - does not exist, skipping...")
                                            continue
                                        if "/system/usr/" in full_path: # M7200_EU_V2_201020
                                            continue
                                        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
                                        stdout = sp.stdout
                                        stdout = stdout.replace(target_path.encode("u8"), b"") # handle lfwc path
                                        arch = Fixer.get_arch_from_file_command(stdout)
                                        print("    - ", f"[{arch}]", stdout)
                                        if arch in ARCH_MAP.keys():
                                            found_fs = target_root
                                            fix_img_unpack(found_fs, extracted_path_)
                                            return found_fs

        if found_fs == "":
            for target_root, target_dirs, target_files in os.walk(extracted_path):
                for td in sorted(target_dirs):
                    if "sqfs.img.extracted" in target_root or "modsqfs.img.extracted" in target_root:
                        continue
                    if "bin" in td or "pfrm":
                        binfolder_path = os.path.join(target_root, td)
                        binfolder_path = os.path.realpath(binfolder_path)
                        if not binfolder_path.startswith(extracted_path):
                            continue
                        file_list = [os.path.basename(i) for i in get_all_filenames(target_root)]
                        if not any(file in POTENTIAL_HTTPSERV for file in file_list):
                            continue
                        bin_files = os.listdir(binfolder_path)
                        for f in sorted(bin_files):
                            bin_path = os.path.join(target_root, td, f)
                            for indicator in self.indicators:
                                if bin_path.endswith(indicator):
                                    full_path = str(pathlib.Path(bin_path).resolve())  # handle symlinks
                                    print("Checking arch of binary at ", full_path)
                                    if not os.path.exists(full_path):
                                        print("    - does not exist, skipping...")
                                        continue
                                    sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
                                    stdout = sp.stdout
                                    print("    - ", stdout)
                                    arch = Fixer.get_arch_from_file_command(stdout)
                                    if arch in ARCH_MAP.keys():
                                        found_fs = target_root
                                        fix_img_unpack(found_fs, extracted_path_)
                                        return found_fs
        return ""
    
    def lfwc_unpack_success(self, extracted_path):
        """Check if extraction produced a valid filesystem by looking for standard Linux directories."""
        def get_all_subdirectories(root_dir):
            subdirs = []
            for dirpath, dirnames, _ in os.walk(root_dir):
                for dirname in dirnames:
                    subdirs.append(dirname)
            return subdirs
        
        if bool(set(get_all_subdirectories(extracted_path)) & set(
                ["bin", "var", "www", "etc", "sbin", "boot", "home", "lib", "opt", "root", "src", "usr"])):
            return True
        
        return False
    # def zip_extracted_fs(self, output_path, extracted_path):
    #     """
    #     Creates a zip archive of the contents of extracted_path without including extracted_path itself.
    # 
    #     Args:
    #         image_name (str): The name of the image (used for naming the zip file).
    #         extracted_path (str): The directory whose contents will be zipped.
    # 
    #     Returns:
    #         str: The path to the created zip file.
    #     """
    #     
    #     def rm_extracted_files(extracted_path):
    #         """
    #         4334  _4334.extracted
    #         R8900-V1.0.1.36.img _R8900-V1.0.1.36.img.extracte
    #         :param extracted_path:
    #         :return:
    #         """
    #         for root, dirs, files in os.walk(extracted_path):
    #             for file in files:
    #                 extracted_dir = os.path.join(root, f"_{os.path.basename(file)}.extracted")
    #                 if os.path.isdir(extracted_dir):
    #                     print(f"Removing extracted file: {file}")
    #                     os.remove(os.path.join(root, file))
    #     
    #     rm_extracted_files(extracted_path)
    #     
    #     zip_path = os.path.join("/tmp", output_name)
    #     
    #     # zip_path，10G，
    #     if os.path.exists(zip_path):
    #         if os.path.getsize(zip_path) > 10 * 1024 * 1024 * 1024:
    #             print(f"Zip file {zip_path} is too large, skipping")
    #             return ""
    #     
    #     # Change directory to extracted_path and zip all its contents
    #     cmd = f'cd "{extracted_path}" && zip -r -y "{zip_path}" .'
    #     
    #     print("    - Zipping extracted fs to", zip_path)
    #     print("    - ", cmd)
    #     
    #     subprocess.run(cmd, shell=True, check=True)
    #     print("    - Done")
    #     
    #     return zip_path
    
    def mksquashfs(self, output_path, extracted_path):
        def rm_extracted_files(extracted_path):
            for root, dirs, files in os.walk(extracted_path):
                for file in files:
                    extracted_dir = os.path.join(root, f"_{os.path.basename(file)}.extracted")
                    if os.path.isdir(extracted_dir):
                        print(f"Removing extracted file: {file}")
                        os.remove(os.path.join(root, file))
        
        rm_extracted_files(extracted_path)

        # Skip if extracted path is too large (>10GB)
        if os.path.exists(extracted_path):
            if os.path.getsize(extracted_path) > 10 * 1024 * 1024 * 1024:
                print(f"Zip file {extracted_path} is too large, skipping")
                return ""
        
        cmd = f'cd "{extracted_path}" && mksquashfs . "{output_path}" -noappend'
        
        print("    - mksquashfs extracted fs to", output_path)
        print("    - ", cmd)
        
        subprocess.run(cmd, shell=True, check=True)
        print("    - Done")
        
        return output_path
    
    def unpack_by_fact_extractor(self, img_path, extracted_path):
        print("try to unpack by fact_extractor")
        extracted_path = "/tmp/fact_extracted"
        if os.path.exists(extracted_path):
            shutil.rmtree(extracted_path)
    
        fact_extract_script = os.path.join(self.scripts_path, "fact_extractor_wrapper.py")
        fact_cmd = f'python {fact_extract_script} -e -r "{img_path}" {extracted_path}'
        print("    - Running fact cmd:", fact_cmd)
    
        print(f"POD_NAME" in os.environ.keys())
        if "POD_NAME" in os.environ.keys():
            os.environ['DOCKER_HOST'] = 'tcp://127.0.0.1:2375'
            print("DOCKER_HOST", os.environ["DOCKER_HOST"])

        subprocess.run(fact_cmd, shell=True)
        
        print("    - Done")
        
        return extracted_path
    
    def fact_extract(self, img_path, extracted_path, extract_only_flag=False):
        iid = None
        # Create the output directory
        output_dir = "/output/images/"
        os.makedirs(output_dir, exist_ok=True)
        
        # Run the FirmAE extractor script with the specified parameters
        fact_cmd = ['/root/venv/bin/python', '/fw/firmwell/tools/scripts/FirmAE_extractor.py', '-b', self.brand, '-d', '-sql',
                    '127.0.0.1', '-np', img_path, output_dir]
        try:
            print(f"Running extract command '{' '.join(fact_cmd)}'")
            result = subprocess.run(fact_cmd, timeout=1800, capture_output=True, text=True)
            print(result.stdout)
            print(result.stderr)
        except subprocess.TimeoutExpired:
            print(f"Command '{' '.join(fact_cmd)}' timed out")
        except subprocess.CalledProcessError as e:
            print(f"Command '{' '.join(fact_cmd)}' failed with return code {e.returncode}")
        
        script_path = '/fw/firmwell/tools/scripts/db_util.py'
        # Run the script and capture the output
        try:
            result = subprocess.run(['/root/venv/bin/python', script_path, "get_iid", img_path, "127.0.0.1"], capture_output=True, text=True,
                                    check=True)
            output = result.stdout
            print("Script output:", output)
            
            if len(output.strip()) > 0 and not iid:
                iid = output.strip()
                print(f"iid: {iid}")
        except subprocess.CalledProcessError as e:
            print(f"Error running script: {e}")
            print(f"Script output: {e.output}")
            
        # Extract the tar.gz file to the extracted_path
        import tarfile
        tar_path = os.path.join(output_dir, f"{iid}.tar.gz")
        if os.path.exists(tar_path):
            unpack_succ = True
            print("FirmAE_extractor unpack success")
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=extracted_path)
        else:
            print("FirmAE_extractor unpack success")
            unpack_succ = False
        
        if not unpack_succ:
            # Run the FirmAE extractor script with the specified parameters
            fact_cmd = ['/root/venv/bin/python', '/fw/firmwell/tools/scripts/FirmAE_extractor_fact.py', '--fact', '-b', self.brand, '-d', '-sql',
                        '127.0.0.1', '-np', img_path, output_dir]
            try:
                print(f"Running fact command '{' '.join(fact_cmd)}'")
                result = subprocess.run(fact_cmd, timeout=1800, capture_output=True, text=True)
                print(result.stdout)
                print(result.stderr)
            except subprocess.TimeoutExpired:
                print(f"Command '{' '.join(fact_cmd)}' timed out")
            except subprocess.CalledProcessError as e:
                print(f"Command '{' '.join(fact_cmd)}' failed with return code {e.returncode}")
            
            script_path = '/fw/firmwell/tools/scripts/db_util.py'
            iid = None
            # Run the script and capture the output
            try:
                result = subprocess.run(['/root/venv/bin/python', script_path, "get_iid", img_path, "127.0.0.1"],
                                        capture_output=True, text=True, check=True)
                output = result.stdout
                print("Script output2:", output)
                
                if len(output.strip()) > 0:
                    iid = output.strip()
                    print(f"iid: {iid}")
            except subprocess.CalledProcessError as e:
                print(f"Error running script: {e}")
                print(f"Script output: {e.output}")
            
            # Extract the tar.gz file to the extracted_path
            import tarfile
            tar_path = os.path.join(output_dir, f"{iid}.tar.gz")
            if os.path.exists(tar_path):
                unpack_succ = True
                print("FirmAE_extractor_fact unpack success")
                with tarfile.open(tar_path, "r:gz") as tar:
                    tar.extractall(path=extracted_path)
            else:
                unpack_succ = False
                print("FirmAE_extractor_fact unpack failed")

        # save info
        if extract_only_flag:
            print("Extract only flag is set, exiting after extraction")
            if unpack_succ:
                unpack_info = {
                    "unpack_succ": True,
                    "http_potential_binaries" : self.get_target_binary(extracted_path, "HTTP"),
                    "upnp_potential_binaries" : self.get_target_binary(extracted_path, "UPNP"),
                    "dns_potential_binaries" : self.get_target_binary(extracted_path, "DNS"),
                }
            else:
                unpack_info = {
                    "unpack_succ": False,
                    "http_potential_binaries": [],
                    "upnp_potential_binaries": [],
                    "dns_potential_binaries": [],
                }
            
            
            print("="*50)
            from pprint import pprint
            pprint(unpack_info)
            print("="*50)
            print(os.listdir("/tmp"))
            json.dump(unpack_info, open(self.args.fixpath, 'w'), indent=4)
            exit(0)
            
        return unpack_succ, extracted_path
            
            
    
    def unpack_image(self, img_path, fs_path_override, sha256hash):
        img_path = os.path.realpath(img_path)
        print("    - Unpacking image", img_path)
        image_name = os.path.basename(img_path)
        dir_name = os.path.dirname(img_path)
        
        if not os.path.exists(img_path):
            print("    ! Image path %s does not exist, skipping..." % img_path)
            return ""
        
        dir_base = os.path.basename(dir_name)
        dir_name = os.path.join(EXTRACT_PATH, dir_base)
        extracted_name = "_"+image_name+".extracted"
        extracted_path = os.path.join(dir_name, extracted_name)
        print("    - Extracted path:", extracted_path)


        
        
        if fs_path_override != "":
            if os.path.exists(fs_path_override):
                print("    - Using known rootfs path", fs_path_override)
                fs_path = fs_path_override.rstrip("/")
                return fs_path
            else:
                print("known rootfs path %s does not exist, defaulting to search..." % fs_path_override)
        
        
        if os.path.exists(extracted_path):
            print("Extracted directory %s already exists, skipping extraction" % extracted_path)
            cmd = f"rm -rf {extracted_path}"
            subprocess.run(cmd, shell=True)
        
        # use fact extractor
        unpack_succ, extracted_path = self.fact_extract(img_path, extracted_path, self.args.unpack2zip)
        if unpack_succ:
            fs_path_override = extracted_path
            
        if fs_path_override != "":
            if os.path.exists(fs_path_override):
                print("    - Using known rootfs path", fs_path_override)
                fs_path = fs_path_override.rstrip("/")
                return fs_path
            else:
                print("known rootfs path %s does not exist, defaulting to search..." % fs_path_override)
        
        # ==================================
        # legacy, use binwalk
        filename = os.path.basename(img_path)
        src = img_path
        firm_dir = "/tmp/firm"
        if not os.path.exists(firm_dir):
            os.mkdir(firm_dir)
        dst = os.path.join(firm_dir, sha256hash) # use sha256hash as folder name
        extracted_name = "_"+sha256hash+".extracted"
        extracted_path = os.path.join(dir_name, extracted_name)
        shutil.copy(src, dst)
        img_path = dst
        
        
        
        # current we use firmae_extractor.py to get input fs
        curruser = getpass.getuser()
        binwalk_command = ["binwalk"]
        if curruser == "root":
            binwalk_command.extend(["--run-as=root"])
        binwalk_command.extend(["--preserve-symlinks", "-eMq", "-r", img_path, "-C", dir_name])

        # unpack firmware if haven't extracted yet
        if not os.path.exists(extracted_path) or (
                os.path.exists(extracted_path) and len(os.listdir(extracted_path)) == 0):
            print("binwalk cmd:")
            print(binwalk_command)
            subprocess.run(binwalk_command)
            time.sleep(1)


        if os.path.exists(extracted_path):
            # make entire folder RWXtable
            print("Calling chmod  on", extracted_path)
            sp = subprocess.run(["chmod", "-R", "a+rwx", extracted_path])
            stdout = sp.stdout
            print("    - ", stdout)
            if self.unpack_enhance:
                found_fs = self.identify_target_folder_enhance(extracted_path)
            else:
                found_fs = self.identify_target_folder(extracted_path)

            print("Found root dir at %s" % found_fs)
            
            try: # rm /tmp/firm/firmwarexxx
                shutil.rmtree(firm_dir)
            except OSError as e:
                print(f"Error: {e.strerror}")


            if len(found_fs) > 0:
                return found_fs
        else:
            print("ERROR %s does not exist!" % extracted_path)


        print("Unable to find a proper root directory for ")
        print(extracted_path)
        
        # print all files in extracted_path for debug
        for i in get_all_filenames(extracted_path):
            print(i)
        return ""

    def get_potential_binaries(self, rehost_type):
        http_server = POTENTIAL_HTTPSERV
        if rehost_type == "HTTP":
            return http_server
        elif rehost_type == "UPNP":
            return POTENTIAL_UPNPSERV
        elif rehost_type == "DNS":
            return POTENTIAL_DNSSERV
        elif rehost_type == "DHCP":
            return POTENTIAL_DHCPSERV
        return "UNKNOWN"

    def get_target_binary(self, fs_path, rehost_type):
        potential_binaries = self.get_potential_binaries(rehost_type)
        pot_targets = dict()
        potential_http_set = set()
        
        for root, dirs, files in os.walk(fs_path, topdown=False):
            for name in files:
                if name in potential_binaries:
                    if name not in pot_targets.keys():
                        pot_targets[name] = []
                    pot_targets[name].append(os.path.join(root, name))
        
        if rehost_type == "DNS":
            if "dnsmasq" in pot_targets.keys() and "ddnsd" in pot_targets.keys():
                pot_targets.pop("ddnsd")
                
        # For UPNP service, prefer miniupnpd over miniupnpc if both exist
        if rehost_type == "UPNP" and "miniupnpc" in pot_targets.keys() and "miniupnpd" in pot_targets.keys():
            pot_targets.pop("miniupnpc")
        
        print("Potential Binaries: ", pot_targets)
        # return "best" match in order listed in potential_binaries
        for binary in potential_binaries:
            if binary in pot_targets.keys():
                for bin_path in pot_targets[binary]:
                    if "rc_app" not in bin_path:
                        tmp_bin_path = str(pathlib.Path(bin_path).resolve())
                    # For symlinked binaries (e.g. httpd -> busybox), use the original name
                    sp = subprocess.run(["file", tmp_bin_path], stdout=PIPE, stderr=PIPE)
                    stdout = sp.stdout
                    print(stdout)
                    details = stdout.split(b":")[1].strip()
                    if details.startswith(b"ELF "):
                        print("    - Found binary: %s" % bin_path)
                        potential_http_set.add(bin_path)

        # for binary in potential_binaries:
        #     if binary in pot_targets.keys():
        #         for bin_path in pot_targets[binary]:
        #             sp = subprocess.run(["file", bin_path], stdout=PIPE, stderr=PIPE)
        #             stdout = sp.stdout
        #             print(stdout)
        #             details = stdout.split(b":")[1].strip()
        #             if details.startswith(b"ELF "):
        #                 print("    - Found binary: %s" % bin_path)
        #                 # return bin_path
        #                 potential_http_set.add(bin_path)
        if len(potential_http_set) == 0:
            return ""
        else:
            self.potential_http_set = potential_http_set
            return min(potential_http_set, key=lambda x: len(os.path.basename(x)))


    def get_mac_from_nvrams(self, fs_path):
        # heuristic for targets the require a specific mac address
        nvram_key_value_path = os.path.join(fs_path, NVRAM_KEY_VALUE_FOLDER)
        if os.path.exists(nvram_key_value_path):
            nvram_keys = os.listdir(nvram_key_value_path)
            for key in nvram_keys:
                key = key.strip()
                if key in MAC_NVRAM_KEYS:
                    keypath = os.path.join(nvram_key_value_path, key)
                    value = ""
                    if os.path.exists(keypath):
                        with open(keypath, "r") as vFile:
                            value = vFile.read().strip()
                            match = re.match(r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}", value)
                            if match is not None:
                                value = match.group(0)
                        vFile.close()
                    else:
                        print("    - unable to open keypath", keypath)
                    if len(value) > 0:
                        return value
        return ""

    def setup_env(self, qemu_src_path, fs_path, bin_path, fixbash, name, enable_nvram_faker, enable_nvram_sematic,
                  enable_fix_dev, no_start_with_nvram, no_basic_dev, args):
        """Create a Fixer instance and run initial environment setup."""
        self.fixer = Fixer(qemu_src_path, self.gh_path, self.scripts_path, self.brand, name, fixbash, args)
        r = self.fixer.initial_setup(fs_path, bin_path, enable_nvram_faker, enable_nvram_sematic, enable_fix_dev, no_start_with_nvram, no_basic_dev)
        return r 

    def check_cwd(self, fs_path, targets, old_cwd, cwd_rh_replaced, already_success):
        if cwd_rh_replaced or already_success:
            print("    - already got correct directory, skipping...")
            return False, old_cwd
        relative_targets = []
        for target in targets:
            if not target.startswith("/") and target not in relative_targets:
                relative_targets.append(target)

        cwds = dict()
        for target in relative_targets:
            # skip none html and cgi files, we can pretty much copy everything else
            ext = target.split(".")[-1]
            if ext not in WEB_EXTS:
                continue
            # check if file might exists somewhere else
            path = os.path.join(fs_path, target)
            sourcefiles = self.fixer.find_files(os.path.basename(target), fs_path, include_backups=True, skip=[path])
            for sourcefile in sourcefiles:
                print("target", target, "source", sourcefile)
                if len(sourcefile) > 0:
                    cwd_path = os.path.dirname(sourcefile)
                    relative_path = os.path.relpath(cwd_path, fs_path)
                    if relative_path not in cwds and relative_path != ".":
                        cwds[relative_path] = 0
                    if relative_path != ".":
                        print("    - adding relative path", target)
                        cwds[relative_path] += 1

        if len(cwds) <= 0:
            print("No relative cwd targets found")
            return False, old_cwd

        # else len(cwds) > 1:
        print("More than one possible CWD: ", cwds)
        majority_cwds = []
        highest = 0
        for k, v in cwds.items():
            if v > highest:
                majority_cwds.clear()
                highest = v
            if v >= highest:
                majority_cwds.append(k)
        cwds_sorted = sorted(majority_cwds, key=lambda x: ("www" not in x and "web" not in x and "htm" in x, x.count('/'), len(x), x))
        cwd_path = cwds_sorted[0]
        print("CWD target found", cwd_path)
        return True, cwd_path

    def add_interfaces(self, interfaces, urls):
        # we rebuild the interface <-> ip address mapping each time
        # just to be safe
        new_urls = []
        noninterface_urls = []
        iface_cmds = []
        for url in urls:
            fields = url.split(".")
            if fields[0] == "172":
                id = int(fields[1])
                if id >= 100 and id < 200:
                    # is a special interface, skip
                    continue
            noninterface_urls.append(url)
        i = 1
        for iface in interfaces:
            url = ""
            url = "172.%s.0.1" % (100+i)
            if i > 100:
                print("ERROR - too many interfaces. skipping extra interface")
                continue
            # index of iface matches index in urls
            new_urls.append(url)
            iface_cmds.append("/greenhouse/ip link set eth%d down" % i)
            iface_cmds.append("/greenhouse/ip link set eth%d name %s" % (i, iface))
            iface_cmds.append("/greenhouse/ip link set %s up" % iface)            
            i += 1
        new_urls.extend(noninterface_urls)
        
        return new_urls, iface_cmds

    def get_subnet(self, ipaddr, netmask="255.255.255.0"):
        subnet_string = "%s/%s" % (ipaddr, netmask)
        subnet = ""
        try:
            subnet = str(ipaddress.ip_interface(subnet_string).network)
        except:
            pass
        return subnet

    def parse_ips(self, ip_targets_path, ip_addrs, old_ips=[]):
        new_ips = []
        in_use_subnets = []

        # check in use ips
        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            for ip in adapter.ips:
                in_use_subnet = self.get_subnet(ip.ip)
                if len(in_use_subnet) > 0:
                    in_use_subnets.append(in_use_subnet)

        for ip in ip_addrs:
            subnet = self.get_subnet(ip)
            if ip not in RESERVED_IPS and \
               ip not in old_ips and \
               not ip.startswith("255.") and \
               not ip.endswith(".255") and \
               not ip.endswith(".0") and \
               subnet not in in_use_subnets:
                print("    - adding ip device %s" % ip)
                new_ips.append(ip)

        # update ip targets
        with open(ip_targets_path, "w+") as ipFile:
            for ip in old_ips:
                ipFile.write(ip+"\n")
            for ip in new_ips:
                ipFile.write(ip+"\n")
        ipFile.close()

        return new_ips

    def parse_ports(self, ports_path, ports, old_ports=[]):
        new_ports = []
        for p in ports:
            if p not in old_ports and p not in PORTS_BLACKLIST:
                print("    - adding port target %s" % p)
                new_ports.append(p)

        # update ip targets
        with open(ports_path, "w+") as portFile:
            for p in old_ports:
                if p not in PORTS_BLACKLIST:
                    portFile.write(p+"\n")
            for p in new_ports:
                if p not in PORTS_BLACKLIST:
                    portFile.write(p+"\n")
        portFile.close()

        return new_ports


    def get_ips_from_nvram(self):
        return self.fixer.get_ips_from_nvram()


    def get_qemu_run_path(self):
        if self.fixer == None:
            return ""
        return self.fixer.qemu_run_path

    def get_qemu_arch(self):
        if self.fixer == None:
            return ""
        return self.fixer.qemu_arch
    
    def remove_ssl_sections(self, conf_text):

        mod_openssl_pattern = re.compile(r'\s*"mod_openssl"\s*,?')

        socket_block_pattern = re.compile(r'^\s*\$SERVER\["socket"\]\s*==\s*"(?:\:443|\[::\]:443)"\s*\{')

        lines = conf_text.splitlines()
        new_lines = []
        skip_block = False
        block_brace_count = 0

        for line in lines:
            if not skip_block and socket_block_pattern.search(line):
                skip_block = True
                block_brace_count = line.count('{') - line.count('}')
                continue

            if skip_block:
                block_brace_count += line.count('{') - line.count('}')
                if block_brace_count <= 0:
                    skip_block = False
                continue

            if mod_openssl_pattern.search(line):
                continue

            new_lines.append(line)
        
        # Preserve original file's ending (with or without final newline)
        result = "\n".join(new_lines)
        result = result + "\n"
        return result

    def clean_fs(self, target_fs):

        target_fs = os.path.realpath(target_fs)
        print("    - cleaning", target_fs)
        for root, dirs, files in os.walk(target_fs, topdown=False):
            for f in files:
                fpath = os.path.join(root, f)
                fpath = os.path.realpath(fpath)
                if os.path.exists(fpath) and fpath.startswith(target_fs):
                    st_mode = os.stat(fpath).st_mode
                    if stat.S_ISBLK(st_mode) or stat.S_ISCHR(st_mode) or stat.S_ISSOCK(st_mode) or stat.S_ISFIFO(st_mode):
                        print("    - replacing special file", fpath)
                        os.unlink(fpath)
                        if not (stat.S_ISSOCK(st_mode) or stat.S_ISBLK(st_mode) or stat.S_ISCHR(st_mode)):
                            # do not recreate sock files
                            # blk and chr device creation handled by script now
                            os.mknod(fpath)
                
                if f == "etc/lighttpd/lighttpd.conf":
                    if os.path.exists(fpath):
                        lines = []
                        with open(fpath, "r", encoding="utf-8", errors="surrogateescape") as confFile:
                            for line in confFile:
                                if line.strip().startswith("mod_cgi"):
                                    line = "#        " + line.strip() + "\n"
                                lines.append(line)
                        confFile.close()

                        with open(fpath, "w", encoding="utf-8", errors="surrogateescape") as confFile:
                            for line in lines:
                                confFile.write(line)
                        confFile.close()
                
                if f == "netconf":
                    with open(fpath, "r") as f:
                        lines = f.readlines()
                    with open(fpath, "w") as f:
                        for line in lines:
                            if "#/usr/sbin/lighttpd" in line:
                                line = line.replace("#/usr/sbin/lighttpd", "/usr/sbin/lighttpd")
                            f.write(line)
                            
                if f.endswith(".html"):
                    try:
                        if os.path.exists(fpath) and not os.path.islink(fpath):
                            st_mode = os.stat(fpath).st_mode
                            if stat.S_IXUSR & st_mode:
                                os.chmod(fpath, st_mode & ~stat.S_IXUSR)
                    except (OSError, IOError) as e:
                        print(f"Warning: Could not process {fpath}: {str(e)}")
                        
                if f == "boa-dog.sh":
                    if os.path.exists(fpath):
                        os.rename(fpath, fpath + ".bak")
    def preprocess_filesystem(self, file_system, file_list, fs_path, basepath, templates_path):
        """
        Preprocess the firmware filesystem with various enhancements and fixes.
        This method handles htmlunpack extraction, language file copying, sqfs handling, etc.
        
        Args:
            file_system: FileSystem object
            file_list: List of all filenames in the filesystem
            fs_path: Path to the filesystem
            basepath: Base path for templates
            templates_path: Path to templates directory
        """
        
        """
        root@0a6ef83f6610:/fs# chroot . /qemu-mipsel-static /bin/htmlunpack /etc_ro/web/pack/eng.lzma /etc_ro/web
total files=90
total file types=3
ext=js      , num=3
ext=css     , num=2
ext=htm     , num=85
qemu: uncaught target signal 10 (Bus error) - core dumped
Bus error
        """
        
        if any("htmlunpack" in file for file in file_list):
            htmlunpack = os.path.join(fs_path, "bin", "htmlunpack")
            os.rename(htmlunpack, htmlunpack + ".bak")
            web_archive = os.path.join(basepath, 'tools', 'templates', 'web.tar.gz')
            web_src = os.path.join(basepath, 'tools', 'templates', 'web')
            if not os.path.isdir(web_src) and os.path.isfile(web_archive):
                import tarfile
                with tarfile.open(web_archive, 'r:gz') as tar:
                    tar.extractall(path=os.path.join(basepath, 'tools', 'templates'))
            web_dst = os.path.join(fs_path, 'etc_ro', 'web')

            # Extract eng.lzma if it exists
            eng_lzma = os.path.join(web_dst, "pack/cht.lzma")
            if os.path.exists(eng_lzma):
                try:
                    # Decompress eng.lzma
                    with open(eng_lzma, 'rb') as f:
                        comp = f.read()
                    data = lzma.decompress(comp)

                    # Extract files from decompressed data
                    p = 0
                    extracted = 0
                    name_pattern = re.compile(r'^[\w\-.]+\.(?:htm|html|css|js)$', re.I)
                    total_len = len(data)
                    
                    while True:
                        # Find three null byte marker
                        pos = data.find(b'\x00\x00\x00', p)
                        if pos == -1 or pos + 3 >= total_len:
                            break

                        # Get filename
                        start = pos + 3
                        i = start
                        while i < total_len and 0x21 <= data[i] <= 0x7e:
                            i += 1
                        name = data[start:i].decode('ascii', 'ignore')

                        # Validate filename extension
                        if not name_pattern.match(name):
                            p = pos + 1
                            continue

                        # Get file length
                        if i + 8 > total_len:
                            break
                        length = struct.unpack_from('<I', data, i + 4)[0]
                        data_start = i + 8
                        data_end = data_start + length

                        # Boundary check
                        if data_end > total_len:
                            print(f'Warning: {name} exceeds data boundary, skipping')
                            p = pos + 1
                            continue

                        # Write file
                        out_path = os.path.join(web_dst, name)
                        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
                        with open(out_path, 'wb') as fo:
                            fo.write(data[data_start:data_end])
                        print(f'Extracted: {name} ({length} Bytes) -> {out_path}')
                        extracted += 1
                        p = data_end

                    print(f'Total files extracted: {extracted}')

                except Exception as e:
                    print(f"Error extracting eng.lzma: {str(e)}")
        
        
        languages_en_js = os.path.join(fs_path, "www.satellite", "languages-en.js")
        if os.path.exists(languages_en_js):
            try:
                Files.copy_file(languages_en_js, os.path.join(fs_path, "www", "languages-en.js"))
            except Exception as e:
                print(e)
        
        # TODO, move to preprocess
        # for sqfs, copy sqfs/home/web to home/web
        if any("sqfs.img" in file for file in file_list):
            try:
                home_web = os.path.join(fs_path, "home", "web")
                Files.rm_file(home_web)  # symbol link
                sqfs_web = os.path.join(fs_path, "sqfs", "home", "web")
                Files.copy_directory(sqfs_web, home_web)
                login_html_ori = os.path.join(home_web, "html", "login.html")
                login_html_dst = os.path.join(home_web, "login.html")
                
                if os.path.islink(login_html_dst):
                    Files.rm_file(login_html_dst)
                    Files.copy_file(login_html_ori, login_html_dst)
            except Exception as e:
                print(e)
        
        # unpack error, sym link err, rc_apps
        if file_system.file_in_filesystem("rc_apps"):
    
            # qemu user mode cant resolve sym link in multi layer sym link
            src_etc = os.path.join(fs_path, "usr/etc")
            dst_etc = os.path.join(fs_path, "tmp/etc")
            os.makedirs(dst_etc, exist_ok=True)
            Files.copy_directory(src_etc, dst_etc)

    def preprocess_bash2(self, FileSystem, tmp_fs_path):
        '''
        for bash script, add debug info record
        '''
        debug_script = ['set -x', 'exec >> FIRMWELL_BASH 2>&1', "echo $0"]
        protect_file = ['fake_mtd.sh', 'sanitize_dev.sh', 'killer.sh', 'fw.sh', "create_mtd.sh", "clean_fs.sh",
                        "GH_PATH_TRAVERSAL", "fw_watchdog.sh"]
        protect_file += ["passwd", "phpsh", "config", "lua"]
        protect_dir = ['dumaos', "gh_nvram"]
        analyzed = set()

        if FileSystem.file_in_filesystem("xmldb"):
            return

        for file in FileSystem.bash_files:
            file = file.replace("/ori_fs/", "/fs/")
            name = os.path.basename(file)
            abs_path = FileSystem.get_abs_path(file)

            if any(i in abs_path for i in protect_dir):
                continue

            if any(i in name for i in protect_file):
                continue

            # if name not endswith .php, .lua
            if name.endswith(".lua"):
                continue
            if name.endswith(".php"):
                continue
            if name.endswith(".php") or name.endswith(".html") or name.endswith(".htm"):
                continue

            try:
                if os.path.islink(file):
                    continue

                print("[preprocss_bash]", name)
                insert_multiple_lines_at(file, 2, debug_script)
                analyzed.add(file)

                with open(file, 'r', encoding='u8', errors='ignore') as f:
                    lines = f.readlines()
                    first_line = lines[0].strip()
                    if not first_line.startswith("#!") or "sh" not in first_line:
                        lines.insert(0, "#!/bin/sh\n")

                with open(file, 'w') as f:
                    f.writelines(lines)
                    print("[fix_bash]", name)

            except Exception as e:
                print("error preprocss_etc_bash")
                print(e)

    def fix_filesystem(self, fs_path, templates_path, arch):
        # for some dlink firmware, it will miss this lib
        def fix_libm(libm_file):
            libmso = os.path.join(fs_path, "lib", libm_file)
            sym_path = str(pathlib.Path(libmso).resolve())
            if os.path.islink(libmso) and not os.path.exists(sym_path):
                Files.copy_file(os.path.join(templates_path, "libm-0.9.30.so"), sym_path)

        fix_libm("libm.so.0")
        fix_libm("libm.so.1")

        # if fs have no /bin/sh, copy it
        if not os.path.exists(os.path.join(fs_path, "bin/sh")):
            if not os.path.exists(os.path.join(fs_path, "bin")):
                os.mkdir(os.path.join(fs_path, "bin"))
            busybox_src = os.path.join(templates_path, "busybox", arch, "busybox")
            Files.copy_file(busybox_src, os.path.join(fs_path, "bin/sh"))
            
    def remove_high_cpu_usage_process(self, fs_path, FileSystem, rehost_type):
        def rename_files(self, file_list):
            for f in file_list:
                os.rename(f, f + ".bak")
        
        rename_files(self, Files.find_file_paths(fs_path, "hotplug"))
        rename_files(self, Files.find_file_paths(fs_path, "hotplug2"))
        rename_files(self, Files.find_file_paths(fs_path, "hd-idle"))
        rename_files(self, Files.find_file_paths(fs_path, "afpd"))

        rename_files(self, Files.find_file_paths(fs_path, "minissdpd")) # DIR_825_REVC_FIRMWARE_3.00, block upnp
        
        rename_files(self, Files.find_file_paths(fs_path, "arpmonitor"))
        rename_files(self, Files.find_file_paths(fs_path, "udhcpd"))
    
        if rehost_type != "DNS" and FileSystem.file_in_filesystem("dnsmasq"):
            rename_files(self, Files.find_file_paths(fs_path, "dnsmasq"))
        
        if FileSystem.file_in_filesystem("avahi-daemon"):
            rename_files(self, Files.find_file_paths(fs_path, "avahi-daemon"))
        
        if rehost_type != "UPNP" and FileSystem.file_in_filesystem("obd"):
            rename_files(self, Files.find_file_paths(fs_path, "obd"))
        
        for tool in ["acfg_tool", "ebtables", "portt", "consoled", "getty", "ledSer", "timer", "wlxmlpatch"]:
            if FileSystem.file_in_filesystem(tool):
                rename_files(self, Files.find_file_paths(fs_path, tool))
        
        if self.brand == "asus":
            for tool in ["lldpd", "ahs", "nt_center", "obd_eth", "envrams"]:
                if FileSystem.file_in_filesystem(tool):
                    rename_files(self, Files.find_file_paths(fs_path, tool))
                    
        for f in Files.find_file_paths(fs_path, "monitor_http.sh"):  # trendnet, fork bomb
            os.rename(f, f + ".bak")
        for f in Files.find_file_paths(fs_path, "monitor_web.sh"):  # trendnet, fork bomb
            os.rename(f, f + ".bak")
        for f in Files.find_file_paths(fs_path, "monitor_upnpd.sh"):  # trendnet, fork bomb
            os.rename(f, f + ".bak")
        
        # can remove in release version, it is no harm for rehost http, but occur too more resource
        for f in Files.find_file_paths(fs_path, "crond"):  # FW_RT_AC67U_300438432799.zip, fork bomb,
            os.rename(f, f + ".bak")
        for f in Files.find_file_paths(fs_path, "networkmap"):
            os.rename(f, f + ".bak")
        for f in Files.find_file_paths(fs_path, "asd"):
            os.rename(f, f + ".bak")
