import os
import pathlib
from pprint import pprint
from .new_utils import *
from .Utils import Files

class EntryPoint:
    def __init__(self, fs_path, bin_path, brand):
        self.fs_path = fs_path
        self.bin_path = bin_path
        self.brand = brand
        self.etc = ""
        self.init_bash = ""
        self.init_bash_args = ""
        self.init_binary = ""
        self.init_binary_for_rc = "" # only for rc, record which binary links to rc
        self.init_binary_procd = ""
        self.type = None

    def get_result(self):
        print(f"init_bash:\t{self.init_bash}")
        print(f"init_bash_args:\t{self.init_bash_args}")
        print(f"init_binary:\t{self.init_binary}")
        print(f"init_binary_for_rc:\t{self.init_binary_for_rc}")
        return self.type, self.init_bash, self.init_bash_args, self.init_binary, self.init_binary_for_rc, self.etc

    def find_etc_dir(self):
        etc_list = ['etc', 'usr/etc', 'tmp/etc', "etc_ro"]

        indicators_files = ["rcS", "inittab", "hosts", "passwd", "TZ"]
        indicators_files += ["lld2d.conf", "ld.so.conf"] # for netgear
        indicators_dirs = ["init.d", "rc.d"]

        for tmp_etc in etc_list:
            etc_path = os.path.join(self.fs_path, tmp_etc)
            if not os.path.exists(etc_path):
                continue
            files = get_all_files_in_directory(etc_path)

            if any(i in files for i in indicators_files) or any(os.path.exists(os.path.join(self.fs_path, i)) for i in indicators_dirs):
                self.etc = tmp_etc
                return tmp_etc

        return ""

    def find_etc_preinit(self):
        rel_rcs_path = os.path.join(self.etc, "preinit")
        tmp_initd_rcs_path = os.path.join(self.fs_path, rel_rcs_path)
        if os.path.exists(tmp_initd_rcs_path):
            etc_preinit = "/" + rel_rcs_path  # /etc/init.d/rcS
            return etc_preinit

        return ""

    def parse_inittab(self, file):
        '''
        console::sysinit:/etc/rc.d/rcS
        ::respawn:/bin/sh
        # "console::sysinit:-/etc/init.d/rcS"
        # "::sysinit:/etc/init.d/rcS S boot"
        '''
        with open(file, 'r') as f:
            lines = f.readlines()

        new = []
        for line in lines:
            if "respawn" in line or "restart" in line:
               line = f"#{line}"

            new.append(line)

        with open(file, 'w') as f:
            f.writelines(new)

        with open(file, 'r') as f:
            for line in f:
                if "sysinit" in line and ("null::sysinit" not in line or "rc.sysinit" in line):
                    init_bash, args = "", ""
                    tmp = line.split(":")[-1].strip()
                    if tmp.startswith("-"):
                        tmp = tmp.replace("-", "", 1)
                    if " " in tmp:
                        init_bash, args = tmp.split(" ", 1)
                    else:
                        init_bash = tmp
                    if os.path.exists(os.path.join(self.fs_path, get_rel_path(init_bash))):
                        return init_bash, args
        return None, None

    def analysis_sbin_rc(self):
        """Find sbin/rc and resolve its symlink target if any."""
        sbin_init_path = ""
        sbin_init_link_path = ""
        potenial_init = ["sbin/rc", "usr/sbin/rc"]
        for rc_path in potenial_init:
            if os.path.exists(os.path.join(self.fs_path, rc_path)):
                sbin_init_path = rc_path

        if os.path.islink(os.path.join(self.fs_path, sbin_init_path)):
            sbin_init_link_path = get_target_link_path(self.fs_path, sbin_init_path)

        if not sbin_init_path.startswith("/") and len(sbin_init_path) > 0:
            sbin_init_path = "/" + sbin_init_path
        if not sbin_init_link_path.startswith("/") and len(sbin_init_link_path) > 0:
            sbin_init_link_path = "/" + sbin_init_link_path

        return sbin_init_path, sbin_init_link_path

    def analysis_sbin_init(self):
        """Find sbin/init and resolve its symlink target if any."""
        sbin_init_path = ""
        sbin_init_link_path = ""
        potenial_init = ["sbin/init", "usr/sbin/init", "init"]
        for rc_path in potenial_init:
            if os.path.exists(os.path.join(self.fs_path, rc_path)):
                sbin_init_path = rc_path
                break

        if os.path.islink(os.path.join(self.fs_path, sbin_init_path)):
            sbin_init_link_path = get_target_link_path(self.fs_path, sbin_init_path)

        if not sbin_init_path.startswith("/") and len(sbin_init_path) > 0:
            sbin_init_path = "/" + sbin_init_path
        if not sbin_init_link_path.startswith("/") and len(sbin_init_link_path) > 0:
            sbin_init_link_path = "/" + sbin_init_link_path

        return sbin_init_path, sbin_init_link_path

    def get_only_one_rcS(self, rcS):
        """Find the best rcS script path, preferring init.d/ then rc.d/ locations."""
        rcs_list = Files.find_file_paths(os.path.join(self.fs_path, self.etc), rcS)

        if len(rcs_list) == 1:
            return rcs_list[0].replace(self.fs_path, "")
        else:
            for i in rcs_list:
                if "init.d" in i:
                    return i.replace(self.fs_path, "")
            for i in rcs_list:
                if "rc.d" in i:
                    return i.replace(self.fs_path, "")
        return ""

    def get_inittab(self):
        """Find and return the path to the inittab file containing sysinit entries."""
        inittab_list = Files.find_file_paths(self.fs_path, "inittab")
        if len(inittab_list) == 1:
            return inittab_list[0]
        else:
            for file in inittab_list:
                try:
                    with open(file, 'r') as f:
                        for line in f:
                            if "sysinit" in line:
                                return file
                except Exception as e:
                    print("get_inittab", e)

        return None

    def default_entrypoint(self):
        """Set init_binary to the default init path, following Linux kernel search order.

        See https://elixir.bootlin.com/linux/latest/source/init/main.c#L1497
        """

        if os.path.exists(os.path.join(self.fs_path, "sbin/init")):
            self.init_binary = "/sbin/init"
        elif os.path.exists(os.path.join(self.fs_path, "etc/init")):
            self.init_binary = "/etc/init"
        elif os.path.exists(os.path.join(self.fs_path, "bin/init")):
            self.init_binary = "/bin/init"
        else:
            print("not find default_entrypoint")
            print("not find default_entrypoint")
            print("not find default_entrypoint")
            print("not find default_entrypoint")
            print("not find default_entrypoint")


    def identify(self):
        """Identify the firmware's init binary and startup script by analyzing the filesystem."""
        print("=" * 50)
        etc_dir = self.find_etc_dir()
        self.etc = etc_dir

        sbin_init_path, sbin_init_link_path = self.analysis_sbin_init()

        if self.brand == "belkin":
            if os.path.exists(os.path.join(self.fs_path, 'bin', 'init')):
                self.init_binary = "/bin/init"
                return
            if os.path.exists(os.path.join(self.fs_path, 'sbin', 'preinit')):
                self.init_binary = "/sbin/preinit"
                return

        # type1, sbin/init -> bin/busybox
        if len(sbin_init_path) > 0 and "busybox" in sbin_init_link_path:
            self.init_binary = sbin_init_link_path

            # busybox parse /etc/inittab
            inittab = self.get_inittab()
            if inittab:
                init_bash, args = self.parse_inittab(inittab)
                if init_bash:
                    self.init_bash = init_bash
                    self.init_bash_args = args
                    return
                profile = os.path.join(self.fs_path, etc_dir, 'profile')
                if os.path.exists(profile):
                    self.init_bash = os.path.join("/"+etc_dir, 'profile')
                    print("init_bash: ", self.init_bash)
                    return

            # sometime inittab don't exist
            rcS = self.get_only_one_rcS('rcS')
            self.init_bash = rcS
            if rcS and self.brand == 'dlink': # in some case, init -> busybox -> rcS -> sbin/rc
                if os.path.exists(rcS):
                    with open(rcS, 'r') as f:
                        if "noinitrc" in f.read():
                            self.init_bash = "/sbin/rc init" # DIR_866L, our hooked libnvram cause init error
                            return

            if len(self.init_bash) > 0:
                return

            profile = os.path.join(self.fs_path, etc_dir, 'profile')
            if os.path.exists(profile):
                self.init_bash = os.path.join("/"+etc_dir, 'profile')
                return

        # type2, sbin/init and sbin/procd
        procd = os.path.join(self.fs_path, "sbin", "procd")
        if len(sbin_init_path) > 0 and os.path.exists(procd):
            self.init_binary = sbin_init_path
            self.init_binary_procd = procd.replace(self.fs_path, "")
            if os.path.exists(os.path.join(self.fs_path, "etc/init.d/rcS")):
                self.init_bash = "/etc/init.d/rcS"
            else:
                self.init_bash = ""
            return

        # type3, only have sbin/init
        if len(sbin_init_path) > 0 and len(sbin_init_link_path) == 0:

            if is_elf_executable(os.path.join(self.fs_path, get_rel_path(get_rel_path(sbin_init_path)))):
                self.init_binary = sbin_init_path

            inittab = self.get_inittab()
            if inittab:
                init_bash, args = self.parse_inittab(inittab)
                if init_bash:
                    self.init_bash = init_bash
                    self.init_bash_args = args

            if len(self.init_binary) == 0:
                self.init_binary = ""
                profile = os.path.join(self.fs_path, etc_dir, 'profile')
                if os.path.exists(profile):
                    self.init_bash = os.path.join("/" + etc_dir, 'profile')

            if len(self.init_binary) > 0 or len(self.init_bash) > 0:
                return

        # type4, sbin/init -> sbin/rc
        sbin_rc_path, sbin_rc_link_path = self.analysis_sbin_rc() # in almost case, rc have no target link
        if len(sbin_rc_path) > 0 and len(sbin_rc_link_path) == 0: # have sbin/rc and rc not link to other bianry
            self.type = 1
            self.init_binary = sbin_rc_path

            rel_sbin_path = sbin_rc_path.rsplit("/", 1)[0]
            sbin_path = os.path.join(self.fs_path, rel_sbin_path.replace("/", "", 1))
            all_symbolic_links =  get_symbolic_links_in_dir(sbin_path)
            symbolic_links_to_rc = find_keys_by_value(all_symbolic_links, "rc")

            # TODO: maybe has other case, use code analysis
            init_order = ["preinit", "rcd", "rcS", "init"]
            for init_type in init_order:
                for symbol_link in symbolic_links_to_rc:
                    if init_type in symbol_link:
                        self.init_binary_for_rc = os.path.join(rel_sbin_path, init_type)
                        return

            return

        if len(sbin_init_path) > 0 and len(sbin_init_link_path) > 0: # /dlink/DIR_825AC_G1A_KOREA_1.0.0KRb02.bin, init -> dcfg
            self.init_binary = sbin_init_link_path