import os
import logging
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

class FileSystem:
    def __init__(self, fs_path):
        self.path = fs_path
        self.fs_path = Path(fs_path)
        self.dir_list = [str(i) for i in self.fs_path.iterdir()] # ori dir list

        self.symbol2file_dict = {}
        self.file2symbol_dict = defaultdict(list)

        executeable_files = self.traverse_file()
        self.elf_files = executeable_files['elf']
        self.bash_files = executeable_files['sh']
        self.executeable_files = executeable_files['elf'] + executeable_files['sh']

    @property
    def all_filenames(self):
        return {file.name for file in self.fs_path.rglob('*') if file.is_file()}

    @property
    def all_filepath(self):
        return [str(file.relative_to(self.fs_path)) for file in self.fs_path.rglob('*') if file.is_file()]

    def file_in_filesystem(self, f):
        """
        input: httpd
        return: if httpd is a filename in FS (e.g. /sbin/httpd), return True
        """
        return f in self.all_filenames

    def filepath_exist_in_filesystem(self, path, abs_path=False):
        """
        input: /sbin/httpd or sbin/httpd
        return: if /sbin/httpd in FS, return True
        """
        rel_path = self.get_rel_path(path)
        return (self.fs_path / Path(rel_path)).exists()

    def get_exe_path_by_name(self, name):
        """
        input: xmldb
        return: /usr/sbin/xmldb
        """
        for bin_dir in self.fs_path.rglob('*'):
            if bin_dir.name in {'bin', 'sbin'} and bin_dir.is_dir(): # # TODO, change to FS executeable
                for file in bin_dir.iterdir():
                    if file.is_file() and file.name == name:
                        return str(file.relative_to(self.fs_path))
        return ""

    def get_rel_path(self, path):
        """
        input: any file path
        output: rel file path in original firmware fs.
        e.g. /sbin/httpd -> sbin/httpd
        e.g. /tmp/extracted_firmware/sbin/httpd -> sbin/httpd
        """

        path = Path(path)

        if path.is_absolute() and path.exists() and self.path in str(path):
            return str(path.relative_to(self.fs_path))
        else:
            return str(path).lstrip('/')

    def get_abs_path(self, path):
        """
        input: any file path
        output: abs file path in original firmware fs.
        e.g. sbin/httpd -> /sbin/httpd
        e.g. /tmp/extracted_firmware/sbin/httpd -> /sbin/httpd
        """
        # logger.debug(f"get_abs_path: {path}")

        # 
        if os.path.basename(path) == path:
            path = self.get_exe_path_by_name(path)

        path = Path(path)

        original_cwd = Path.cwd()
        os.chdir(self.path)
        try:
        # 
            if path.is_absolute():
                if path.exists():  # host
                    return str(path).replace(str(self.fs_path), '')
                else:
                    return str(path)

            else:
                return f"/{str(path)}"
        finally:
            os.chdir(original_cwd)

    def get_full_path(self, sub_path):
        """
        input: any file path
        output: fs_path + rel file path in host fs.
        e.g. /sbin/httpd -> /tmp/extracted_firmware/sbin/httpd
        e.g. /tmp/extracted_firmware/sbin/httpd -> /tmp/extracted_firmware/sbin/httpd
        """
        # logger.debug(f"get_full_path: {sub_path}")
        
        if len(sub_path) == 0:
            return None
        
        sub_path = Path(sub_path)
        if sub_path.is_absolute(): # 
            if sub_path.exists() and self.path in str(sub_path):  # host
                return str(sub_path)

            full_path = self.fs_path / sub_path.relative_to('/')  # 
            if full_path.exists():
                return str(full_path)

            # sym link
            full_path = self.fs_path / self.get_rel_path(sub_path)
            if full_path.is_symlink():
                return str(full_path)

        # 
        full_path = self.fs_path / sub_path
        if full_path.exists():
            return str(full_path)

        # ，
        file_abs_path  = self.get_exe_path_by_name(sub_path.name)
        if len(file_abs_path) > 0:
            file_path = self.fs_path / self.get_rel_path(file_abs_path)
            if file_path.exists():
                return str(self.fs_path / file_path)

        # logger.error(f"get_full_path: {sub_path} not found")
        return None

    def get_symlink_by_file(self, file):
        return self.file2symbol_dict.get(file, [])

    def get_file_by_symlink(self, symlink):
        return self.symbol2file_dict.get(symlink, "")

    def path_has_symlink(self, path):
        return path in self.symbol2file_dict.values()
    
    def is_dir(self, path):
        # return Path(path).is_dir()
        return os.path.basename(path) == "" or path.endswith('/')
    
    def exist_dir(self, path):
        return os.path.isdir(self.get_full_path(path))
    
    @staticmethod
    def fetch_file(filepath, suffix_list):
        file = Path(filepath)
        if not file.exists():
            return False
        if suffix_list == ['elf']:
            try:
                if not file.is_file() or file.is_symlink():
                    return False
                with file.open('rb') as f:
                    header = f.read(4)[1:4].decode("utf-8")
                    if header == "ELF":
                        return True
            except:
                pass
        elif suffix_list == ['sh']:
            try:
                if file.suffix.lower() == '.sh':
                    if not file.is_file() or file.is_symlink():
                        return False
                    with file.open('rb') as f:
                        header = f.read(4)[1:4].decode("utf-8")
                        if header == "ELF":
                            return False
                    return True
                else:
                    if not file.is_file() or file.is_symlink():
                        return False
                    with file.open('rb') as f:
                        header = f.read(11).decode("utf-8")
                        if header.startswith("#!/bin/sh") or header.startswith("#!/bin/bash"):
                            return True
            except:
                pass
        else:
            if file.suffix.lower() in suffix_list:
                return True
        return False

    def traverse_file(self):
        path = self.fs_path
        files = {'sh': [], 'elf': []}
        black_dir_prefix = ["dev", "lib", "usr/lib", "usr/local/lib"]
        black_file_suffix = [".so", "ko"]

        for file in path.rglob('*'):
            # ，symbol2file_dict
            if file.is_symlink():
                try:
                    target_file = str(file.resolve())
                except RuntimeError: # /sbin/bin -> bin
                    continue
                if file.exists():
                    if self.path not in target_file:
                        target_file = os.path.join(self.path, self.get_rel_path(target_file))
                    self.symbol2file_dict[str(file)] = target_file # link -> target
                    self.file2symbol_dict[target_file].append(str(file)) # target -> link
                else: # TODO: try to handle multi-level symlink. hard code. AC2100_V1.2.0.62_1.0.1
                    if "rc_app" in str(file):
                        rc_apps = os.path.join(self.path, "usr/sbin/rc_app/rc_apps")
                        self.symbol2file_dict[str(file)] = rc_apps  # link -> target
                        self.file2symbol_dict[rc_apps].append(str(file))  # target -> link

            if not any(str(file).startswith(d) for d in self.dir_list): # artifact file
                continue
            if any(str(file).startswith(str(path / prefix)) for prefix in black_dir_prefix):
                continue
            if any(file.suffix == suffix for suffix in black_file_suffix):
                continue
            if file.is_symlink():
                continue
            if file.is_file():
                # Check if file is in etc or etc_ro directory, some bash file not ends with .sh
                file_str = str(file)
                if "/etc/" in file_str or "/etc_ro/" in file_str or "/bin" in file_str or "/sbin" in file_str:
                    try:
                        with open(file, 'r') as f:
                            first_line = f.readline().strip()
                            if first_line.startswith("#!/bin/sh") or first_line.startswith("#!/bin/bash"):
                                files['sh'].append(str(file))
                                continue
                    except:
                        pass

                if FileSystem.fetch_file(file, ["sh"]):
                    files['sh'].append(str(file))
                elif FileSystem.fetch_file(file, ["elf"]):
                    files['elf'].append(str(file))
                    
            if os.path.basename(str(file)) == "profile":
                files['sh'].append(str(file))

        return files
