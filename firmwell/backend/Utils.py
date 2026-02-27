import os, stat
import shutil
import subprocess
import hashlib
import pathlib
import time

BACKUP_TAGS = ["bak", "bak2", "bkup"]


def incremental_copy(src, dst):
    cmd = f'rsync -av --ignore-existing "{src}/" "{dst}/"'
    print(cmd)
    # stdout = subprocess.run(cmd, shell=True, cwd=self.tmp_fs_path, text=True, capture_output=True).stdout
    stdout = subprocess.run(cmd, shell=True, text=True, capture_output=True).stdout
    print(stdout)
    
def binary_containt_strings(binary_path, string):
    res = subprocess.run(
        f"/bin/bash -c 'strings {binary_path} | grep {string}'", shell=True)
    if res.returncode == 0:
        return True
    else:
        return False
    
def get_tracelog_dict(directory):
    """
     trace.log* ， tracelog_dict。

    Args:
        directory (str): 。

    Returns:
        dict: tracelog_dict，key （"1", "2", "3", ...），value  trace （list）。
    """
    tracelog_dict = {}
    for i in range(0, 100):
        path = os.path.join(directory, f"trace.log{i}")
        if i == 0 and not os.path.exists(path):
            path = os.path.join(directory, "trace.log")
        if os.path.exists(path):
            tracelog_dict[str(i)] = open(path, "r", encoding="utf-8", errors="ignore").readlines()
    return tracelog_dict

def find_files(filename, fs_path, include_backups=False, resolve_symlinks=True, skip=[]):
    """
     filename 。

    Args:
        filename (str): （）。
        fs_path (str): 。
        include_backups (bool): 。
        resolve_symlinks (bool): 。
        skip (list): 。

    Returns:
        list: 。
    """
    found = []
    for root, dirs, files in os.walk(fs_path):
        for f in files:
            # if filename in f:
            if filename == f: # full match
                file_path = os.path.join(root, f)
                if os.path.dirname(file_path) == fs_path:
                    continue
                if os.path.islink(file_path):
                    if resolve_symlinks:
                        file_path = str(pathlib.Path(file_path).resolve())
                    if not file_path.startswith(fs_path):
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
                    if f.lower().endswith(filename.lower() + "." + tag):
                        file_path = os.path.join(root, f)
                        if os.path.dirname(file_path) == fs_path:
                            continue
                        if os.path.islink(file_path):
                            if resolve_symlinks:
                                file_path = str(pathlib.Path(file_path).resolve())
                            if not file_path.startswith(fs_path):
                                while file_path.startswith("/") or file_path.endswith("/"):
                                    file_path = file_path.strip("/")
                                file_path = os.path.join(fs_path, file_path)
                        if file_path in skip or file_path in found:
                            continue
                        if not os.path.exists(file_path):
                            continue
                        found.append(file_path)
    return found

class Files():
    @staticmethod
    def chmod_exe(path:str):
        org_mode = os.stat(path)
        os.chmod(path, org_mode.st_mode | stat.S_IXUSR)

    @staticmethod
    def mkdir(path:str, root="/", silent=False):
        recursive_dirs = []
        if os.path.exists(path):
            Files.rm_target(path, silent)
        while len(path) > 0 and not os.path.exists(path):
            if not silent:
                print("    - **", path)
            if os.path.islink(path):
                # path = os.path.realpath(path)
                oldpath = path
                path = str(pathlib.Path(path).resolve())
                if not path.startswith(root):
                    Files.rm_target(oldpath)
                    path = oldpath
            else:
                recursive_dirs.append(path)
                path = os.path.dirname(path)
        if not silent:
            print("Recursive Dirs:")
            print("     - ", recursive_dirs)
        try:
            for dirs in recursive_dirs[::-1]: #iterate from lowest dir
                if not silent:
                    print("    - Making directory", dirs)
                prev_dir = os.path.dirname(dirs)
                if os.path.exists(prev_dir) and not os.path.isdir(prev_dir):
                    if not silent:
                        print("      - Changing file into directory", prev_dir)
                    Files.rm_file(prev_dir)
                    os.mkdir(prev_dir)
                os.mkdir(dirs)
        except Exception as e:
            print(e)

    @staticmethod
    def touch_file(path, root="/", silent=False):
        try:
            basedir = os.path.dirname(path)
            if not os.path.exists(basedir) or not os.path.isdir(basedir):
                Files.mkdir(basedir, root=root)
            if not os.path.exists(path):
                if not silent:
                    print("    - Touching file", path)
                os.mknod(path)
        except Exception as e:
            print(e)

    @staticmethod
    def write_file(path, value, root="/", silent=False):
        if not silent:
            print("    - Writing file %s with value %s" % (path, value))
        try:
            if not os.path.exists(path):
                Files.touch_file(path)
            with open(path, "w") as wfile:
                wfile.write(value)
            wfile.close()
        except Exception as e:
            print(e)

    @staticmethod
    def rm_target(path, silent=False):
        if os.path.isdir(path) and not os.path.islink(path):
            Files.rm_folder(path, silent)
        else:
            Files.rm_file(path, silent)

    @staticmethod
    def rm_files(pathlist, silent=False):
        for path in pathlist:
            Files.rm_file(path, silent)

    @staticmethod
    def rm_file(path, silent=False):
        if os.path.isdir(path) and not os.path.islink(path):
            print("    - Is a Directory, skipping", path)
            return
        if os.path.exists(path):
            if not silent:
                print("    - Deleting file", path)
            os.remove(path)
        elif os.path.islink(path):
            if not silent:
                print("    - Unlinking file", path)
            os.unlink(path)

    @staticmethod
    def rm_folder(path, ignore_errors=False, silent=False):
        retry = 0
        if os.path.exists(path):
            if not silent:
                print("    - Recursively deleting folder", path)
            while retry < 3:
                try:
                    shutil.rmtree(path, ignore_errors=ignore_errors)
                    break
                except OSError as e:
                    print(e)
                    time.sleep(1)
                    retry += 1
                    continue
        else:
            print("    - Folder path not found:", path)

    @staticmethod
    def mk_link(linkpath, linktarget, relative_dir="."):
        fullpath = os.path.join(relative_dir, linktarget)
        if linkpath == fullpath:
            print("    - not creating symlink that points to itself. Skip")
            return
        current_dir = os.getcwd()
        os.chdir(relative_dir)
        Files.rm_file(linkpath)
        os.symlink(linktarget, linkpath)
        os.chdir(current_dir)

    @staticmethod
    def find_file_paths(folder, target):
        paths = []
        for root, dirs, files in os.walk(folder):
            for f in files:
                if target == f:
                    path = os.path.join(root, f)
                    paths.append(path)
        return paths

    @staticmethod
    def copy_overwrite_dir_contents(src, dest):
        if not os.path.exists(src):
            print("src", src, "does not exist")
            return
        if not os.path.isdir(src):
            print("src", src, "is not a directory")
            return
        if not os.path.exists(dest):
            print("dest", dest, "does not exist")
            return
        if not os.path.isdir(dest):
            print("dest", dest, "is not a directory")
            return
        for f in os.listdir(src):
            path = os.path.join(src, f)
            print("     - copying %s" % (path))
            subprocess.call(["cp", "-r", path, dest])

    @staticmethod
    def copy_directory(src, dest, via_cp=False):
        if os.path.exists(dest): # qc add
            Files.rm_folder(dest)
        if via_cp:
            subprocess.run(["cp", "-r", "-R", src, dest])
        else:
            shutil.copytree(src, dest, symlinks=True)

    @staticmethod
    def copy_file(src, dest, silent=False):
        st_mode = 0
        if os.path.exists(src):
            st_mode = os.stat(src).st_mode
        if os.path.exists(dest):
            Files.rm_file(dest, silent=True)
        if not silent:
            print("    - Copying file", src, "to", dest)
        shutil.copyfile(src, dest)
        os.chmod(dest, st_mode | stat.S_IXUSR)

    @staticmethod
    def get_all_files(folder):
        paths = []
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f not in paths:
                    path = os.path.join(root, f)
                    paths.append(path)
        return paths

    @staticmethod
    def hash_file(path):
        result = None
        if not os.path.exists(path):
            print("    - error, file does not exist!")
            return result
        with open(path,"rb") as hashfile:
            fbytes = hashfile.read()
            result = hashlib.sha256(fbytes).hexdigest()
        return result
