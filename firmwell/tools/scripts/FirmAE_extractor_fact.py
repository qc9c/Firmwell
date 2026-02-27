#!/usr/bin/env python3
"""
Module that performs extraction. For usage, refer to documentation for the class
'Extractor'. This module can also be executed directly,
e.g. 'extractor.py <input> <output>'.
"""

import argparse
import hashlib
import multiprocessing
import os
import shutil
import subprocess
import tempfile
import traceback
import pathlib

import magic
import binwalk


class Extractor(object):
    """
    Class that extracts kernels and filesystems from firmware images, given an
    input file or directory and output directory.
    """
    
    # UNIX filesystem root directory markers and detection threshold
    UNIX_DIRS = ["bin", "etc", "dev", "home", "lib", "mnt", "opt", "root",
                 "run", "sbin", "tmp", "usr", "var"]
    UNIX_THRESHOLD = 4
    
    # Lock to prevent concurrent access
    visited_lock = multiprocessing.Lock()
    
    def __init__(self, indir, outdir=None, rootfs=True, kernel=True,
                 numproc=True, server=None, brand=None, debug=False, fact=False, scripts_path=None):
        self._input = os.path.abspath(indir)
        self.output_dir = os.path.abspath(outdir) if outdir else None
        
        # Extraction flags for kernel and rootfs
        self.do_kernel = kernel
        self.kernel_done = False
        self.do_rootfs = rootfs
        self.rootfs_done = False
        
        self.brand = brand
        self.database = server
        self.debug = debug
        
        self._pool = multiprocessing.Pool() if numproc else None
        self.visited = dict()
        self._list = list()
        
        # When enabled, use fact_extractor logic for firmware unpacking
        self.fact = fact
        
        if os.path.exists("fact_extractor_wrapper.py"):
            self.scripts_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fact_extractor_wrapper.py")
        else:
            self.scripts_path = "/fw/firmwell/tools/scripts/fact_extractor_wrapper.py"
            

    def __getstate__(self):
        self_dict = self.__dict__.copy()
        del self_dict["_pool"]
        del self_dict["_list"]
        return self_dict
    
    @staticmethod
    def io_dd(indir, offset, size, outdir):
        if not size:
            return
        with open(indir, "rb") as ifp:
            with open(outdir, "wb") as ofp:
                ifp.seek(offset, 0)
                ofp.write(ifp.read(size))
    
    @staticmethod
    def magic(indata, mime=False):
        try:
            if mime:
                mymagic = magic.open(magic.MAGIC_MIME_TYPE)
            else:
                mymagic = magic.open(magic.MAGIC_NONE)
            mymagic.load()
        except AttributeError:
            mymagic = magic.Magic(mime)
            mymagic.file = mymagic.from_file
        try:
            return mymagic.file(indata)
        except magic.MagicException:
            return None
    
    @staticmethod
    def io_md5(target):
        blocksize = 65536
        hasher = hashlib.md5()
        with open(target, 'rb') as ifp:
            buf = ifp.read(blocksize)
            while buf:
                hasher.update(buf)
                buf = ifp.read(blocksize)
            return hasher.hexdigest()
    
    @staticmethod
    def io_rm(target):
        shutil.rmtree(target, ignore_errors=True, onerror=Extractor._io_err)
    
    @staticmethod
    def _io_err(function, path, excinfo):
        print(("!! %s: Cannot delete %s!\n%s" % (function, path, excinfo)))
    
    @staticmethod
    def io_find_rootfs(start, recurse=True):
        # Traverse single-child directory chains (e.g. jffs2-root/fs_1/...)
        path = start
        while (len(os.listdir(path)) == 1 and
               os.path.isdir(os.path.join(path, os.listdir(path)[0]))):
            path = os.path.join(path, os.listdir(path)[0])
        # Count UNIX-style directories
        count = 0
        for subdir in os.listdir(path):
            if subdir in Extractor.UNIX_DIRS and \
                    os.path.isdir(os.path.join(path, subdir)) and \
                    len(os.listdir(os.path.join(path, subdir))) > 0:
                count += 1
        if count >= Extractor.UNIX_THRESHOLD:
            return (True, path)
        # Recurse into subdirectories if threshold not met
        if recurse:
            for subdir in os.listdir(path):
                if os.path.isdir(os.path.join(path, subdir)):
                    res = Extractor.io_find_rootfs(os.path.join(path, subdir), True)
                    if res[0]:
                        return res
        return (False, start)
    
    def extract(self):
        if os.path.isdir(self._input):
            for path, _, files in os.walk(self._input):
                for item in files:
                    self._list.append(os.path.join(path, item))
        elif os.path.isfile(self._input):
            self._list.append(self._input)
        if self.output_dir and not os.path.isdir(self.output_dir):
            os.makedirs(self.output_dir)
        if self._pool:
            chunk_size = 1
            list(self._pool.imap_unordered(self._extract_item, self._list, chunk_size))
        else:
            for item in self._list:
                self._extract_item(item)
    
    def _extract_item(self, path):
        ExtractionItem(self, path, 0, None, self.debug).extract()


class ExtractionItem(object):
    RECURSION_BREADTH = 10
    RECURSION_DEPTH = 3
    database = None
    
    def __init__(self, extractor, path, depth, tag=None, debug=False):
        self.temp = None
        self.depth = depth
        self.extractor = extractor
        self.item = path
        self.debug = debug
        if self.extractor.database:
            import psycopg2
            self.database = psycopg2.connect(database="firmware",
                                             user="firmadyne",
                                             password="firmadyne",
                                             host=self.extractor.database)
        self.checksum = Extractor.io_md5(path)
        self.tag = tag if tag else self.generate_tag()
        self.output = os.path.join(self.extractor.output_dir, self.tag) if self.extractor.output_dir else None
        self.terminate = False
        self.status = None
        self.update_status()
    
    def __del__(self):
        if self.database:
            self.database.close()
        if self.temp:
            self.printf(">> Cleaning up %s..." % self.temp)
            Extractor.io_rm(self.temp)
    
    def printf(self, fmt):
        if self.debug:
            print(("\t" * self.depth + fmt))
        pass
    
    def generate_tag(self):
        if not self.database:
            return os.path.basename(self.item) + "_" + self.checksum
        try:
            image_id = None
            cur = self.database.cursor()
            if self.extractor.brand:
                brand = self.extractor.brand
            else:
                brand = os.path.relpath(self.item).split(os.path.sep)[0]
            cur.execute("SELECT id FROM brand WHERE name=%s", (brand,))
            brand_id = cur.fetchone()
            if not brand_id:
                cur.execute("INSERT INTO brand (name) VALUES (%s) RETURNING id", (brand,))
                brand_id = cur.fetchone()
            if brand_id:
                cur.execute("SELECT id FROM image WHERE hash=%s", (self.checksum,))
                image_id = cur.fetchone()
                if not image_id:
                    cur.execute("INSERT INTO image (filename, brand_id, hash) VALUES (%s, %s, %s) RETURNING id",
                                (os.path.basename(self.item), brand_id[0], self.checksum))
                    image_id = cur.fetchone()
            self.database.commit()
        except BaseException:
            traceback.print_exc()
            self.database.rollback()
        finally:
            if cur:
                cur.close()
        if image_id:
            self.printf(">> Database Image ID: %s" % image_id[0])
        return str(image_id[0]) if image_id else os.path.basename(self.item) + "_" + self.checksum
    
    def get_kernel_status(self):
        return self.extractor.kernel_done
    
    def get_rootfs_status(self):
        return self.extractor.rootfs_done
    
    def update_status(self):
        kernel_done = os.path.isfile(
            self.get_kernel_path()) if self.extractor.do_kernel and self.output else not self.extractor.do_kernel
        rootfs_done = os.path.isfile(
            self.get_rootfs_path()) if self.extractor.do_rootfs and self.output else not self.extractor.do_rootfs
        self.status = (kernel_done, rootfs_done)
        self.extractor.kernel_done = kernel_done
        self.extractor.rootfs_done = rootfs_done
        if self.database and kernel_done and self.extractor.do_kernel:
            self.update_database("kernel_extracted", "True")
        if self.database and rootfs_done and self.extractor.do_rootfs:
            self.update_database("rootfs_extracted", "True")
        return self.get_status()
    
    def update_database(self, field, value):
        ret = True
        if self.database:
            try:
                cur = self.database.cursor()
                cur.execute("UPDATE image SET " + field + "='" + value + "' WHERE id=%s", (self.tag,))
                self.database.commit()
            except BaseException:
                ret = False
                traceback.print_exc()
                self.database.rollback()
            finally:
                if cur:
                    cur.close()
        return ret
    
    def get_status(self):
        return True if self.terminate or all(i for i in self.status) else False
    
    def get_kernel_path(self):
        return self.output + ".kernel" if self.output else None
    
    def get_rootfs_path(self):
        return self.output + ".tar.gz" if self.output else None
    
    def extract(self):
        self.printf("\n" + self.item.encode("utf-8", "replace").decode("utf-8"))
        if self.get_status():
            self.printf(">> Skipping: completed!")
            return True
        if self.depth > ExtractionItem.RECURSION_DEPTH:
            self.printf(">> Skipping: recursion depth %d" % self.depth)
            return self.get_status()
        self.printf(">> MD5: %s" % self.checksum)
        with Extractor.visited_lock:
            if (self.checksum in self.extractor.visited and
                    self.extractor.visited[self.checksum] == self.status):
                self.printf(">> Skipping: %s..." % self.checksum)
                return self.get_status()
            else:
                self.extractor.visited[self.checksum] = self.status
        if self._check_blacklist():
            return self.get_status()
        
        # In fact mode at top level (depth==0), use fact_extractor for unpacking
        if self.extractor.fact and self.depth == 0:
            extracted_dir = self.unpack_by_fact_extractor(self.item)
            if os.path.isdir(extracted_dir):
                unix = Extractor.io_find_rootfs(extracted_dir)
                if unix[0]:
                    self.printf(">>>> Found Linux filesystem in %s!" % unix[1])
                    if self.output:
                        print(">>>> Making archive to %s" % self.output)
                        shutil.make_archive(self.output, "gztar", root_dir=unix[1])
                    else:
                        self.extractor.do_rootfs = False
                    return True
                else:
                    self.printf(">>>> Failed to identify rootfs in fact extraction result")
                    return False
            else:
                self.printf(">>>> Fact extraction did not produce a valid directory")
                return False
        
        # Non-fact mode or recursive depth: use binwalk scanning
        self.temp = tempfile.mkdtemp()
        os.chdir(self.temp)
        try:
            self.printf(">> Tag: %s" % self.tag)
            self.printf(">> Temp: %s" % self.temp)
            self.printf(">> Status: Kernel: %s, Rootfs: %s, Do_Kernel: %s, Do_Rootfs: %s" % (
                self.get_kernel_status(), self.get_rootfs_status(),
                self.extractor.do_kernel, self.extractor.do_rootfs))

            binwalk_args = ["--run-as=root", "--preserve-symlinks", "-e", "-r", "-C", self.temp]
            for module in binwalk.scan(self.item, *binwalk_args, signature=True, quiet=True):
                prev_entry = None
                for entry in module.results:
                    desc = entry.description
                    dir_name = module.extractor.directory
                    if prev_entry and prev_entry.description == desc and 'Zlib comparessed data' in desc:
                        continue
                    prev_entry = entry
                    self.printf('========== Depth: %d ================' % self.depth)
                    self.printf("Name: %s" % self.item)
                    self.printf("Desc: %s" % desc)
                    self.printf("Directory: %s" % dir_name)
                    self._check_firmware(module, entry)
                    if not self.get_rootfs_status():
                        self._check_rootfs(module, entry)
                    if not self.get_kernel_status():
                        self._check_kernel(module, entry)
                    if self.update_status():
                        self.printf(">> Skipping: completed!")
                        return True
                    else:
                        if not self.extractor.fact:
                            self._check_recursive(module, entry)
        except Exception:
            print("ERROR: ", self.item)
            traceback.print_exc()
        return False
    
    def unpack_by_fact_extractor(self, img_path):
        """Invoke fact_extractor_wrapper to unpack firmware and return the output directory."""
        self.printf("try to unpack by fact_extractor")
        # Use a fixed extraction directory
        extracted_path = "/tmp/fact_extracted"
        if os.path.exists(extracted_path):
            shutil.rmtree(extracted_path)
        fact_extract_script = self.extractor.scripts_path
        fact_cmd = f'python {fact_extract_script} -e -r "{img_path}" {extracted_path}'
        self.printf("    - Running fact cmd: " + fact_cmd)
        
        if "POD_NAME" in os.environ.keys():
            os.environ['DOCKER_HOST'] = 'tcp://127.0.0.1:2375'
            print("DOCKER_HOST set to tcp://127.0.0.1:2375")
        
        result = subprocess.run(fact_cmd, shell=True, capture_output=True, text=True)
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)
        self.printf("    - Done")
        return extracted_path
    
    def _check_blacklist(self):
        real_path = os.path.realpath(self.item)
        filetype = Extractor.magic(real_path.encode("utf-8", "surrogateescape"), mime=True)
        if filetype:
            if any(s in filetype for s in ["application/x-executable",
                                           "application/x-dosexec",
                                           "application/x-object",
                                           "application/x-sharedlib",
                                           "application/pdf",
                                           "application/msword",
                                           "image/", "text/", "video/"]):
                self.printf(">> Skipping: %s..." % filetype)
                return True
        filetype = Extractor.magic(real_path.encode("utf-8", "surrogateescape"))
        if filetype:
            if any(s in filetype for s in ["executable", "universal binary",
                                           "relocatable", "bytecode", "applet",
                                           "shared"]):
                self.printf(">> Skipping: %s..." % filetype)
                return True
        black_lists = ['.dmg', '.so', '.so.0']
        for black in black_lists:
            if self.item.endswith(black):
                self.printf(">> Skipping: %s..." % (self.item))
                return True
        return False
    
    def _check_firmware(self, module, entry):
        dir_name = module.extractor.directory
        desc = entry.description
        if 'header' in desc:
            if "uImage header" in desc:
                if not self.get_kernel_status() and "OS Kernel Image" in desc:
                    kernel_offset = entry.offset + 64
                    kernel_size = 0
                    for stmt in desc.split(','):
                        if "image size:" in stmt:
                            kernel_size = int(''.join(i for i in stmt if i.isdigit()), 10)
                    if kernel_size != 0 and kernel_offset + kernel_size <= os.path.getsize(self.item):
                        self.printf(">>>> %s" % desc)
                        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                        os.close(tmp_fd)
                        Extractor.io_dd(self.item, kernel_offset, kernel_size, tmp_path)
                        kernel = ExtractionItem(self.extractor, tmp_path, self.depth, self.tag, self.debug)
                        return kernel.extract()
            elif not self.get_kernel_status() and not self.get_rootfs_status() and "rootfs offset: " in desc and "kernel offset: " in desc:
                image_size = os.path.getsize(self.item)
                header_size = 0
                kernel_offset = 0
                kernel_size = 0
                rootfs_offset = 0
                rootfs_size = 0
                for stmt in desc.split(','):
                    if "header size" in stmt:
                        header_size = int(stmt.split(':')[1].split()[0])
                    elif "kernel offset:" in stmt:
                        kernel_offset = int(stmt.split(':')[1], 16)
                    elif "kernel length:" in stmt:
                        kernel_size = int(stmt.split(':')[1], 16)
                    elif "rootfs offset:" in stmt:
                        rootfs_offset = int(stmt.split(':')[1], 16)
                    elif "rootfs length:" in stmt:
                        rootfs_size = int(stmt.split(':')[1], 16)
                kernel_offset += entry.offset
                rootfs_offset += entry.offset + header_size
                if rootfs_offset < kernel_offset:
                    if rootfs_size == 0:
                        rootfs_size = kernel_offset - rootfs_offset
                    if kernel_size == 0:
                        kernel_size = image_size - kernel_offset
                elif rootfs_offset > kernel_offset:
                    if kernel_size == 0:
                        kernel_size = rootfs_offset - kernel_offset
                    if rootfs_size == 0:
                        rootfs_size = image_size - rootfs_offset
                self.printf('image size: %d' % image_size)
                self.printf('rootfs offset: %d' % rootfs_offset)
                self.printf('rootfs size: %d' % rootfs_size)
                self.printf('kernel offset: %d' % kernel_offset)
                self.printf('kernel size: %d' % kernel_size)
                if kernel_size > 0 and rootfs_size > 0 and kernel_offset + kernel_size <= image_size and rootfs_offset + rootfs_size <= image_size:
                    self.printf(">>>> %s" % desc)
                    tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                    os.close(tmp_fd)
                    Extractor.io_dd(self.item, kernel_offset, kernel_size, tmp_path)
                    kernel = ExtractionItem(self.extractor, tmp_path, self.depth, self.tag, self.debug)
                    kernel.extract()
                    tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                    os.close(tmp_fd)
                    Extractor.io_dd(self.item, rootfs_offset, rootfs_size, tmp_path)
                    rootfs = ExtractionItem(self.extractor, tmp_path, self.depth, self.tag, self.debug)
                    rootfs.extract()
                    return True
        return False
    
    def _check_kernel(self, module, entry):
        dir_name = module.extractor.directory
        desc = entry.description
        if 'kernel' in desc:
            if self.get_kernel_status():
                return True
            else:
                if "kernel version" in desc:
                    self.update_database("kernel_version", desc)
                    if "Linux" in desc:
                        if self.get_kernel_path():
                            shutil.copy(self.item, self.get_kernel_path())
                        else:
                            self.extractor.do_kernel = False
                        self.printf(">>>> %s" % desc)
                        return True
                    else:
                        self.printf(">>>> Ignoring: %s" % desc)
        return False
    
    def _check_rootfs(self, module, entry):
        """Check if the entry is a rootfs based on filesystem/archive/compressed keywords."""
        dir_name = module.extractor.directory
        desc = entry.description
        print("check_rootfs", dir_name)
        if 'filesystem' in desc or 'archive' in desc or 'compressed' in desc:
            if self.get_rootfs_status():
                return True
            else:
                if dir_name:
                    unix = Extractor.io_find_rootfs(dir_name)
                    if not unix[0]:
                        self.printf(">>>> Extraction failed!")
                        return False
                    self.printf(">>>> Found Linux filesystem in %s!" % unix[1])
                    if self.output:
                        shutil.make_archive(self.output, "gztar", root_dir=unix[1])
                    else:
                        self.extractor.do_rootfs = False
                    return True
        return False
    
    def _fact_check_rootfs(self, module, entry):
        """In fact mode, bypass description keywords and directly search for rootfs via io_find_rootfs."""
        dir_name = module.extractor.directory
        if self.get_rootfs_status():
            return True
        if dir_name:
            unix = Extractor.io_find_rootfs(dir_name)
            if not unix[0]:
                self.printf(">>>> Extraction failed!")
                return False
            self.printf(">>>> Found Linux filesystem in %s!" % unix[1])
            if self.output:
                shutil.make_archive(self.output, "gztar", root_dir=unix[1])
            else:
                self.extractor.do_rootfs = False
            return True
        return False
    
    def _check_recursive(self, module, entry):
        """Recursively extract nested archives (non-fact mode only)."""
        dir_name = module.extractor.directory
        desc = entry.description
        if 'filesystem' in desc or 'archive' in desc or 'compressed' in desc:
            if dir_name:
                self.printf(">> Recursing into %s ..." % desc)
                count = 0
                for root, dirs, files in os.walk(dir_name):
                    dirs.sort()
                    dirs.sort(key=lambda x: ("root" in x, x), reverse=True)
                    files.sort()
                    files.sort(key=len)
                    if (not self.extractor.do_rootfs or self.get_rootfs_status()) and 'bin' in dirs and 'lib' in dirs:
                        break
                    if desc and "original file name:" in desc:
                        orig = None
                        for stmt in desc.split(","):
                            if "original file name:" in stmt:
                                orig = stmt.split("\"")[1]
                        if orig and orig in files:
                            files.remove(orig)
                            files.insert(0, orig)
                    for filename in files:
                        path = os.path.join(root, filename)
                        if not pathlib.Path(path).is_file():
                            continue
                        new_item = ExtractionItem(self.extractor, path, self.depth + 1, self.tag, self.debug)
                        if new_item.extract():
                            if self.update_status():
                                return True
                        count += 1
        return False


def psql_check(psql_ip):
    try:
        import psycopg2
        psycopg2.connect(database="firmware",
                         user="firmadyne",
                         password="firmadyne",
                         host=psql_ip)
        return True
    except Exception as e:
        print(e)
        return False


def main():
    parser = argparse.ArgumentParser(description="Extracts filesystem and kernel from Linux-based firmware images")
    parser.add_argument("input", action="store", help="Input file or directory")
    parser.add_argument("output", action="store", nargs="?", default="images",
                        help="Output directory for extracted firmware")
    parser.add_argument("-sql", dest="sql", action="store", default=None,
                        help="Hostname of SQL server")
    parser.add_argument("-nf", dest="rootfs", action="store_false", default=True,
                        help="Disable extraction of root filesystem (may decrease extraction time)")
    parser.add_argument("-nk", dest="kernel", action="store_false", default=True,
                        help="Disable extraction of kernel (may decrease extraction time)")
    parser.add_argument("-np", dest="parallel", action="store_false", default=True,
                        help="Disable parallel operation (may increase extraction time)")
    parser.add_argument("-b", dest="brand", action="store", default=None,
                        help="Brand of the firmware image")
    parser.add_argument("-d", dest="debug", action="store_true", default=False,
                        help="Print debug information")
    parser.add_argument("--fact", dest="fact", action="store_true", default=False,
                        help="Enable fact mode: use fact_extractor for firmware unpacking and rootfs identification")
    parser.add_argument("--scripts-path", dest="scripts_path", action="store", default=None,
                        help="Path to fact_extractor_wrapper script")
    result = parser.parse_args()
    
    if psql_check(result.sql):
        extract = Extractor(result.input, result.output, result.rootfs, result.kernel,
                            result.parallel, result.sql, result.brand, result.debug,
                            fact=result.fact, scripts_path=result.scripts_path)
        extract.extract()
    else:
        print("ERROR: Unable to connect to the database server!")


if __name__ == "__main__":
    main()
