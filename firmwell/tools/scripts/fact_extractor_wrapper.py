#!/usr/bin/env python3
"""
Recursive firmware extraction script (based on fact-core and binwalk Matryoshka mode)

This script uses fact-extractor (Docker container) to extract individual files from firmware,
recursively extracting all contents. The idea is as follows:
    - If the item to be processed is a directory (and not a symbolic link):
            * Determine if it constitutes a complete Linux file system (e.g., contains bin, etc, lib, sbin, usr);
            * If it is a complete system, stop recursion for that branch; otherwise, directly traverse its sub-items.
    - If the item to be processed is a file:
            * If it exceeds the maximum recursion depth, is on the whitelist, or is a symbolic link, directly copy it to the target directory;
            * Otherwise, call fact-extractor to extract the file,
                placing the extraction results in a directory named "_<filename>.extracted" at the same level as the original file;
            * If extraction is successful, delete the original file (implementing binwalk's -r functionality);
            * Continue recursive processing for each file in the extraction results.

The extraction results retain the original directory structure, similar to binwalk.
"""

import argparse
import os
import sys
import subprocess
import shutil
import tempfile
import logging
import re
import fcntl

try:
    import magic
except ImportError:
    magic = None

# Whitelist MIME types: these files are not further extracted, directly copied
WHITELIST = [
    "application/x-object",
    "application/x-shockwave-flash",
    "audio/mpeg",
    "image/gif",
    "image/jpeg",
    "image/png",
    "text/plain",
    "video/mp4",
    "video/mpeg",
    "video/ogg",
    "video/quicktime",
    "video/x-msvideo",
]

DEFAULT_MAX_DEPTH = 8
DEFAULT_CONTAINER = 'fkiecad/fact_extractor'
DEFAULT_MEMORY = 512


def sanitize_filename(filename: str) -> str:
    """
    Replace special characters in the filename with underscores, keeping only letters, numbers, underscores, dots, and hyphens.
    """
    return re.sub(r'[^A-Za-z0-9_.-]', '_', filename)


def safe_copy(src: str, dst: str):
    """
    Safely copy files: skip copying if the target file already exists or if the source and target are the same.
    """
    if os.path.abspath(src) == os.path.abspath(dst):
        logging.debug(f"File {src} is already in the target location, skipping copy")
    else:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)


def safe_copy_symlink(src: str, dst: str):
    """
    Safely copy symbolic links: if the target link does not exist, copy the link.
    """
    if os.path.lexists(dst):
        logging.info(f"Symbolic link {dst} already exists")
    else:
        target = os.readlink(src)
        os.symlink(target, dst)


def is_complete_linux_fs(directory: str) -> bool:
    """
    Determine if a directory constitutes a complete Linux file system,
    based on whether it contains common system directories: bin, etc, lib, sbin, usr.
    """
    if not os.path.isdir(directory):
        return False
    required_dirs = {"bin", "etc", "lib", "sbin", "usr"}
    try:
        entries = set(os.listdir(directory))
    except Exception as e:
        logging.debug(f"Cannot read directory {directory}: {e}")
        return False
    return required_dirs.issubset(entries)


def contains_any_linux_fs_dirs(directory: str) -> bool:
    """
    Determine if a directory contains any of the common Linux file system directories: bin, etc, lib, sbin, usr.
    """
    if not os.path.isdir(directory):
        return False
    required_dirs = {"bin", "etc", "lib", "sbin", "usr"}
    try:
        entries = set(os.listdir(directory))
    except Exception as e:
        logging.debug(f"Cannot read directory {directory}: {e}")
        return False
    return bool(required_dirs & entries)


def get_mime_type(file_path: str) -> str:
    """
    Get the MIME type of a file. If the file does not exist (but may be a symbolic link), return an empty string.
    """
    if not os.path.exists(file_path) and not os.path.islink(file_path):
        logging.debug(f"File {file_path} does not exist")
        return ""
    if magic is not None:
        try:
            return magic.from_file(file_path, mime=True)
        except Exception as e:
            logging.debug(f"Cannot determine MIME type of {file_path} using python-magic: {e}")
    try:
        output = subprocess.check_output(['file', '--mime-type', '-b', file_path])
        return output.decode().strip()
    except Exception as e:
        logging.debug(f"Failed to determine MIME type of {file_path} using file command: {e}")
        return ""


def extract_file_to(input_file: str, out_dir: str, container: str, memory: int, extract_everything: bool):
    """
    Use the fact-extractor Docker container to extract a single file,
    copying the extraction results to out_dir.
    Note: Extraction is only called for regular files; symbolic links are handled at the outer layer.
    """
    
    shared_dir = "/data"  # for dind
    if not os.path.exists(shared_dir):
        os.makedirs(shared_dir)
    
    with tempfile.TemporaryDirectory(dir=shared_dir) as tmpdir:
        # Build temporary directory structure
        for sub in ['files', 'reports', 'input']:
            os.makedirs(os.path.join(tmpdir, sub), exist_ok=True)
        safe_name = sanitize_filename(os.path.basename(input_file))
        input_dest = os.path.join(tmpdir, 'input', safe_name)
        try:
            shutil.copy2(input_file, input_dest)
        except Exception as e:
            logging.debug(f"Failed to copy file {input_file} to temporary directory: {e}")
            raise
        
        cmd = [
            'docker', 'run', '--rm',
            '--ulimit', 'nofile=20000:50000',
            '-m', f'{memory}m',
            '-v', f'{tmpdir}:/tmp/extractor',
            '-v', '/dev:/dev',
            '--privileged',
            container
        ]
        if extract_everything:
            cmd.append('--extract_everything')
        logging.debug(f"Executing command: {' '.join(cmd)}")
        
        lock_file = '/tmp/extract_file_to.lock'
        with open(lock_file, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                # subprocess.run(cmd, check=True)
                # print(f"cmd: {cmd}")
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            except subprocess.CalledProcessError as e:
                logging.debug(f"Command '{e.cmd}' returned non-zero exit status {e.returncode}.")
                logging.debug(f"Error output: {e.stderr}")
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
        
        files_dir = os.path.join(tmpdir, 'files')
        if os.path.exists(files_dir) and os.listdir(files_dir):
            shutil.copytree(files_dir, out_dir, dirs_exist_ok=True, symlinks=True)
        else:
            logging.debug(f"No files extracted from {input_file}.")


def extract_recursive(file_path: str, parent_dir: str, container: str,
                      memory: int, depth: int, max_depth: int,
                      whitelist: list, extract_everything: bool, remove_original: bool):
    """
    Recursive extraction process:
        1. If the item to be processed is a directory (and not a symbolic link):
                 - If the directory constitutes a complete Linux file system, stop recursion;
                 - Otherwise, traverse its sub-items and recursively process them.
        2. If it is a regular file:
                 - If it exceeds the maximum depth, or the MIME type is on the whitelist, or it is a symbolic link, directly copy it to parent_dir;
                 - Otherwise, call fact-extractor to extract it, placing the results in a directory named "_<filename>.extracted" under parent_dir;
                 - If extraction is successful, delete the original file (if --rm is set);
                 - Continue recursive processing for each item in the extraction results.
    """
    # print(f"[file_path]", file_path)
    if not os.path.exists(file_path) and not os.path.islink(file_path):
        logging.debug(f"File or directory {file_path} does not exist, skipping")
        return
    
    if contains_any_linux_fs_dirs(os.path.dirname(file_path)):
        logging.debug(f"Detected Linux file system directory {file_path}, stopping recursion.")
        return
    
    # If it is a directory (and not a symbolic link), directly traverse sub-items
    if os.path.isdir(file_path) and not os.path.islink(file_path):
        for child in sorted(os.listdir(file_path)):
            child_path = os.path.join(file_path, child)
            extract_recursive(child_path, file_path, container, memory,
                              depth, max_depth, whitelist, extract_everything, remove_original)
        return
    
    # For regular files: if it exceeds the maximum depth, is on the whitelist, or is a symbolic link, directly copy it
    mime = get_mime_type(file_path)
    if depth > max_depth or mime in whitelist or os.path.islink(file_path):
        dest = os.path.join(parent_dir, sanitize_filename(os.path.basename(file_path)))
        if os.path.islink(file_path):
            safe_copy_symlink(file_path, dest)
        else:
            safe_copy(file_path, dest)
        return
    
    logging.debug(f"[Depth {depth}] Attempting to extract {file_path} (MIME: {mime})")
    with tempfile.TemporaryDirectory() as temp_extract_dir:
        try:
            extract_file_to(file_path, temp_extract_dir, container, memory, extract_everything)
        except subprocess.CalledProcessError as e:
            logging.debug(f"Failed to extract {file_path}: {e}")
            dest = os.path.join(parent_dir, sanitize_filename(os.path.basename(file_path)))
            safe_copy(file_path, dest)
            return
        
        entries = os.listdir(temp_extract_dir)
        if not entries:
            logging.debug(f"No extractable content from {file_path}. Directly copying the original file.")
            dest = os.path.join(parent_dir, sanitize_filename(os.path.basename(file_path)))
            safe_copy(file_path, dest)
            return
        
        # Construct the extraction result directory, format: _<original_filename>.extracted, placed under the current parent_dir
        base_name = sanitize_filename(os.path.basename(file_path))
        extract_dir_name = f"_{base_name}.extracted"
        extract_dir = os.path.join(parent_dir, extract_dir_name)
        os.makedirs(extract_dir, exist_ok=True)
        shutil.copytree(temp_extract_dir, extract_dir, dirs_exist_ok=True, symlinks=True)
        logging.debug(f"Successfully extracted {file_path}, results stored in {extract_dir}")
        
        # If the original file is to be deleted, delete the currently extracted file
        global input_firm
        if remove_original and file_path != input_firm:
            try:
                os.remove(file_path)
                logging.debug(f"Deleted original file {file_path}")
            except Exception as e:
                logging.debug(f"Failed to delete original file {file_path}: {e}")
        
        if contains_any_linux_fs_dirs(file_path):
            logging.debug(f"Detected Linux file system directory {file_path}, stopping recursion.")
            return
        
        # Recursively process each item in the extraction results
        for child in sorted(os.listdir(extract_dir)):
            child_path = os.path.join(extract_dir, child)
            extract_recursive(child_path, extract_dir, container, memory,
                              depth + 1, max_depth, whitelist, extract_everything, remove_original)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Recursively extract firmware files. Input the firmware path, and save the extraction results in the output directory (retaining the original directory structure)."
                    "The extraction results are named '_<filename>.extracted'."
    )
    parser.add_argument("input_file", type=str, help="Path to the firmware file to be extracted")
    parser.add_argument("output_dir", type=str,
                        help="Directory to store extraction results (will be created if it does not exist)")
    parser.add_argument("-c", "--container", type=str, default=DEFAULT_CONTAINER,
                        help=f"Docker container image used for extraction (default is {DEFAULT_CONTAINER})")
    parser.add_argument("-m", "--memory", type=int, default=DEFAULT_MEMORY,
                        help=f"Docker container memory limit (in MB, default is {DEFAULT_MEMORY})")
    parser.add_argument("-d", "--max_depth", type=int, default=DEFAULT_MAX_DEPTH,
                        help=f"Maximum recursion depth for extraction (default is {DEFAULT_MAX_DEPTH})")
    parser.add_argument("-e", "--extract_everything", action="store_true",
                        help="Extract even empty files, etc. (parameter passed to fact-extractor)")
    parser.add_argument("-r", "--rm", action="store_true",
                        help="Delete the original file if it can be extracted")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase log output verbosity")
    return parser.parse_args()


def setup_logging(verbose: bool):
    fmt = "[%(asctime)s][%(levelname)s]: %(message)s"
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format=fmt)


def main():
    args = parse_args()
    setup_logging(args.verbose)
    
    if not os.path.isfile(args.input_file):
        logging.debug(f"Input firmware file {args.input_file} does not exist or is not a regular file.")
        sys.exit(1)
    if os.path.exists(args.output_dir):
        logging.debug(f"Output directory {args.output_dir} already exists, please specify a non-existent directory.")
        sys.exit(1)
    os.makedirs(args.output_dir, exist_ok=True)
    
    global input_firm
    input_firm = args.input_file
    
    extract_recursive(args.input_file, args.output_dir, args.container,
                      args.memory, 1, args.max_depth, WHITELIST, args.extract_everything, args.rm)
    
    logging.debug(f"Extraction complete, results saved in {args.output_dir}")


if __name__ == "__main__":
    main()
