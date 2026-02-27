#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import tempfile
import hashlib
import time

def copy_files_to_container(docker_manager, fs_path, changed_files):
    """
    Copy changed files from GH filesystem to the container

    Args:
        docker_manager: Docker container manager
        fs_path: GH filesystem path
        changed_files: list of changed file paths

    Returns:
        bool: True on success, False otherwise
    """
    if docker_manager is None or not changed_files:
        return False

    print(f"[GH] Copying {len(changed_files)} changed files to container...")
    success_count = 0

    for file_path in changed_files:
        # Get local file path
        local_path = os.path.join(fs_path, file_path)
        if os.path.exists(local_path) and os.path.isfile(local_path):
            # Target path in the container
            container_path = f"/fs/{file_path}"

            try:
                print(f"[GH] Copying {local_path} -> {container_path}")

                # Ensure target directory exists
                container_dir = os.path.dirname(container_path)
                docker_manager.exec_run(f"mkdir -p {container_dir}")

                # Create temp file and copy
                with tempfile.NamedTemporaryFile(delete=False) as temp:
                    temp_path = temp.name

                # Copy file contents to temp file
                shutil.copy2(local_path, temp_path)

                # Copy to container
                docker_manager.docker_cp_to_container(temp_path, container_path)

                # Set correct permissions
                try:
                    mode = oct(os.stat(local_path).st_mode)[-3:]
                    docker_manager.exec_run(f"chmod {mode} {container_path}")
                except Exception as e:
                    print(f"[GH] Error setting file permissions: {e}")

                # Delete temp file
                os.unlink(temp_path)
                success_count += 1

            except Exception as e:
                print(f"[GH] Error copying file: {e}")

    print(f"[GH] Successfully copied {success_count}/{len(changed_files)} files")
    return success_count > 0

def compare_file_systems(before_fs, after_fs):
    """
    Compare filesystem state before and after patching, find changed files

    Args:
        before_fs: filesystem state before patching (dict {path: MD5 hash})
        after_fs: filesystem state after patching (dict {path: MD5 hash})

    Returns:
        list: list of new and modified file paths
    """
    changed_files = []

    # Find new files
    new_files = set(after_fs.keys()) - set(before_fs.keys())
    changed_files.extend(list(new_files))

    # Find modified files
    for file_path in set(before_fs.keys()).intersection(set(after_fs.keys())):
        if before_fs[file_path] != after_fs[file_path]:
            changed_files.append(file_path)

    return changed_files

def collect_file_system_state(fs_path):
    """
    Collect filesystem state

    Args:
        fs_path: filesystem path

    Returns:
        dict: filesystem state (dict {path: MD5 hash})
    """
    fs_state = {}

    for root, dirs, files in os.walk(fs_path, topdown=False):
        for file in files:
            path = os.path.join(root, file)
            if os.path.isfile(path):
                try:
                    rel_path = os.path.relpath(path, fs_path)

                    # Compute MD5 hash
                    md5_hash = hashlib.md5()
                    with open(path, 'rb') as f:
                        # Read in chunks to avoid loading large files into memory at once
                        for chunk in iter(lambda: f.read(4096), b''):
                            md5_hash.update(chunk)

                    fs_state[rel_path] = md5_hash.hexdigest()
                except Exception as e:
                    print(f"[GH] Error processing file {path}: {e}")

    return fs_state
