import os
import magic
from .Utils import *
import pathlib

# def find_rcS(fs_path):
#     # first, find "/etc"
#     # find in order, if find one then break
#     etc_list = ['etc', 'usr/etc', 'tmp/etc', "etc_ro"]
#     etc_path = None
#     for etc in etc_list:
#         tmp_etc_path = os.path.join(fs_path, etc)
#         if os.path.exists(tmp_etc_path):
#             etc_path = etc
#             break
#     if etc_path is None:
#         print("not found /etc dir!", fs_path)
#         return False
#
#     # samely, search in order
#     init_file_list = ["profile", "init.d/rcS", "rcS", "rc"]
#     init_file = None
#     for file in init_file_list:
#         tmp_init_file_path = os.path.join(fs_path, etc_path, file)
#         if os.path.exists(tmp_init_file_path):
#             init_file = os.path.join(etc_path, file)
#             break
#     if init_file is None:
#         print("not found rcS file!", fs_path)
#         return False
#
#     init_file = "/" + init_file
#     return init_file  # /etc/rcS

# def find_rcS(fs_path):
#     # first and first, find rcS directly
#     init_file_list = ["rcS", "profile"]
#     res_list = []
#
#     for init_file in init_file_list:
#         rcS_list = Files.find_file_paths(fs_path, init_file)
#
#         for file in rcS_list:
#             res_list.append(file.replace(fs_path, ""))
        # if len(rcS_list) == 1 and rcS_list[0] is not False:
        #     return rcS_list[0].replace(fs_path, "")
        # if len(rcS_list) > 1:  # for multi file, we use which longer
        #     max = 0
        #     res = None
        #     for file in rcS_list:
        #         line = count_lines(file)
        #         if line > max:
        #             max = line
        #             res = file
        #
        #     # print(len(rcS_list), fs_path, res.replace(fs_path, "").replace("/","", 1))
        #     return res.replace(fs_path, "") # /etc/rcS

    # return res_list


# def find_rcS(fs_path):
#     res_list = []
#     # first, we try /etc/init.d/rcS
#     etc_list = ['etc', 'usr/etc', 'tmp/etc', "etc_ro"]
#     for etc in etc_list:
#         rel_rcs_path = os.path.join(etc, "init.d/rcS")
#         tmp_initd_rcs_path = os.path.join(fs_path, rel_rcs_path)
#         if os.path.exists(tmp_initd_rcs_path):
#             res_list += [["/" + rel_rcs_path, ""]] # file name, args
#
#     # second, return other all
#     # TODO: maybe rcS and profile should be process differently
#     init_file_list = ["rcS", "profile"]
#
#
#     for init_file in init_file_list:
#         rcS_list = Files.find_file_paths(fs_path, init_file)
#         for file in rcS_list:
#             res_list.append([file.replace(fs_path, ""), ""])
#
#     return res_list

# def find_etc(fs_path):
#     # first, find "/etc"
#     etc_list = ['etc', 'usr/etc', 'tmp/etc', "etc_ro"]
#     etc_res = []
#     for etc in etc_list:
#         tmp_etc_path = os.path.join(fs_path, etc)
#         if os.path.exists(tmp_etc_path) and os.path.isdir(tmp_etc_path): # we found a etc dict
#
#             # TODO:R8500_V1.0.0.28_1.0.15.zip.extracted/
#             if os.path.exists(os.path.join(tmp_etc_path, "init.d")) or os.path.exists(os.path.join(tmp_etc_path, "rc.d")) \
#                     or os.path.exists(os.path.join(tmp_etc_path, "profile")) or os.path.exists(os.path.join(tmp_etc_path, "rcS")) \
#                     or os.path.exists(os.path.join(tmp_etc_path, "rc")): # indicators
#                 etc_res.append(tmp_etc_path.replace(fs_path, ""))
#
#     return etc_res

# def find_initd_rcs(fs_path):
#     # actually, there is only one /etc/init.d/rcS is right
#     rcS_path = ""
#
#     etc_list = ['etc', 'usr/etc', 'tmp/etc', "etc_ro"]
#     for etc in etc_list:
#         rel_rcs_path = os.path.join(etc, "init.d/rcS")
#         tmp_initd_rcs_path = os.path.join(fs_path, rel_rcs_path)
#         if os.path.exists(tmp_initd_rcs_path):
#             rcS_path = "/" + rel_rcs_path # etc/init.d/rcS
#             return rcS_path
#
#     # second, return other all
#     # # TODO: maybe rcS and profile should be process differently
#
#     if rcS_path == "":
#         init_file_list = find_all_rcs(fs_path)
#         if len(init_file_list) == 0:
#             return ""
#         if len(init_file_list) == 1:
#             print(init_file_list[0])
#             return init_file_list[0]
#         else:
#             print("multi rcS found!")
#             print(init_file_list)
#             exit(0)


# def find_all_rcs(fs_path):
#     res_list = list()
#     init_file_list = ["rcS"]
#
#     for init_file in init_file_list:
#         rcS_list = Files.find_file_paths(fs_path, init_file)
#         for file in rcS_list:
#             res_list.append(file.replace(fs_path, ""))
#
#     return res_list

def is_elf_executable(file_path):
    if os.path.isdir(file_path) or os.path.islink(file_path):
        return False
    mime = magic.Magic(mime=True)
    file_mime_type = mime.from_file(file_path)
    return "application/x-executable" in file_mime_type

def is_bash_script(file_path):
    if file_path.endswith(".php") or file_path.endswith(".html") or file_path.endswith(".htm"):
        return False
    if file_path.endswith(".sh") or ".sh" in file_path:
        return True
    try:
        with open(file_path, 'r', encoding='u8') as file:
            first_line = file.readline()
            if first_line.startswith("#!") or "sh" in first_line: # #!/bin/bash
                return True
    except Exception as e:
        pass
        # print(f"[is_bash_script]: {e}")
        # print(file_path)
    return False

# def is_bash_script(file_path):
#     try:
#         with open(file_path, 'r') as file:
#             lines = file.readlines()
#
#         # shebang
#         if lines[0].strip() in ["#!/bin/bash", "#!/usr/bin/env bash"]:
#             return True
#
#         # bash
#         bash_patterns = [
#             r"\bif\b", r"\bthen\b", r"\bfi\b",
#             r"\bcase\b", r"\besac\b",
#             r"\bfor\b", r"\bdo\b", r"\bdone\b",
#             r"\bwhile\b", r"\buntil\b",
#             r"\bfunction\b"
#         ]
#         for line in lines:
#             for pattern in bash_patterns:
#                 if re.search(pattern, line):
#                     return True
#
#         return False
#     except IOError:
#         return False

# def find_all_broken_symlinks(directory):
#     broken_symlinks = []
#     for dirpath, _, filenames in os.walk(directory):
#         for filename in filenames:
#             filepath = os.path.join(dirpath, filename)
#             if os.path.islink(filepath) and not os.path.exists(filepath):
#                 filepath = filepath.replace(directory, "")  # return rel path
#                 broken_symlinks.append(filepath)
#     return broken_symlinks

# def find_main_broken_symlinks(directory):
#     broken_symlinks = []
#     for file in os.listdir(directory):
#         filepath = os.path.join(directory, file)
#         if os.path.islink(filepath) and not os.path.exists(filepath):
#             filepath = filepath.replace(directory, "") # return rel path
#             broken_symlinks.append(filepath)
#     return broken_symlinks

# def count_lines(file_path):
#     try:
#         with open(file_path, 'r', encoding='u8') as file:
#             lines = file.readlines()
#             line_count = len(lines)
#             return line_count
#     except:
#         return 0




# def readlines(file_path):
#     with open(file_path, 'r') as f:
#         return f.readlines()

# def writelines(file_path, lines):
#     with open(file_path, 'w') as f:
#         f.writelines(lines)
#         f.flush()
#     return



def insert_multiple_lines_at(file_path, line_number, lines_to_insert):
    """
    。

    :param file_path: 。
    :param line_number: （1）。
    :param lines_to_insert: ，。
    """
    with open(file_path, 'r', encoding='u8', errors='ignore') as file:
        lines = file.readlines()

    # 
    lines_to_insert = [line if line.endswith('\n') else line + '\n' for line in lines_to_insert]

    # 
    for index, line in enumerate(lines_to_insert):
        lines.insert(line_number - 1 + index, line)

    # 
    with open(file_path, 'w') as file:
        file.writelines(lines)

# def comment_lines_with_keywords(file_path, keywords):
#     """
#     ，(#)。
#
#     :param file_path: 。
#     :param keywords: 。
#     """
#     with open(file_path, 'r') as file:
#         lines = file.readlines()
#
#     # ，
#     for i, line in enumerate(lines):
#         if all(keyword in line for keyword in keywords) and "[" not in line:
#             print(f"[comment_lines_with_keywords] {file_path} #{line.strip()}")
#             lines[i] = '#' + line
#
#     # 
#     with open(file_path, 'w') as file:
#         file.writelines(lines)


# def check_and_umount(directory):
#     """
#     ，，。
#
#     :param directory: 。
#     """
#     # 
#     result = subprocess.run(['mountpoint', '-q', directory])
#
#     # （mountpoint  0），
#     if result.returncode == 0:
#         try:
#             print(f": {directory}")
#             subprocess.run(['sudo', 'umount', directory], check=True)
#             print("。")
#         except subprocess.CalledProcessError as e:
#             print(f": {e}")
#     else:
#         print(f" {directory} 。")

# def proprecess_rcS(file_path):
#     '''
#     # exec >/dev/console 2>/dev/console
#     '''
#     pass
#
#
#
#     # lines = readlines(file_path)
#     #
#     # new_lines = list()
#     #
#     # for line in lines:
#     #     if ". /etc/init.d/rcS.preinit" in line and not line.startswith("#"):
#     #         new_lines.append("#" + line)
#     #     elif "exec " in line and not line.startswith("#"):
#     #         new_lines.append(line.replace("exec ", ""))
#     #     else:
#     #         new_lines.append(line)
#     #
#     # writelines(file_path, new_lines)



def get_rel_path(path):
    if path.startswith("/"):
        return path.replace("/", "", 1)
    else:
        return path

def get_symbolic_links_in_dir(directory_path):
    res = dict()
    if not os.path.isdir(directory_path):
        return

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.islink(file_path):
                link_target = os.readlink(file_path)
                file_path = file_path.replace(directory_path + "/", "")
                res[file_path] = link_target # preinit: rc

    return res

def find_keys_by_value(dictionary, value):
    keys = [key for key, val in dictionary.items() if val == value]
    return keys

def get_target_link_path(fs_path, rel_path):
    full_path = os.path.join(fs_path, rel_path)
    return str(pathlib.Path(full_path).resolve()).replace(fs_path, "")

def get_all_files_in_directory(directory):
    file_list = []
    for root, directories, files in os.walk(directory):
        for filename in files:
            file_list.append(filename)
    return file_list

def get_symbolic_links_in_dir(directory_path):
    res = dict()
    if not os.path.isdir(directory_path):
        return res

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)

            if os.path.islink(file_path):
                link_target = os.readlink(file_path)
                file_path = file_path.replace(directory_path + "/", "")
                res[file_path] = link_target  # preinit: rc

    return res

# def quote_arguments(command_line):
#     # Split the command line into tokens
#     parts = command_line.split()
#     result = []
#
#     i = 0
#     while i < len(parts):
#         part = parts[i]
#
#         # If part starts with '-' and is not the last part
#         if part.startswith('-') and i + 1 < len(parts):
#             # Collect all subsequent parts until next part starts with '-' or end of command
#             temp = [part]
#             i += 1
#             while i < len(parts) and not parts[i].startswith('-'):
#                 temp.append(parts[i])
#                 i += 1
#
#             # Join these parts with space and enclose in quotes
#             if len(temp[1:]) != 0:
#                 result.append(f'{temp[0]} "{" ".join(temp[1:])}"')
#             else:
#                 result.append(f'{temp[0]}')
#         else:
#             # Otherwise, just add the part to the result
#             result.append(part)
#             i += 1
#
#     return ' '.join(result)

def find_directories_name(path, name):
    # List to store the paths of 'lib' directories found
    paths = []

    # Walk through the directory
    for root, dirs, files in os.walk(path):
        # Check if 'lib' is in the current directory
        for _dir in dirs:
            if _dir == name:
                # Construct the full path and add it to the list
                full_path = os.path.join(root, name)
                paths.append(full_path.replace(path, ""))

    return paths



# def get_execve_trace(lines):
#     if len(lines) == 0:
#         return None
#
#     execve_set = set()
#     curr_ps = []
#     bin_sh_flag = False
#
#     for line in lines:
#         try:
#             line = line.strip()
#             if "[qemu] doing qemu_execven on filename" in line:
#                 bin_sh_flag = False # set a new loop, if bin/sh in line it will be True
#                 if "/bin/sh" in line:
#                     bin_sh_flag = True # skip this loop for extract arg
#
#             if line.startswith("- arg") and ":" in line and bin_sh_flag is False:
#                 if len(line.split(": ", 1)) > 1:
#                     key, value = line.split(": ", 1)
#                 else:
#                     key = line.split(": ", 1)[0]
#                     value = ""
#                 arg_index = int(key.replace("- arg", "").replace(":", ""))
#
#                 if arg_index == 8 and "/bin/sh" in value: # skip /bin/sh
#                     continue
#                 if arg_index == 9 and "-c" in value: # skip -c
#                     continue
#
#                 if arg_index == 8: # first word not add ""
#                     curr_ps.append(value)
#                 if arg_index > 8: # for other word, if not start with -, add ""
#                     # /usr/sbin/mini_httpd -d "/www" -r "NETGEAR R6220" -c "**.cgi" -t "300"
#                     if not value.startswith("-"):
#                         value = f"\"{value}\""
#                     curr_ps.append(value)
#
#             if not line.startswith("- arg"): # for next trace
#                 execve_set.add(" ".join(curr_ps))
#                 curr_ps = []
#         except Exception as e:
#             pass
#             # print("error: get_execve_trace", line)
#             # print(e)
#             # return None
#
#     return execve_set

def parse_bash_trace_log(lines):
    execute_lines = []
    error_lines = []
    for line in lines.splitlines():
        if line.startswith("+"):
            execute_lines.append(line)
        else:
            error_lines.append(line)
    return execute_lines, error_lines


def find_shortest_string_in_set(strings_set):
    # Check if the set is not empty
    if not strings_set:
        return None

    # The shortest string can be initialized with any element from the set
    shortest = next(iter(strings_set))

    # Iterate through the strings to find the shortest one
    for string in strings_set:
        if len(string) < len(shortest):
            shortest = string

    return shortest

def get_all_filenames(directory):
    filenames = set()
    for root, dirs, files in os.walk(directory):
        for file in files:
            filenames.add(file)
    return filenames

def binwalk_img(img_path, out_path):
    import getpass
    curruser = getpass.getuser()
    binwalk_command = ["binwalk"]
    if curruser == "root":
        binwalk_command.extend(["--run-as=root"])
    binwalk_command.extend(["--preserve-symlinks", "-eMq", img_path, "-C", out_path])
    subprocess.run(binwalk_command)