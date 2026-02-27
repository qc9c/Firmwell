import os
import logging
import networkx
import traceback
import subprocess
from pprint import pprint
from collections import defaultdict

from firmwell.backend.call_chain_utils.GhidraTool import GhidraTool
from firmwell.backend.call_chain_utils.shell_cfg import ShellCFGGenerator
from firmwell.backend.Utils import find_files

logger = logging.getLogger(__name__)


class CallChainConstructor:
    def __init__(self, firm_name, filesystem, config):
        self.firm_name = firm_name
        self.fs_path = filesystem.path
        self.filesystem = filesystem
        self.config = config

        self.HEADLESS_ANALYZER="/ghidra_11.2_PUBLIC/support/analyzeHeadless"
        self.GHIDRA_SCRIPT="/fw/firmwell/backend/call_chain_utils/fw_ghidra_scripts.py"


        self.execve_map = defaultdict(set)

        self.shell_parser = ShellCFGGenerator()

        firm_dir = os.path.join("/tmp", self.firm_name)
        self.ghidra_proj_path = os.path.join(firm_dir, "ghidra_project")
        if not os.path.exists(self.ghidra_proj_path):
            os.makedirs(self.ghidra_proj_path)
        self.ghidra_result_path = os.path.join(firm_dir, "ghidra_result")
        if not os.path.exists(self.ghidra_result_path):
            os.makedirs(self.ghidra_result_path)

        self._initialize_graph()

    def _initialize_graph(self):
        self._graph = networkx.DiGraph()

    @property
    def graph(self):
        return self._graph

    def add_egde(self, caller, callee):
        if not self._graph.has_node(caller):
            self._graph.add_node(caller)
        if not self._graph.has_node(callee):
            self._graph.add_node(callee)

        self._graph.add_edge(caller, callee)
        logger.debug(f"[execve] {caller} -> {callee}")

    def traverse_graph(self):
        try:
            for node in networkx.topological_sort(self.graph):
                for edge in self.graph.edges(node):
                    print(f"    {edge[0]} -> {edge[1]}")
        except Exception as e:
            print(f"traverse_graph error: {e}")

    def get_call_chain(self, init_path, target_binary_path):
        print(f"Find the path from {init_path} to {target_binary_path}")

        try:
            call_chain = list(networkx.all_simple_paths(self.graph, init_path, target_binary_path))

            if call_chain:
                call_chain = min(call_chain, key=len)

            pprint(call_chain)

            for i in range(len(call_chain)):
                call_chain[i] = self.filesystem.get_abs_path(call_chain[i])
            
            self.traverse_graph()
            
            logger.info(f"call_chain: {call_chain}")
            return call_chain
        except Exception as e:
            print(f"get_call_chain error: {e}")
            return []

    def get_executeable_type_by_path(self, path):
        if path in self.filesystem.elf_files:
            return "elf"
        elif path in self.filesystem.bash_files:
            return "bash"
        else:
            return None

    @staticmethod
    def get_strings_of_file(file_path, target_str) -> list:
        cmd = f'strings -w "{file_path}" | grep {target_str}' # -w: match white space
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.splitlines()

    def get_potential_caller_by_str(self, target_path: str) -> set:
        target_str = os.path.basename(target_path)
        target_dir = self.filesystem.get_abs_path(target_path)

        potential_caller_set = set()

        for file_path in self.filesystem.executeable_files:
            if target_path == file_path: # exclude self
                continue
                

            if "sbin/rc" in file_path:
                potential_caller_set.add(file_path)
                continue

            strings = self.get_strings_of_file(file_path, target_str)

            if self.get_executeable_type_by_path(file_path) == "elf":
                for i in strings:
                    first_token = i.strip().split(" ")[0]
                    if (i.startswith(f"{target_str} ") # rel path, with space as spliter
                            or i == target_str # rel path, without space
                            or (self.filesystem.filepath_exist_in_filesystem(first_token) and target_dir == first_token) # abs_path, /sbin/init
                            or os.path.basename(first_token) == target_str): # /etc/mini_httpd -d /www -r "NETGEAR DG834%s%c" -c '**cgi' -t %d&
                        potential_caller_set.add(file_path)
            elif self.get_executeable_type_by_path(file_path) == "bash":
                for i in strings:
                    if target_str in i:
                        potential_caller_set.add(file_path)

        # # potential_caller_setfilesystem.symbol_link_dict，symbol link
        # for i in potential_caller_set:
        #     if i in self.filesystem.symbol_link_dict:
        #         target = self.filesystem.symbol_link_dict[i]
        #
        #         potential_caller_set.remove(i)
        #         if "busybox" not in target:
        #             potential_caller_set.add(target)

        # ，target_pathsymbol link
        if target_path in potential_caller_set:
            potential_caller_set.remove(target_path)
        if target_path in self.filesystem.symbol2file_dict and self.filesystem.symbol2file_dict[target_path] in potential_caller_set:
            potential_caller_set.remove(self.filesystem.symbol2file_dict[target_path])

        return potential_caller_set

    def call_chain_build_succ(self, init_path, target_binary_full_path) -> bool:
        if self.graph.has_node(init_path) and self.graph.has_node(target_binary_full_path):
            if networkx.has_path(self.graph, init_path, target_binary_full_path):
                return True
        return False

    def get_callee(self, caller, current_binary_name) -> set:
        caller_type = self.get_executeable_type_by_path(caller)
        if caller_type == "bash":
            callee_set = self.get_bash_callee(caller)
        elif caller_type == "elf":
            callee_set = self.get_binary_callee(caller, current_binary_name)
        else:
            print(f"unknown type: {caller}")
            callee_set = None
        return callee_set

    def run(self, entry, target_binary_path):

        init_path = entry.init_binary
        init_bash = entry.init_bash
        init_binary_procd = entry.init_binary_procd
        full_init_path = self.filesystem.get_full_path(init_path)

        target_binary_full_path = self.filesystem.get_full_path(target_binary_path)
        worklist, analyzed = list(), set()
        worklist.append(target_binary_full_path)

        self.graph.add_node(target_binary_full_path) # target node

        # Known Information
        # TODO: dirty hack. use ghidra analysis to find busybox and procd
        # UPDATE: for busybox -> rcS, it's hard to find execve info
        if os.path.basename(init_path) == "busybox":
            self.graph.add_node(full_init_path)
            if init_bash and not self.graph.has_node(self.filesystem.get_full_path(init_bash)):
                self.graph.add_node(self.filesystem.get_full_path(init_bash))

            self.graph.add_edge(full_init_path, self.filesystem.get_full_path(init_bash))
            logger.debug(f"[execve] {full_init_path} -> {init_bash}")

        if os.path.basename(init_binary_procd) == "procd":
            procd_path = self.filesystem.get_full_path(init_binary_procd)
            self.graph.add_node(full_init_path)
            self.graph.add_node(procd_path)
            self.graph.add_edge(full_init_path, procd_path)
            logger.debug(f"[execve] {full_init_path} -> {procd_path}")
            
            if self.filesystem.get_full_path(init_bash):
                self.graph.add_node(self.filesystem.get_full_path(init_bash))
                self.graph.add_edge(procd_path, self.filesystem.get_full_path(init_bash))
                logger.debug(f"[execve] {procd_path} -> {self.filesystem.get_full_path(init_bash)}")
            # self.graph.add_node(init_bash)
            # self.graph.add_edge(self.filesystem.get_full_path(init_bash), current_binary)
            # logger.debug(f"[execve] {init_bash} -> {current_binary}")
        if self.filesystem.file_in_filesystem("HTTP.php"): # edge-case, use php as init script
            self.graph.add_node(self.filesystem.get_full_path(target_binary_path))
            
            self.graph.add_edge(self.filesystem.get_full_path(init_bash), self.filesystem.get_full_path(target_binary_path))
            logger.debug(f"[execve] {self.filesystem.get_full_path(init_bash)} -> {self.filesystem.get_full_path(target_binary_path)}")

        count = 20 

        while worklist:
            count -= 1 # TODO: remove count
            if count == 0:
                print("callchain_count_failed\n\n")
                print("callchain_count_failed\n\n")
                print("callchain_count_failed\n\n")
                exit(1)


            current_binary = worklist.pop()
            analyzed.add(current_binary)

            current_binary_name = os.path.basename(current_binary)
            logger.info(f"analyzing {current_binary_name}")

            if "etc/init.d" in current_binary or "etc/rc.d" in current_binary or "etc_ro/init.d" in current_binary or "etc_ro/rc.d" in current_binary or "etc/rcS" in current_binary or "etc_ro/rcS" in current_binary \
                    and (os.path.basename(init_path) == "busybox" or os.path.basename(init_binary_procd) == "procd"):
                '''
                ['/bin/busybox',
                 '/etc/init.d/uhttpd',
                 '/www/cgi-bin/uhttpd.sh',
                 '/usr/sbin/uhttpd']
                '''
                if self.filesystem.get_full_path(init_bash):
                    self.graph.add_edge(self.filesystem.get_full_path(init_bash), current_binary)
                    logger.debug(f"[execve] {self.filesystem.get_full_path(init_bash)} -> {current_binary}")
                elif os.path.basename(init_binary_procd) == "procd":
                    self.graph.add_edge(self.filesystem.get_full_path(procd_path), current_binary)
                    logger.debug(f"[execve] {self.filesystem.get_full_path(procd_path)} -> {current_binary}")

            if self.call_chain_build_succ(full_init_path, target_binary_full_path):
                return self.get_call_chain(full_init_path, target_binary_full_path)

            potential_caller = self.get_potential_caller_by_str(current_binary)
            if target_binary_full_path in potential_caller:
                potential_caller.remove(target_binary_full_path)
            for i in potential_caller:
                logger.info(f"[{current_binary_name}] potential_caller: {i}")


            if len(potential_caller) == 0:
                logger.info(f"potential_caller is empty")
                if current_binary in self.filesystem.file2symbol_dict:
                    potential_caller = set()
                    syms = self.filesystem.file2symbol_dict[current_binary]


                    for sym in syms:
                        tmp_res = self.get_potential_caller_by_str(sym)
                        if len(tmp_res) > 0:
                            logger.info(f"find potential_caller by sym link {sym}")
                            logger.info(f"potential_caller: {tmp_res}")
                            potential_caller.update(tmp_res)

            potential_caller = sorted(potential_caller)
            # Prioritize full_init_path by moving it to the front
            if full_init_path in potential_caller:
                potential_caller.remove(full_init_path)
                potential_caller.insert(0, full_init_path)

            for caller in potential_caller:

                if target_binary_path == caller and self.get_executeable_type_by_path(caller) == "elf":
                    continue # exclude self

                callee_set = self.get_callee(caller, current_binary_name)
                if not callee_set:
                    logger.info(f"{caller} potential callee []")
                    continue

                # # potential_caller_setfilesystem.symbol_link_dict，symbol link
                # caller_real_path = caller
                # if current_binary_name in self.filesystem.symbol_link_dict:
                #     caller_real_path = self.filesystem.symbol_link_dict[current_binary]

                find_flag = False
                for callee in callee_set:
                    logger.debug(f"        {os.path.basename(caller)} potential callee: {callee}")
                    if (current_binary_name == os.path.basename(callee)
                        or (callee in self.filesystem.symbol2file_dict and os.path.basename(self.filesystem.symbol2file_dict[callee]) == os.path.basename(current_binary_name))):

                        # Add caller node and edge if caller is not yet in the graph
                        if not self.graph.has_node(caller):
                            self.graph.add_node(caller)
                            self.graph.add_edge(caller, current_binary)
                            if caller not in analyzed:
                                worklist.append(caller)
                                analyzed.add(caller)

                            logger.info(f"[found execve] {os.path.basename(caller)} -> {os.path.basename(callee)}")
                            find_flag = True

                            if self.call_chain_build_succ(full_init_path, target_binary_full_path):
                                return self.get_call_chain(full_init_path, target_binary_full_path)
                            break

                        elif not networkx.has_path(self.graph, current_binary, caller):
                            self.graph.add_edge(caller, current_binary)
                            if caller not in analyzed:
                                worklist.append(caller)
                                analyzed.add(caller)

                            logger.info(f"[found execve] {os.path.basename(caller)} -> {os.path.basename(callee)}")
                            find_flag = True

                            if self.call_chain_build_succ(full_init_path, target_binary_full_path):
                                return self.get_call_chain(full_init_path, target_binary_full_path)

                            break

                        else:
                            pass
                        
                if not find_flag:
                    logger.info(f"[not found execve] {os.path.basename(caller)} -> ")
                    for i in callee_set:
                        logger.info(f"    {i}")

                if self.call_chain_build_succ(full_init_path, target_binary_full_path):
                    return self.get_call_chain(full_init_path, target_binary_full_path)

            logger.info(f"End of analyzing {current_binary_name}")
            logger.info(f"current_binary_name: {current_binary_name}, worklist: {worklist}")


        print("callchain_failed\n\n")
        print("callchain_failed\n\n")
        
        print("callchain_failed\n\n")
        pprint(self.get_call_chain(init_path, target_binary_path))

        return None

    def run_ghidra_analysis(self, binary_path: str, target_str: str):
        ghidra_tool = GhidraTool(project_path=self.ghidra_proj_path,
                                 project_name=self.firm_name,
                                 result_path=self.ghidra_result_path,
                                 ghidra_script=self.GHIDRA_SCRIPT,
                                 headless_analyzer=self.HEADLESS_ANALYZER)

        try:
            ghidra_tool.run(binary_path, target_str)
        finally:
            ghidra_tool.stop_ghidra_process()

    def get_real_caller_by_path(self, caller_path, potential_callee_set) -> set:
        """
        For potential callee set, if the callee is in the filesystem, add it to the callee set.
        """
        callee_set = set()

        for potential_callee in potential_callee_set:
            try:
                potential_callee = potential_callee.strip().replace("\"", "")
                
                if potential_callee.endswith("&"):
                    potential_callee = potential_callee[:-1]
                
                full_path = self.filesystem.get_full_path(potential_callee)
                # print(f"[get_real_caller_by_path]    {potential_callee} -> {full_path}")
                # abs_path = self.filesystem.get_abs_path(full_path)
                # if full_path:
                #     if not os.path.islink(full_path) and full_path in self.filesystem.executeable_files:
                #         # print(f"    {caller_path.replace(self.fs_path, '')} -> {str(subprocess_abs_path).replace(self.fs_path, '')}")
                #         callee_set.add(self.filesystem.get_abs_path(full_path))

                # if full_path and os.path.exists(full_path):
                if full_path:
                    callee_set.add(full_path)
                # if self.filesystem.file_in_filesystem(os.path.basename(potential_callee)):
                #     # print("debug", potential_callee)
                #     subprocess_abs_path = self.filesystem.get_exe_path_by_name(potential_callee)
                #     subprocess_full_path = self.filesystem.get_full_path(subprocess_abs_path)
                #     # if not symbolic link
                #     if not os.path.islink(subprocess_full_path) and str(subprocess_abs_path) in self.filesystem.executeable_files:
            except Exception as e:
                print(f"error [get_real_caller_by_path]: {e}")
                print(callee_set)
                print(caller_path)
                traceback.print_exc()

        return callee_set

    def get_bash_callee(self, caller_path: str) -> set:
        """
        Get the subprocess of the binary by Ghidra scripts.
        Input: binary_path
        Output: a set of subprocess name
        """

        if caller_path in self.execve_map:
            return self.execve_map[caller_path]

        potential_callee = self.shell_parser.get_all_callee(caller_path)
        callee_set = self.get_real_caller_by_path(caller_path, potential_callee)

        self.execve_map[caller_path] = callee_set

        return callee_set

    def get_binary_callee(self, caller_path: str, target_str: str) -> set:
        """
        Get the subprocess of the binary by Ghidra scripts.
        Input: caller_path
        Output: a set of subprocess name
        """

        if caller_path in self.execve_map:
            return self.execve_map[caller_path]

        callee_set = self.get_callee_set_by_ghidra(caller_path, target_str)
        self.execve_map[caller_path] = callee_set
        
        if os.path.basename(caller_path) == "cos":
            res = find_files("libcmm.so", self.fs_path)
            if len(res) > 0:
                callee_set = self.get_callee_set_by_ghidra(res[0], target_str)
                self.execve_map[caller_path].update(callee_set)
        
        if os.path.basename(caller_path) == "lighttpd-angel":
            self.execve_map[caller_path].add("lighttpd")

        return callee_set


    def get_callee_set_by_ghidra(self, caller_path, target_str):
        """Run Ghidra analysis on a binary and return the set of verified callees."""
        potential_callee = set()

        result_file = os.path.join(self.ghidra_result_path, os.path.basename(caller_path))

        if not os.path.exists(result_file):
            self.run_ghidra_analysis(caller_path, target_str)

        # read the result from ghidra analysis
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                for line in f.readlines():
                    # get first token, which is the subprocess name(if any)
                    potential_subprocess = line.strip().split(" ")[0]
                    potential_callee.add(potential_subprocess)

        callee_set = self.get_real_caller_by_path(caller_path, potential_callee)
        return callee_set

class Entry:
    def __init__(self, init_binary: str, init_bash: str, init_binary_procd):
        self.init_binary = init_binary
        self.init_bash = init_bash
        self.init_binary_procd = init_binary_procd

