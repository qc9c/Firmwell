import os
import logging
import networkx as nx
from collections import OrderedDict

logger = logging.getLogger(__name__)

def _get_clean_process(command):
    if "-E LD_PRELOAD=libnvram-faker.so" in command:
        command = command.rsplit("-E LD_PRELOAD=libnvram-faker.so")[-1].strip()
    elif "-strace " in command:
        command = command.rsplit("-strace ")[-1].strip()
    elif "hacksysinfo" in command:
        command = command.split("hacksysinfo")[-1].strip()
    return command

class ProcessUtil: # TODO: get process every time if a metohd is called
    def __init__(self, runner, filesystem):
        self.runner = runner
        self.filesystem = filesystem

    def get_alive_numm(self):
        cmd = "ps x | wc -l"
        res = self.runner.exec(cmd)
        return int(res)

    def get_defunct_process_num(self, process_dict):
        defunct_num = 0
        for pid, ps in process_dict.items():
            if "<defunct>" in ps:
                defunct_num += 1
        return defunct_num

    def get_ppid(self, pid):
        output = self.runner.exec(f"ps -o pid,ppid -p {pid}")
        if output.count("\n") == 2:
            ppid = output.split("\n")[1].replace(pid, "").strip()
            return ppid
        return None

    def pid_is_alive(self, pid):
        return pid in self.get_process_dict()

    def get_process_tree(self):
        ps_output = self.runner.exec("ps -eo pid,ppid,args")
        process_dict, process_graph = self._parse_ps_output(ps_output)
        return process_graph, process_dict

    # def get_process_dict(self) -> dict:
    #     if self.runner.category == "system":
    #         ps_output = self.runner.exec("ps -eo pid,ppid,args")
    #         process_dict, _ = self._parse_ps_output(ps_output)
    #         return process_dict
    #     else:  # category == "user" (docker container)
    #         top_output = self.runner.container.top(ps_args='-eo pid,ppid,args')
    #         process_dict = {}
    #         for process in top_output['Processes']:
    #             pid = process[0]
    #             args = process[2]
    #             # Clean the process command similar to _get_clean_process
    #             args = _get_clean_process(args)
    #             process_dict[pid] = args
    #         return process_dict
    
    def get_process_dict(self): # top,dindpid,pidkill,docker errorps
        ps_output = self.runner.exec("ps -eo pid,ppid,args")
        process_dict, _ = self._parse_ps_output(ps_output)
        return process_dict

    def get_processname_pid_dict(self, process_dict):
        """
        input: { '266': '/bin/sh /etc/rc.common /etc/rc.d/S20net-lan boot'}
        output: { '/etc/rc.d/S20net-lan': '266'}
        """
        logger.debug("process_dict: %s", process_dict)
        processname_dict = {}
        for pid, ps in process_dict.items():
            # psfs
            for ps in ps.split(" ")[::-1]:
                if self.filesystem.filepath_exist_in_filesystem(ps):
                    processname_dict[ps] = pid
                    break

        logger.debug("processname_dict: %s", processname_dict)
        return processname_dict

    def process_is_alive(self, process_path):
        process_dict = self.get_process_dict()
        processname_pid_dict = self.get_processname_pid_dict(process_dict)
        for path, pid in processname_pid_dict.items():
            if process_path == path:
                return True
        return False

    def get_children_and_parent(self, process_graph, pid):
        children = list(process_graph.successors(pid))
        parents = list(process_graph.predecessors(pid))
        parent = parents[0] if parents else None
        return children, parent

    def get_subtree_depth(self, process_graph, pid):
        """。"""
        if pid not in process_graph:
            return 0
        try:
            path = nx.algorithms.dag.dag_longest_path(process_graph)
            if pid in path:
                return len(path) - 1
            return 0
        except nx.NetworkXError:
            return 0

    # ，pidsubprocess，pidprocess nameordered_dict

    def get_subprocess(self, process_graph, process_dict, pid):
        """
        pidsubprocess
        Args:
            process_graph (networkx.DiGraph): 。
            pid: pid

        Returns:
            list: subprocesspid。
        """

        #last_subprocess = subprocess.popitem(last=True) if subprocess else None

        subprocess = OrderedDict()
        for node in process_graph.successors(pid):
            subprocess_pid = node
            subprocess_name = process_dict[node]
            subprocess[subprocess_pid] = subprocess_name
            subprocess.update(self.get_subprocess(process_graph, process_dict, node))
        return subprocess

    # ，，。
    def get_all_paths(self, process_graph):
        """
        ，。

        Args:
            process_graph (networkx.DiGraph): 。

        Returns:
            list: 。
        """
        all_paths = []
        # Find all source nodes (nodes with in-degree 0)
        source_nodes = [node for node in process_graph.nodes if process_graph.in_degree(node) == 0]
        
        # If there's an edge from '0' to '1', add '1' as a source node
        if '1' in process_graph.nodes and ('0', '1') in process_graph.edges:
            if '1' not in source_nodes:
                source_nodes.append('1')
        
        for source in source_nodes:
            for target in process_graph.nodes:
                if source != target:  # Skip paths from a node to itself
                    for path in nx.all_simple_paths(process_graph, source=source, target=target):
                        if path[0] != "0":  # Check if the node itself is not "0"
                            all_paths.append((path, len(path)))
        
        all_paths.sort(key=lambda x: x[1], reverse=True)
        return all_paths

    def get_longest_path(self, process_graph):
        """
        。

        Args:
            process_graph (networkx.DiGraph): 。

        Returns:
            list: 。
        """
        try:
            return nx.dag_longest_path(process_graph)
        except nx.NetworkXError:
            return []

    def get_name_by_pid(self, process_dict, pid):
        """ PID 。"""
        return process_dict.get(pid)

    def get_pid_by_name(self, process_dict, name):
        """ PID。"""
        for pid, pname in process_dict.items():
            if name in pname:
                return pid
        return None

    def kill_process_by_name(self, service_path, recursive_kill=True):
        service_pid = set()
        process_dict = self.get_process_dict()
        service_name = os.path.basename(service_path)
        for pid, ps in process_dict.items():
            if service_path in ps:
                service_pid.add(pid)
            elif service_name in ps:
                service_pid.add(pid)

        if recursive_kill:  # check ppid, kill watchdog process
            watchdog_pid = set()
            for pid in service_pid:
                ppid = self.get_ppid(pid)
                if ppid and ppid != "1" and ppid != "0":
                    watchdog_pid.add(ppid)
            service_pid.update(watchdog_pid)

        if len(service_pid) == 0:
            print('not found pid', service_path)
        else:
            self.kill_process_by_pid(service_pid)

    def kill_process_by_pid(self, pid_set: set):
        if len(pid_set) > 0:
            cmd = "kill -9 " + " ".join(pid_set)
            print("kill cmd", cmd)
            self.runner.exec(cmd, tty=True)

    # @staticmethod
    def _parse_ps_output(self, ps_output):
        process_dict = {}
        process_graph = nx.DiGraph()
        
        try:
            # if self.runner.category == "user":
            #     lines = ps_output.strip().split("\n")
            # else:
            #     lines = ps_output.strip().split("\r\n")
            
            lines = ps_output.strip().split("\n")
            headers = lines[0].split()
            pid_idx = headers.index("PID")
            ppid_idx = headers.index("PPID")
            cmd_idx = headers.index("COMMAND")
    
            for line in lines[1:]:
                parts = line.split(maxsplit=2)
                pid = parts[pid_idx]
                ppid = parts[ppid_idx]
                command = parts[cmd_idx]
    
                if self.runner.category == "user":
                    if not command.startswith("/qemu"):  # firmwell process
                        continue
    
                command = _get_clean_process(command)
    
                process_dict[pid] = command
                process_graph.add_node(pid, name=command)
                if ppid != 0:
                    process_graph.add_edge(ppid, pid)
        except Exception as e:
            print(f"_parse_ps_output {e}")
            print(ps_output)

        return process_dict, process_graph

    # ，，，
    def print_process_tree(self):
        process_graph, process_dict = self.get_process_tree()
        print(self._print_process_tree(process_graph, process_dict, 1, '1'))

    def _print_process_tree(self, process_graph, process_dict, depth, pid):
        children, _ = self.get_children_and_parent(process_graph, pid)
        children_str = ''
        for child in children:
            children_str += self._print_process_tree(process_graph, process_dict, depth + 1, child)
        return f"{' ' * (depth * 4)}[{pid}]{process_dict[pid]}\n{children_str}"


class Runner:
    def __init__(self, category, filesystem):
        self.category = "system"
        self.filesystem = None
