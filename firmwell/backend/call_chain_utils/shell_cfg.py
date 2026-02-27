import time
import networkx as nx
from .shell_syntax_parser import BashParser, BasicBlock


class ShellCFGGenerator:

    def parse_shell_script(self, file_path):
        """
        Reads and parses a shell script file.
        Returns a list of parsed commands.
        """
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()

        parser = BashParser()
        commands = []
        for line in lines:
            line = line.strip()
            if line:  # Skip empty lines
                cmd = parser.parse(line)
                if cmd:
                    commands.append(cmd)
        return commands

    def identify_leaders(self, commands):
        """
        Identifies leaders for basic block formation in a shell script.
        Returns a list of leader indices.
        """
        leaders = set()
        for i, cmd in enumerate(commands):
            # The first statement is a leader
            if i == 0:
                leaders.add(i)
            else:
                # Statement that is the target of a control transfer (goto)
                if cmd.cmdType in ["IF", "ELIF", "ELSE", "FOR", "WHILE", "UNTIL", "CASE"]:
                    leaders.add(i)

                # Statement following a control transfer or its end statement
                previous_cmd = commands[i - 1]
                if previous_cmd.cmdType in ["IF", "ELIF", "ELSE", "FOR", "WHILE", "UNTIL", "CASE", "BREAK", "CONTINUE"]:
                    leaders.add(i)

                # Include end statements as leaders
                if cmd.cmdType in ["FI", "DONE", "ESAC"]:
                    leaders.add(i)

        return leaders

    def construct_basic_blocks(self, commands, leaders):
        """
        Constructs basic blocks from the commands and leaders.
        Returns a list of BasicBlock objects.
        """
        basic_blocks = []
        current_block = BasicBlock("Start", "GENERAL")
        for i, cmd in enumerate(commands):
            if i in leaders and current_block.cmdSet:
                basic_blocks.append(current_block)
                current_block = BasicBlock(cmd.cmd, cmd.cmdType)
            current_block.addContents(cmd)
        if current_block.cmdSet:
            basic_blocks.append(current_block)
        return basic_blocks

    def build_cfg(self, basic_blocks):
        """
        Builds the control flow graph from basic blocks using networkx.
        Handles control flow structures such as loops, conditionals, breaks, and continues.
        Returns a networkx DiGraph object representing the CFG.
        """
        cfg = nx.MultiDiGraph()
        stack = []

        # first, create all nodes
        for i, current_block in enumerate(basic_blocks):
            node_label = '\n'.join(f"{cmd.cmdString}" for cmd in current_block.cmdSet)
            cfg.add_node('s' + str(i), label=node_label)

        # then, add edges based on control flow
        for i, current_block in enumerate(basic_blocks):
            current_node = 's' + str(i)
            next_node = 's' + str(i + 1) if i + 1 < len(basic_blocks) else None

            if current_block.blockType in ["IF", "ELIF"]:
                if next_node:
                    cfg.add_edge(current_node, next_node)  # Link to next block (usually the next condition or else)
                stack.append((current_node, "IF"))

            elif current_block.blockType == "ELSE":
                if stack:
                    if_block, _ = stack.pop()
                    cfg.add_edge(if_block, current_node)  # Link from the last if/elif to else
                if next_node:
                    cfg.add_edge(current_node, next_node)
                stack.append((current_node, "ELSE"))

            elif current_block.blockType == "FI":
                while stack and stack[-1][1] in ["IF", "ELSE"]:
                    block, _ = stack.pop()
                    cfg.add_edge(block, current_node)  # Link from if/elif/else to fi
                if next_node:
                    cfg.add_edge(current_node, next_node)

            elif current_block.blockType in ["FOR", "WHILE", "UNTIL"]:
                if next_node:
                    cfg.add_edge(current_node, next_node)  # Link to the first block inside the loop
                stack.append((current_node, "LOOP"))

            elif current_block.blockType == "DONE":
                if stack:
                    loop_block, _ = stack.pop()
                    cfg.add_edge(loop_block, current_node)  # Loop back to the start of the loop
                if next_node:
                    cfg.add_edge(current_node, next_node)  # Link to the block after the loop

            elif current_block.blockType == "BREAK":
                # Find the nearest enclosing loop and link to the block after the loop
                for block, block_type in reversed(stack):
                    if block_type == "LOOP":
                        cfg.add_edge(current_node, 's' + str(basic_blocks.index(block) + 1))
                        break

            elif current_block.blockType == "CONTINUE":
                # Link to the start of the nearest enclosing loop
                for block, block_type in reversed(stack):
                    if block_type == "LOOP":
                        cfg.add_edge(current_node, block)
                        break

            elif current_block.blockType == "CASE":
                stack.append((current_node, "CASE"))

            elif current_block.blockType == "ESAC":
                if stack:
                    case_block, _ = stack.pop()
                    cfg.add_edge(case_block, current_node)  # Link from case to esac
                if next_node:
                    cfg.add_edge(current_node, next_node)

            # Handle FI, DONE, and ESAC as independent blocks
            elif current_block.blockType in ["FI", "DONE", "ESAC"]:
                if stack:
                    prev_block, _ = stack.pop()
                    cfg.add_edge(prev_block, current_node)
                if next_node:
                    cfg.add_edge(current_node, next_node)

            # Link to the next block for general cases
            else:
                if next_node and not stack:
                    cfg.add_edge(current_node, next_node)

        return cfg

    def generate_cfg(self, shell_script_path):
        """
        Generates a control flow graph for a given shell script.
        """
        start_time = time.time()
        cfg = None
        try:
            commands = self.parse_shell_script(shell_script_path)
            leaders = self.identify_leaders(commands)
            basic_blocks = self.construct_basic_blocks(commands, leaders)
            cfg = self.build_cfg(basic_blocks)

        except Exception as e:
            print(f"An error occurred: {e}")

        finally:
            end_time = time.time()
            duration = end_time - start_time
            return cfg, duration

    def get_all_callee(self, shell_script_path):
        """
        Generates all potential callee for a given shell script.
        """

        potential_callee = set()
        try:
            commands = self.parse_shell_script(shell_script_path)

            # instantiate variables
            """
            UHTTPD_BIN="/usr/sbin/uhttpd"
            $UHTTPD_BIN -h /www -r $REALM -x /cgi-bin -t 60 -p 0.0.0.0:80
            """

            # get all defined variables
            variable_dict = {}
            for node in commands:
                if node.cmdType == "SET":
                    variable_dict[node.cmd] = node.para

            # raplace variables
            for node in commands:
                if node.cmdType == "OTHER":
                    if "$" in node.cmd :
                        tmp_cmd = node.cmd.replace("$", "").replace("{", "").replace("}", "").replace("\"", "") # $UHTTPD_BIN or ${UHTTPD_BIN}
                        if tmp_cmd in variable_dict:
                            node.cmd = variable_dict[tmp_cmd]
                            
                    for i in range(len(node.para)):
                        if "$" in node.para[i]:
                            tmp_para = node.para[i].replace("$", "").replace("{", "").replace("}", "").replace("\"", "")
                            if tmp_para in variable_dict:
                                node.para[i] = variable_dict[tmp_para]

                    if not any(c.islower() for c in node.cmd): # "*)"
                        continue

                    if "\"" in node.cmd:
                        node.cmd = node.cmd.replace("\"", "")

                    # RBS50Y_V2.7.0.122
                    # service_start /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.con
                    if node.cmd.startswith("service_start"):
                        node.cmd = node.para[0]
                    
                    # CPE210_V3.20_2.2.5 Build2023021
                    # tdbrun /usr/bin/httpd &
                    if node.cmd.startswith("tdbrun"):
                        node.cmd = node.para[0]
                    
                    # M7450
                    # start-stop-daemon --start -x "$DAEMON" -- $OPTS
                    if node.cmd.startswith("start-stop-daemon"):
                        node.cmd = node.para[2]
                    
                    # RAX40-V1.0.5.104_1.0.1
                    # procd_set_param command lighttpd-angel -D -f "$file"
                    if node.cmd.startswith("procd_set_param"):
                        node.cmd = node.para[1]

                    # get callee
                    potential_callee.add(node.cmd) # some cmd may be meaningless str

        except Exception as e:
            print(f"An error occurred: {e}")

        return potential_callee

    def get_entry_node(self, cfg):
        for node in cfg.nodes():
            if cfg.in_degree(node) == 0:
                return node
        return None

    def get_exit_node(self, cfg):
        for node in cfg.nodes():
            if len(list(cfg.successors(node))) == 0:
                return node
        return None

    def get_node_by_str(self, cfg, str):
        """
        ('s0', {'label': '\nrealm="$(/bin/config get netbiosname)"\nuhttpd_bin="/usr/sbin/uhttpd"\npx5g_bin="/usr/sbin/px5g"\ncookie="$(/bin/config get t_cookie)"\nuhttpd_stop()\n{\nkill -9 $(pidof uhttpd)\n}\nuhttpd_start()\n{\n/sbin/artmtd -r region\n$uhttpd_bin -h /www -r $realm -x /cgi-bin -t 60 -p 0.0.0.0:80'})
        ('s1', {'label': 'if [ "x$cookie" != "x" ]; then'})
        ('s2', {'label': 'echo $cookie > /tmp/cookie\n/bin/config set t_cookie=""'})
        ('s3', {'label': 'fi\n}'})
        ('s4', {'label': 'case "$1" in'})
        ('s5', {'label': 'stop)\nuhttpd_stop\n;;\nstart)\nuhttpd_start\n;;\nrestart)\nuhttpd_stop\nuhttpd_start\n;;\n*)\nlogger -- "usage: $0 start|stop|restart"\n;;'})
        ('s6', {'label': 'esac'})
        """

        node_list = []
        for node in cfg.nodes(data=True):
            if str in node[1]['label']:
                node_list.append(node[0])
        return node_list

