import os
import time
import signal
import logging
import subprocess
import subprocess as sp
from subprocess import PIPE

logger = logging.getLogger(__name__)

class GhidraTool:
    def __init__(self, project_path, project_name, result_path, ghidra_script, headless_analyzer, timeout=300):
        self.project_path = project_path
        self.project_name = project_name
        self.analysis_path = result_path # result path
        self.ghidra_script = ghidra_script
        self.headless_analyzer = headless_analyzer
        self.timeout = timeout

        self.ghidra_process = None
        
    def get_arch(self, full_path):
        print("Checking binary at ", full_path)
        sp = subprocess.run(["file", full_path], stdout=PIPE, stderr=PIPE)
        outline = sp.stdout
        print("    - ", outline)

        if b"64-bit" in outline:
            if b" ARM" in outline and b" LSB" in outline:
                return "ARM:LE:64:default"
            elif b" x86-64" in outline:
                return "x86:LE:64:default"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "MIPS:BE:64:default"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "MIPS:LE:64:default"
        else:
            if b" ARM" in outline and b" MSB" in outline:
                # return "ARM:BE:32:v8"
                return None # auto decide
            elif b" ARM" in outline and b" LSB" in outline:
                # return "ARM:LE:32:v8"
                return None
            elif b" x86-64" in outline:
                return "x86:LE:32:default"
            elif b" 80386" in outline:
                return "x86:LE:32:default"
            elif b" MIPS" in outline and b" MSB" in outline:
                return "MIPS:BE:32:default"
            elif b" MIPS" in outline and b" LSB" in outline:
                return "MIPS:LE:32:default"
            # elif b" PowerPC" in outline:
            #     return "ppc"
        return None

    def _init_ghidra_proj(self, binary_path):
        # print("[debug] _init_ghidra_proj")
        # print("project_path", self.project_path)
        # print("project_name", self.project_name)
        # print("analysis_path", self.analysis_path)

        # print("initial ghidra proj")
        if not os.path.exists(self.analysis_path):
            os.mkdir(self.analysis_path)
            
        # check if the proj is generate
        # print("self.project_path", self.project_path)
        if not os.path.exists(self.project_path):
            os.mkdir(self.project_path)
        
        # preprocess
        # if not os.path.exists(f"{self.project_path}/{self.project_name}.rep"):
        cmd = [self.headless_analyzer,
               self.project_path,
               self.project_name,
               "-import",
               binary_path]

        arch = self.get_arch(binary_path)
        if arch:
            cmd += ["-processor", arch]
        else:
            pass # auto detect

        logger.info(f"Ghidra analyzing: {os.path.basename(binary_path)}")
        logger.debug(f"[ghidra cmd] ")
        logger.debug(f"{' '.join(cmd)}")

        with open('/tmp/ghidra.log', 'a') as log_file:
            sp.run(cmd,
                    stdout=log_file,
                    stderr=log_file,
                    check=False,
                    text=True)
            
                            # Print the last 10 lines of stdout
        with open('/tmp/ghidra.log', 'r') as log_file:
            lines = log_file.readlines()
            print("".join(lines[-10:]))

        print("initial ghidra proj end")
        
    def run(self, binary_path: str, target_str: str):
        """
        Run Ghidra analysis on the given binary file.
        """

        if not os.path.exists(binary_path):
            raise f"Binary file not found: {binary_path}"

        # preprocess
        self._init_ghidra_proj(binary_path)

        # run analysis
        cmd = [self.headless_analyzer,
               self.project_path,
               self.project_name,
               "-process",
               os.path.basename(binary_path),
               # "-J-Xmx1G", # 1GB memory
               "-noanalysis",
               "-postScript",
               self.ghidra_script,
               self.analysis_path,
               target_str
               ]
        
        env = os.environ.copy()  # Copy current environment
        env["JAVA_TOOL_OPTIONS"] = "-Xmx1G"
        
        
        print("[ghidra run cmd] ", " ".join(cmd))
        with open('/tmp/ghidra.log', 'w') as log_file:
            self.ghidra_process = subprocess.Popen(cmd, stdout=log_file, stderr=log_file ,env=env)

            try:
                self.ghidra_process.communicate(timeout=self.timeout)  # 600 seconds = 10 minutes
            except subprocess.TimeoutExpired:
                stdout, stderr = self.ghidra_process.communicate()
                print(stdout)
                print(stderr)
            finally:
                self.ghidra_process.kill()
                stdout, stderr = self.ghidra_process.communicate()
                print(stdout)
                print(stderr)

                # Print the last 10 lines of stdout
                with open('/tmp/ghidra.log', 'r') as log_file:
                    lines = log_file.readlines()
                    print("".join(lines[-10:]))
        
    def stop_ghidra_process(self):
        if self.is_ghidra_process_running():
            # print("Process is still running. Terminating it now.")
            try:
                os.kill(self.ghidra_process.pid, signal.SIGTERM)

                time.sleep(2)

                if self.ghidra_process.poll() is not None:
                    print("Process terminated successfully.")
                else:
                    print("Failed to terminate the process.")

                self.ghidra_process.stdout.close()
                self.ghidra_process.stderr.close()
            except ProcessLookupError:
                print("Process already terminated.")
            except Exception as e:
                print("Failed to terminate the process:", e)
        
    def is_ghidra_process_running(self):
        if self.ghidra_process is None:
            return False
        return self.ghidra_process.poll() is not None

