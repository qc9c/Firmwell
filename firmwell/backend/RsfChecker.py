import os
import shutil
import subprocess
import time

exploits_list = "/routersploit/exploits.list"


class RsfChecker:
    def __init__(self, ip, port, user, passwd, hash, name, logpath):
        self.ip = ip
        self.port = port
        self.hash = hash
        self.user = user
        self.passwd = passwd
        self.logpath = logpath
        
        if "POD_NAME" in os.environ.keys():
            podname = os.environ.get("POD_NAME")
        else:
            podname = "POD_NAME"
        # self.stdout_file = f"/tmp/{podname}_{name}_{hash}.stdout"  # must end with .stdout
        self.stdout_file = f"/tmp/{name}.stdout"  # must end with .stdout
    
    def probe(self, exploit=None):
        print("running routersploit...")
        
        if exploit is None:
            with open(exploits_list) as fh:
                exploits = [n.strip() for n in fh.readlines()]
        else:
            exploits = [exploit]
        
        with open(self.stdout_file, 'a') as out:
            for p in ['80', '1900']:
                for e in exploits:
                    exploit_cmd = [
                        'python3',
                        # '/routersploit/routersploit_ghpatched/rsf.py',
                        '/routersploit/routersploit_gh/rsf.py',
                        '-a',
                        '-f', e,
                        '-t', f'{self.ip}',
                        '-p', p,
                        '-u', f'{self.user}',
                        '-w', f'{self.passwd}'
                    ]
                    
                    r = subprocess.run(exploit_cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                    time.sleep(5)
                    stdout = r.stdout.decode("utf-8", errors='ignore')
                    for line in stdout.splitlines():
                        print(line)
                        out.write(line + "\n")
                    # out.writelines(stdout.splitlines())
                    print("=" * 30)
        
        # subprocess.run(exploit_cmd, stdout=out, text=True)
    
    def post_probe(self, file_list_after_probe):
        with open(self.stdout_file, 'a') as out:
            for line in file_list_after_probe:
                out.write(line + "\n")
    
    def process_result(self, res_dir_path):
        data = set()
        new_data = set()
        
        # first time
        print("first time")
        if os.path.exists("/tmp/processed_data/vulnerable.csv"):
            with open("/tmp/processed_data/vulnerable.csv", 'r') as f:
                lines = f.readlines()
                data = set(lines[1:])
            print(data)

        
        working_directory = '/routersploit/routersploit_gh/routersploit-log-parser/'
        command = ['python3', 'parse-routersploit-logs.py', '-ld', '/tmp/']
        result = subprocess.run(command, cwd=working_directory, capture_output=True, text=True)
        
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        
        # second time
        print("second time")

        if os.path.exists("/tmp/processed_data/vulnerable.csv"):
            with open("/tmp/processed_data/vulnerable.csv", 'r') as f:
                lines = f.readlines()
                new_data = set(lines[1:])
                print(new_data)
                
        all_data = data.union(new_data)
        with open("/tmp/processed_data/vulnerable.csv", 'w') as f:
            f.write("Firmware ID,Name,Target IP,Target Port,Exploit name\n")
            for line in all_data:
                f.write(line)
                
        
        if not os.path.exists(res_dir_path):  # /shared/rsf/1
            os.mkdir(res_dir_path)
        
        processed_data = "/tmp/processed_data"
        if os.path.exists(processed_data):
            for i in os.listdir(processed_data):
                path = os.path.join(processed_data, i)
                shutil.copyfile(path, os.path.join(res_dir_path,
                                                   i))  # /tmp/processed_data/vulnerable.csv->/shared/rsf/1/vulnerable.csv
