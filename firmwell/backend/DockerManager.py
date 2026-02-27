import os
import shutil
import time
import docker
import docker.errors
import ipaddress
import subprocess
from docker.errors import *
from multiprocessing import Process
from .RedisLock import RedisLock
from firmwell.backend.utils.NetworkUtil import NetworkUtil
from docker.types import Mount
from firmwell.backend.Utils import Files
from firmwell.backend.RehostingEnv import RehostingEnv

import logging
import subprocess as sp

logger = logging.getLogger(__name__)
logging.getLogger("docker").setLevel(logging.WARNING)

docker_logger = logging.getLogger("docker")
docker_logger.setLevel(logging.WARNING)

# Remove existing docker logger handlers
for handler in docker_logger.handlers:
    docker_logger.removeHandler(handler)

# Suppress urllib3 logging (used by docker HTTP client)
urllib3_logger = logging.getLogger("urllib3")
urllib3_logger.setLevel(logging.WARNING)
for handler in urllib3_logger.handlers:
    urllib3_logger.removeHandler(handler)

DOCKER_FS = "fs"
INSTALL_CMD = "apt-get update && apt-get -y install vim curl zsh"

from typing import List

class QemuUserRunner(RehostingEnv):
    def __init__(self, tmp_dir, tmp_fs_path, _hash, debug, name, args, filesystem):
        super().__init__("user", filesystem)
        self.tmp_dir = tmp_dir
        self.tmp_fs_path = tmp_fs_path
        self.hash = _hash
        self.debug = debug
        self.name = name
        self.args = args

        self.img = None
        self.container = None
        self.client = None
        self.network_bridges = None
        self.check_process = None
        self.exec_fail_count = 0

    def get_gateway(self, subnet, reserved_urls):
        """Find an available gateway IP in the given subnet, avoiding reserved addresses."""
        baseurl = subnet.rsplit(".", maxsplit=1)[0]
        gateway = ""
        for count in range(1, 255):
            is_reserved = False
            gateway = "%s.%d" % (baseurl, count)
            for reserved in reserved_urls:
                if gateway in reserved:
                    is_reserved = True
                    break
            if is_reserved:
                continue
            break
        return gateway
    # def setup_bridges(self, network_config):
    #     """
    #     Setup bridges for each network configuration
    #     network_config: dict mapping interface names to IPs
    #     """
    #     networks = {}
    #
    #     for interface, ip in network_config.items():
    #         if interface == 'lo':
    #             continue
    #
    #         # Calculate subnet from IP
    #         try:
    #             subnet = f"{ip.rsplit('.', 1)[0]}.0/24"
    #             gateway = f"{ip.rsplit('.', 1)[0]}.1"
    #         except:
    #             print(f"Invalid IP format: {ip}")
    #             continue
    #
    #         # Create Docker network if it doesn't exist
    #         network_name = f"firmwell_{interface}"
    #
    #         try:
    #             # Check if network exists
    #             self.client.networks.get(network_name)
    #             print(f"Network {network_name} already exists")
    #         except docker.errors.NotFound:
    #             # Create network with the specified subnet
    #             print(f"Creating network {network_name} with subnet {subnet}")
    #             self.client.networks.create(
    #                 name=network_name,
    #                 driver="bridge",
    #                 ipam=docker.types.IPAMConfig(
    #                     pool_configs=[docker.types.IPAMPool(subnet=subnet, gateway=gateway)]
    #                 )
    #             )
    #
    #         networks[interface] = {
    #             "network_name": network_name,
    #             "subnet": subnet,
    #             "gateway": gateway,
    #             "ip": ip
    #         }
    #
    #     return networks
    
    # def setup_bridges(self, urls):
    def setup_bridges(self, network_config):
        count = 0
        bridges = dict()
        bridge_map = []
        existing_networks = []
        docker_networks = self.client.networks.list()

        # Clean up any networks that might have the same hash prefix
        self.cleanup_existing_networks()

        # First collect all existing network names to avoid ambiguity
        existing_network_names = set()
        for network in docker_networks:
            existing_network_names.add(network.name)

        for dnet in docker_networks:
            configs = dnet.attrs['IPAM']['Config']
            for conf in configs:
                subnet = conf['Subnet']
                subnet_addr = subnet.split("/")[0]
                if subnet_addr not in existing_networks:
                    existing_networks.append(subnet_addr)

        # Process each interface in network_config
        for interface, ips in network_config.items():
            if interface == 'lo':
                continue

            if not ips:  # Empty IP list
                # Create bridge without IP configuration
                # Find a bridge name that doesn't exist yet
                bridge_name = self.generate_unique_bridge_name(count, existing_network_names)
                existing_network_names.add(bridge_name)  # Add to our set of known names
                
                print(f"    - creating docker bridge {bridge_name} without IP configuration for interface {interface}")
                b = self.client.networks.create(bridge_name, driver="bridge")
                bridges[b] = None
                count += 1
                continue

            # Process interface with IPs
            for ip in ips:
                subnet_string = "%s/255.255.255.0" % ip
                try:
                    subnet = str(ipaddress.ip_interface(subnet_string).network)
                    subnet_addr = subnet.split("/")[0]
                    if subnet_addr in existing_networks:
                        print("    - skipping existing subnet", subnet_addr)
                        continue
                    
                    gateway = self.get_gateway(subnet, [ip])
                    ipam_pool = docker.types.IPAMPool(subnet=subnet, gateway=gateway)
                    ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
                    
                    # Find a bridge name that doesn't exist yet
                    bridge_name = self.generate_unique_bridge_name(count, existing_network_names)
                    existing_network_names.add(bridge_name)  # Add to our set of known names
                    
                    print(f"    - creating docker bridge {bridge_name} on subnet {subnet} for interface {interface} via gateway {gateway}")

                    b = self.client.networks.create(bridge_name, driver="bridge", ipam=ipam_config)
                    bridges[b] = ip
                    existing_networks.append(subnet_addr)
                    bridge_map.append((ip, subnet, gateway))
                    count += 1
                except Exception as e:
                    print(e)
                    continue

        return bridges, bridge_map

    def generate_unique_bridge_name(self, count, existing_network_names):
        """Generate a unique bridge name that doesn't already exist"""
        base_name = f"{self.hash}ghbridge{count}"
        
        # If the base name is already unique, return it
        if base_name not in existing_network_names:
            return base_name
        
        # Otherwise, append a suffix until we get a unique name
        suffix = 1
        while f"{base_name}_{suffix}" in existing_network_names:
            suffix += 1
        
        return f"{base_name}_{suffix}"

    def setup_bridges_ipv6(self, urls):
        count = 0
        bridges = dict()
        bridge_map = []
        existing_networks = []
        docker_networks = self.client.networks.list()

        # First collect all existing network names to avoid ambiguity
        existing_network_names = set()
        for network in docker_networks:
            existing_network_names.add(network.name)

        for dnet in docker_networks:
            configs = dnet.attrs['IPAM']['Config']
            for conf in configs:
                subnet = conf['Subnet']
                subnet_addr = subnet.split("/")[0]
                if subnet_addr not in existing_networks:
                    existing_networks.append(subnet_addr)
                
        for url in urls:
            subnet_string = "%s/255.255.255.0" % url
            try:
                subnet = str(ipaddress.ip_interface(subnet_string).network)
                subnet_addr = subnet.split("/")[0]
                if subnet_addr in existing_networks:
                    print("    - skipping existing subnet", subnet_addr)
                    continue

                ipv6_subnet = f"2001:db8:{count}::/64"
                ipv6_gateway = f"2001:db8:{count}::1"

                gateway = self.get_gateway(subnet, urls)
                ipam_pool_v4 = docker.types.IPAMPool(subnet=subnet, gateway=gateway)
                ipam_pool_v6 = docker.types.IPAMPool(subnet=ipv6_subnet, gateway=ipv6_gateway)

                ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool_v4, ipam_pool_v6])

                # Find a bridge name that doesn't exist yet
                bridge_name = self.generate_unique_bridge_name(count, existing_network_names)
                existing_network_names.add(bridge_name)  # Add to our set of known names
                
                print(f"    - creating docker bridge {bridge_name} on subnet {subnet} for url {url} via gateway {gateway}")

                b = self.client.networks.create(bridge_name, driver="bridge", ipam=ipam_config)
                bridges[b] = [url, ipv6_subnet]
                existing_networks.append(subnet_addr)
                bridge_map.append((url, subnet, gateway, ipv6_subnet, ipv6_gateway))
                count += 1
            except Exception as e:
                print(e)
                continue
        return bridges, bridge_map

    def make_docker_compose(self, fs_path, bridge_map, ports=[], mac=""):
        docker_compose_path = os.path.join(fs_path, "docker-compose.yml")
        print("Writing docker-compose file to ", docker_compose_path)
        with open(docker_compose_path, "w+", newline="\n") as dcFile:
            dcFile.write("version: \"2.2\"\n\n")
            dcFile.write("services:\n")
            dcFile.write("  gh_rehosted:\n")
            dcFile.write("    build: .\n")
            dcFile.write("    privileged: false\n")
            dcFile.write("    cap_add:\n")
            dcFile.write("      - NET_ADMIN\n")
            dcFile.write("      - CAP_SYS_CHROOT\n")
            dcFile.write("      - SYS_ADMIN\n")
            dcFile.write("    devices:\n")
            dcFile.write("      - /dev/urandom:/fs/dev/urandom\n")
            dcFile.write("      - /dev/random:/fs/dev/random\n")


            if len(mac) > 0:
                dcFile.write("    mac_address: \"%s\"\n" % mac)
            if len(bridge_map) > 0:
                dcFile.write("    networks:\n")
                count = 0
                for targeturl, subnet, gateway in bridge_map:
                    dcFile.write("      %sghbridge%d:\n" % (self.hash, count))
                    dcFile.write("        ipv4_address: %s\n" % targeturl)
                    count += 1

            # ports
            dcFile.write("    ports:\n")
            for port in ports:
                dcFile.write("      - %s:%s/tcp\n" % (port, port))
                dcFile.write("      - %s:%s/udp\n" % (port, port))
                dcFile.write("      - %d:%d/tcp\n" % (1900, 1900))
                dcFile.write("      - %d:%d/udp\n" % (1900, 1900))

                dcFile.write("      - %d:%d/tcp\n" % (81, 81))
                dcFile.write("      - %d:%d/udp\n" % (81, 81))

                dcFile.write("      - %d:%d/tcp\n" % (8000, 8000))
                dcFile.write("      - %d:%d/udp\n" % (8000, 8000))

                dcFile.write("      - %d:%d/tcp\n" % (8080, 8080))
                dcFile.write("      - %d:%d/udp\n" % (8080, 8080))

                dcFile.write("      - %d:%d/tcp\n" % (8181, 8181))
                dcFile.write("      - %d:%d/udp\n" % (8181, 8181))

                dcFile.write("      - %d:%d/tcp\n" % (9090, 9090))
                dcFile.write("      - %d:%d/udp\n" % (9090, 9090))

                dcFile.write("      - %d:%d/tcp\n" % (9091, 9091))
                dcFile.write("      - %d:%d/udp\n" % (9091, 9091))


            if len(bridge_map) > 0:
                dcFile.write("\n")
                dcFile.write("networks:\n")
                count = 0
                for targeturl, subnet, gateway in bridge_map:
                    dcFile.write("   %sghbridge%d:\n" % (self.hash, count))
                    dcFile.write("     driver: bridge\n")
                    dcFile.write("     ipam:\n")
                    dcFile.write("       config:\n")
                    dcFile.write("       - subnet: %s\n" % subnet)
                    dcFile.write("         gateway: %s\n" % gateway)
                    count += 1
        dcFile.close()

    def waiting_is_running(self):
        print("waiting_container_running")
        max_times = 10
        try:
            while True:
                if not self.debug:
                    time.sleep(30)
                else:
                    time.sleep(5)
                status = self.client.containers.get(self.container.id).status
                if status == 'running':
                    print("containers running")
                    return True
                if status == 'exited':
                    print("containers exited")
                    return False
                max_times -= 1
                if max_times == 0:
                    print(("containers not run"))
                    break
        except docker.errors.APIError:
            return False


    def start_rehosting_env(self, dest, ports, network_config, mac, enable_basic_procfs, use_ipv6):
        """Build the Docker image, create networks, and start the rehosting container."""
        dockerfilePath = os.path.join(self.tmp_dir, "Dockerfile")
        if os.path.exists(dockerfilePath):
            Files.rm_file(dockerfilePath)

        sleep_file = os.path.join(self.tmp_fs_path, "sleep.sh")
        if not os.path.exists(sleep_file):
            with open(sleep_file, 'w') as f:
                f.write("#!/bin/sh\n")
                f.write("while true; do sleep 10000; done\n")
                f.flush()
            Files.chmod_exe(sleep_file)

        with open(dockerfilePath, "w") as dockerFile:
            SCRATCH_COMMANDS = "FROM 32bit/ubuntu:16.04\nCOPY fs /%s\n" % DOCKER_FS

            dockerFile.write(SCRATCH_COMMANDS)

            wrap_init_src = os.path.join("/fw/firmwell/greenhouse_files", "wrap_init")
            wrap_init_dst = os.path.join(self.tmp_fs_path, "wrap_init")
            if os.path.exists(wrap_init_src):
                print(f"copy {wrap_init_src} to {wrap_init_dst}")
                shutil.copy(wrap_init_src, wrap_init_dst)
            dockerFile.write("\nCMD [\"/fs/wrap_init\"]\n")
            # else:
            #     dockerFile.write("\nCMD [\"/fs/sleep.sh\"]\n")

        dockerFile.close()

        tools = ["ip", "ifconfig", "brctl", "vconfig"]
        for tool in tools:
            for path in Files.find_file_paths(self.tmp_fs_path, tool):
                if "greenhouse" in path:
                    continue
                os.rename(path, f"{path}.bak")

                link_path = path.replace(self.tmp_fs_path, "")
                command = ["chroot", self.tmp_fs_path, "/greenhouse/busybox", "ln", "-s", "/greenhouse/busybox",
                           link_path]
                subprocess.run(command, check=True)

                # Create symbolic links
                # subprocess.run(["chroot", fs_path, "ln", "-s", "/greenhouse/busybox", "/bin/ip"])
                # subprocess.run(["chroot", fs_path, "ln", "-s", "/greenhouse/busybox", "/usr/sbin/brctl"])
                # subprocess.run(["chroot", fs_path, "ln", "-s", "/greenhouse/busybox", "/sbin/ifconfig"])

        build_success = False
        # support dind
        print(f"POD_NAME" in os.environ.keys())
        if "POD_NAME" in os.environ.keys():
            os.environ['DOCKER_HOST'] = 'tcp://127.0.0.1:2375'
        # if "DOCKER_HOST" in os.environ.keys():
        #     os.environ['DOCKER_HOST'] = 'tcp://127.0.0.1:2375'

        try:
            self.client = docker.from_env(timeout=360)
        except Exception as e:
            print("Error while connecting to Docker:", e)
            exit(1)
        
        # TODO: dont do this in host machine
        try:
            result = self.client.api.prune_networks()
            print("Unused networks have been pruned.")
            print(result)
            if result and "NetworksDeleted" in result:
                print("Deleted networks:", result["NetworksDeleted"])
            else:
                print("No unused networks were deleted.")
        except Exception as e:
            print("Error while pruning networks:", e)

        
        lock = RedisLock("my_global_lock", f"[{self.name}] build_docker", enable_redis_lock=self.args.enable_redis_lock)
        for i in range(0, 3):
            try:
                if not build_success:
                    try:
                        img, jsonlog = self.client.images.build(path=self.tmp_dir, rm=True)
                        self.img = img
                        build_success = True
                    finally:
                        pass
            except BuildError as e:
                print(e)
                print("    - rate limited, backing off and retrying in 60s")
                time.sleep(60)
                continue

        self.client.networks.prune()
        # if not use_ipv6:
        #     network_bridges, bridge_map = self.setup_bridges(potential_urls)
        # else:
        #     network_bridges, bridge_map = self.setup_bridges_ipv6(potential_urls)
        network_bridges, bridge_map = self.setup_bridges(network_config)
        self.make_docker_compose(dest, bridge_map, ports, mac)

        print("Creating new temp container...")

        """
        this will mount the procfs of container "dockerd", rather than the real procfs of rehosting env,
        mount the real procfs will make it writable and modifies the value in host machine, it's very dangerous,
        since the container dockerd must run in privileged, the rootless dind is not enough for rehosting,
        """
        # if enable_basic_procfs:
        #     mounts = [
        #         # Mount(target="/dev", source="/dev", type="bind"),
        #         Mount(target="/fs/proc", source="/proc", type="bind", read_only=True),
        #         # Mount(target="/fs/sys", source="/sys", type="bind", read_only=True),
        #     ]
        # else:
        #     mounts = []


        ulimits = [docker.types.Ulimit(name='core', soft=0, hard=0)]
        if self.debug:
            ulimits = []
        
        working_dir = "/"
        if self.args.working_dirs != "/":
            working_dir = self.args.working_dirs
        
        # --privileged flag (default: False) controls Docker container privilege mode.
        # WARNING: when enabled, the host's procfs is mounted and writes from containers
        # can directly modify host /proc. Use only inside a VM.
        if self.args.privileged is True:
            privileged = True
            container = self.client.containers.create(img, detach=True,
                                                  privileged=privileged,
                                                  mem_limit="2G",
                                                  ulimits=ulimits,
                                                  tty=True,
                                                  working_dir=working_dir,
                                                  )
        else:
            if lock.acquire():
                try:
                    detach = True
                    privileged = False
                    cap_add = ["NET_ADMIN", "CAP_SYS_CHROOT", "CAP_SYS_ADMIN"]
                    tty = True
                    security_opt = []

                    if self.debug:
                        cap_add.append("SYS_PTRACE")
                        security_opt = ["seccomp=unconfined", "apparmor=unconfined"]

                    print("Docker start args:")
                    print("detach", detach)
                    print("privileged", privileged)
                    print("cap_add", cap_add)
                    print("security_opt", security_opt)
                    print("tty", tty)
                    container = self.client.containers.create(img, detach=detach,
                                                          mem_limit="3G",
                                                          ulimits=ulimits,
                                                          privileged=privileged,
                                                          cap_add=cap_add,
                                                          security_opt=security_opt,
                                                          tty=tty,
                                                          working_dir=working_dir,
                                                          pid_mode="private",
                                                          )
                finally:
                    lock.release()


        print("Creating new temp done")

        # disconnect from default bridge network, '172.17.0.0/16'
        docker0_bridge = self.client.networks.get("bridge")
        docker0_bridge.disconnect(container)

        # add own networks
        if not use_ipv6:
            for network, container_url in network_bridges.items():
                try:
                    network.connect(container, ipv4_address=container_url)
                except Exception as e:
                    print(e)

        else:
            for network, container_url in network_bridges.items():
                try:
                    ipv4, ipv6 = container_url
                    network.connect(container, ipv4_address=ipv4, ipv6_address=ipv6)
                except Exception as e:
                    print(e)

        container.start()
        self.container = container
        self.network_bridges = network_bridges
        self.container_id = container.id

        status = self.waiting_is_running()

        self.check_container_status()

        return status

    def check_container_status(self):
        pass

    def check_fork_bomb_daemon(self):
        def defuse():
            max_pid = 500
            while True:
                print("check_fork_bomb")
                time.sleep(30)
                live_process_num = self.exec_run_lock('bash -c "ps -e | wc -l"') # , noprint=True
                live_process_num = int(live_process_num.strip())
                if live_process_num > max_pid:
                    print("!\n"*50)
                    print("find_fork_bomb")
                    self.remove_docker()
                    exit(1)

        self.check_process = Process(target=defuse, args=())
        self.check_process.start()


    def kill_all_pid_in_docker(self):
        self.exec_run_lock('sh -c "kill -9 -1"', detach=True)
        if not self.debug:
            time.sleep(10)
        else:
            time.sleep(5)
            
    def kill_docker_container(self):
        try:
            self.container.kill()
            print(f"Sent kill signal to container {self.container}.")
            
            for i in range(0, 60):
                self.container.reload()
                if self.container.status == 'exited':
                    print(f"Container {self.container} has been killed and exited.")
                    break
                time.sleep(1)
        except docker.errors.NotFound:
            print(f"Container {self.container} not found.")
        except docker.errors.APIError as e:
            print(f"An error occurred: {e}")
            
    def remove_docker_network(self):
        try:
            for network in self.network_bridges.keys():
                network.disconnect(self.container)
                network.remove()
            self.container.remove(force=True)
            time.sleep(5)
            print("Removing image...")
            self.client.images.remove(self.img.id, force=True)
        except Exception as e:
            print(e)

    def remove_docker(self):
        print("Stopping Container...")
        self.kill_docker_container()
        self.remove_docker_network()

        try:
            sp = subprocess.run("docker system prune --force", shell=True)
            print(sp)
            time.sleep(5)
        except Exception as e:
            print(e)

    def docker_cp_to_container(self, src, dst):
        if "POD_NAME" in os.environ.keys():
            os.environ['DOCKER_HOST'] = 'tcp://127.0.0.1:2375'
        print(f"[docker cp] {src} -> {self.container.id}:{dst}")

        cmd = ["docker", "cp", f"{src}", f"{self.container.id}:{dst}"]
        res = subprocess.run(
            cmd,
            capture_output=True, text=True, check=False
        )

        time.sleep(3)
        print(res.stdout)
        print(res.stderr)
        print(f"res.returncode = {res.returncode}")

    def docker_cp_to_host(self, src, dst):
        if "POD_NAME" in os.environ.keys():
            os.environ['DOCKER_HOST'] = 'tcp://127.0.0.1:2375'
        print(f"[docker cp] {self.container.id}:{src} -> {dst}")
        res = subprocess.run(
            ["docker", "cp", f"{self.container.id}:{src}", dst],
            capture_output=True, text=True, check=False
        )
        time.sleep(3)
        print(res.stdout)
        print(res.stderr)
        print(f"res.returncode = {res.returncode}")

    def file_exist_in_container(self, file):
        path = os.path.join(DOCKER_FS, file)
        if "No such file or directory" in self.exec_run_lock(f"cat {path}"):
            return False
        return True

    def read_file(self, file):
        path = os.path.join(DOCKER_FS, file)
        data = self.exec_run_lock(f"cat {path}", noprint=True)
        return data

    def rm_file(self, file):
        path = os.path.join(DOCKER_FS, file)
        self.exec_run_lock(f"rm {path}")

    def get_guest_netdev(self) -> list:
        return NetworkUtil.get_network_interfaces(self.exec_run_lock("ip link"))

    def exec(self, cmd: str, **kwargs):
        """
        Execute a command in the Docker container with appropriate adaptations for QemuUser mode.
        
        Args:
            cmd (str): Command to execute
            **kwargs: Additional arguments (detach, noprint)
            
        Returns:
            str: Command output
        """
        detach = kwargs.get('detach', False)
        noprint = kwargs.get('noprint', False)

        # Replace bash -c with sh -c for better compatibility
        if cmd.startswith("bash -c "):
            cmd = cmd.replace("bash -c ", "sh -c ", 1)
        
        return self.exec_run_lock(cmd, detach=detach, noprint=noprint)
    
    def exec_run_lock(self, cmd: str, **kwargs):
        """Execute command with lock (existing implementation)"""
        detach = False
        noprint = False
        if "detach" in kwargs.keys():
            detach = kwargs["detach"]
        if "noprint" in kwargs.keys():
            noprint = kwargs["noprint"]
            kwargs.pop("noprint")
        
        lock = RedisLock("my_global_lock", f"[{self.name}] {cmd}", enable_redis_lock=self.args.enable_redis_lock)
        
        if lock.acquire():
            try:
                if not noprint:
                    print(f"[exec_run_lock] {cmd}")
                if detach:
                    exit_code, output = self.container.exec_run(cmd, **kwargs)
                else:
                    exit_code, output = self.container.exec_run(cmd, **kwargs)
                if not detach:
                    output = output.decode("utf-8", errors='ignore')
            finally:
                lock.release()
        else:
            print("Failed to acquire lock.")
            return ""
        
        if detach:
            time.sleep(1)
        
        return output
    
    def execute(self, command: str) -> sp.CompletedProcess:
        """Executes the |command| in the container and returns the output."""
        logger.debug('Executing command (%s) in %s: ', command, self.container_id)
        execute_command_in_container = [
            'docker', 'exec', self.container_id, '/bin/bash', '-c', command
        ]
        process = self._execute_command(execute_command_in_container, True)
        process.args = command
        return process
    
    def _execute_command(self,
                         command: List[str],
                         in_container: bool = False) -> sp.CompletedProcess:
        """Executes the |command| in subprocess and log output."""
        result = sp.run(command,
                        stdout=sp.PIPE,
                        stderr=sp.PIPE,
                        check=False,
                        text=True)
        
        if in_container:
            logger.debug(
                'Executing command (%s) in container %s: Return code %d. STDOUT: %s, '
                'STDERR: %s', command, self.container_id, result.returncode,
                result.stdout, result.stderr)
        else:
            logger.debug(
                'Executing command (%s): Return code %d. STDOUT: %s, '
                'STDERR: %s', command, result.returncode, result.stdout,
                result.stderr)
        return result


    def get_network_info(self):
        return NetworkUtil.get_interfaces_ips(self.exec_run_lock("ip addr"))

    def cleanup_existing_networks(self):
        """Remove any existing networks that match our hash pattern"""
        networks = self.client.networks.list()
        pattern = f"{self.hash}ghbridge"
        
        for network in networks:
            if network.name.startswith(pattern):
                try:
                    print(f"Removing existing network: {network.name}")
                    network.remove()
                except Exception as e:
                    print(f"Failed to remove network {network.name}: {e}")


