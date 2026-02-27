import re
import time
import subprocess
from collections import defaultdict

from pprint import pprint

import ipaddress
import docker
import logging

logger = logging.getLogger(__name__)


def check_ip_domain_mapping(ip, domain, file_path):
    with open(file_path, 'r') as file:
        for line in file:
            # 
            parts = line.strip().split()
            # IP
            if ip in parts and domain in parts:
                return True
    return False


# hostsIP
def add_ip_domain_mapping(ip, domain, file_path):
    with open(file_path, 'a') as file:
        file.write(f"{ip} {domain}\n")


HOSTS = {
    "belkin": ["router"],
    "netgear": ["www.mywifiext.net", "www.routerlogin.net"],
    "tenda": ["tendawifi.com"],
    "tplink": ["tplinkrepeater.net"]
}


class NetworkUtil:
    def __init__(self, runner):
        self.runner = runner
    
    @staticmethod
    def set_netdev_name(src, dst):
        cmd = f'bash -c "ip link set {src} down;ip link set {src} name {dst};ip link set {dst} up"'
        return cmd
    
    @staticmethod
    def get_interfaces_ips(ip_addr_output, _filter=True):
        """
        input: the output of linux cmd `ip addr` or ExecResult from docker exec_run
        output: {'lo': ['127.0.0.1'], 'eth0': ['10.0.2.15', '192.168.0.1'], 'eth1': ['192.168.1.1']}
        """
        # Handle ExecResult from docker exec_run
        if hasattr(ip_addr_output, 'output'):
            ip_addr_output = ip_addr_output.output.decode('utf-8')
        elif isinstance(ip_addr_output, bytes):
            ip_addr_output = ip_addr_output.decode('utf-8')
            
        interfaces_data = re.split(r'\n(?=\d+:)', ip_addr_output)
        results = []
        for interface_data in interfaces_data:
            interface_match = re.search(r'^\d+:\s+([^:]+):', interface_data)
            if interface_match:
                interface_name = interface_match.group(1)
                if "@" in interface_name:
                    interface_name = interface_name.split("@")[0]
                if _filter and (interface_name in ["lo", "tunl0", "sit0"]):
                    continue
                state_match = re.search(r'state\s+(\w+)', interface_data)
                state = state_match.group(1) if state_match else ""
                ips = re.findall(r'\binet\s+([\d.]+)', interface_data)
                results.append((interface_name, ips))
        network_info = dict()
        for interface, ips in results:
            network_info[interface] = ips
        return network_info
    
    # @staticmethod
    # def clean_host_netdev(prefix=""):
    #     """Clean up network devices on the host with the given prefix."""
    #     import subprocess
    #     if prefix:
    #         cmd = f"ip link | grep {prefix} | cut -d: -f2 | awk '{{print $1}}'"
    #         output = subprocess.check_output(cmd, shell=True).decode('utf-8')
    #         for line in output.strip().split('\n'):
    #             if line:
    #                 subprocess.run(f"ip link del {line}", shell=True)
    #     else:
    #         logger.warning("No prefix provided for cleaning network devices")
    
    @staticmethod
    def get_ip_by_dev(network_info, interface_name):
        """Get the first IP address of an interface from network_info dictionary."""
        if interface_name in network_info and network_info[interface_name]:
            return network_info[interface_name][0]
        return None
    
    @staticmethod
    def get_dev_by_ip(network_info, ip_address):
        """Find the device name that has the given IP address."""
        for interface, ips in network_info.items():
            if ip_address in ips:
                return interface
        return None
    
    @staticmethod
    def get_network_interfaces(ip_link_output):
        """Parse output of 'ip link' command to get list of interfaces."""
        interfaces = []
        for line in ip_link_output.splitlines():
            if ': ' in line:
                interface = line.split(': ')[1].split('@')[0]
                interfaces.append(interface)
        return interfaces
    
    @staticmethod
    def get_netstat(netstat_output):
        """Parse netstat output to get bound IP addresses and ports."""
        result = []
        for line in netstat_output.splitlines():
            if 'LISTEN' in line or 'ESTABLISHED' in line:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[3]
                    if ':' in local_addr:
                        ip, port = local_addr.rsplit(':', 1)
                        if ip == '*':
                            ip = '0.0.0.0'
                        result.append(('tcp', ip, port))
        return result
    
    def create_network_device(self, device_name, ip_address):
        """
        Create a network device in the Docker container with the specified name and IP address.

        Args:
            device_name (str): Name for the network device
            ip_address (str): IP address to assign to the device

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.runner or not hasattr(self.runner, 'container'):
            logger.error("Environment or container not initialized")
            return False
        
        # Check if the device already exists with the correct IP
        current_network_info = self.get_network_info()
        if device_name in current_network_info and ip_address in current_network_info[device_name]:
            logger.info(f"Device {device_name} with IP {ip_address} already exists")
            return True
        
        # Check if the IP is already used on a different interface
        for interface, ips in current_network_info.items():
            if ip_address in ips:
                logger.debug(f"IP {ip_address} already exists on interface {interface}, removing it")
                self.runner.exec(f"ip addr del {ip_address}/24 dev {interface}")
        
        # Remove the device if it already exists
        if device_name in current_network_info:
            logger.debug(f"Device {device_name} already exists, removing it")
            self.runner.exec(f"ip link del {device_name}")
        
        # Special handling for bridge interfaces with labels (e.g., br0:1)
        if ':' in device_name:
            base_name = device_name.split(':')[0]
            label = device_name
            
            # Create bridge if it doesn't exist
            self.runner.exec(f"ip link add name {base_name} type bridge")
            self.runner.exec(f"ip link set {base_name} up")
            
            # Add IP with label
            self.runner.exec(f"ip addr add {ip_address}/24 dev {base_name} label {label}")
            
            # Verify the change
            time.sleep(1)
            updated_network_info = self.get_network_info()
            if base_name in updated_network_info and ip_address in updated_network_info[base_name]:
                logger.info(f"Successfully created bridge device {device_name} with IP {ip_address}")
                return True
            else:
                logger.error(f"Failed to verify bridge device {device_name} with IP {ip_address}")
                return False
        
        # Regular network device creation through Docker
        try:
            client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to connect to Docker: {e}")
            return False
        
        # Calculate subnet from IP
        subnet = self._get_subnet_from_ip(ip_address)
        gateway = self._get_gateway_from_subnet(subnet, [ip_address])
        
        logger.info(f"Creating network device {device_name} with IP {ip_address} (subnet {subnet}, gateway {gateway})")
        
        # Check if network with this subnet already exists and delete it
        existing_network = self._find_network_by_subnet(client, subnet)
        if existing_network:
            logger.debug(f"Found existing network with subnet {subnet}, deleting...")
            self._delete_network(client, existing_network)
        
        # Create new network
        network_name = f"firmwell_{device_name}"
        network = self._create_network(client, network_name, subnet, gateway)
        if not network:
            logger.error(f"Failed to create network {network_name}")
            return False
        
        # Connect container to network with specific IP
        if not self._connect_container_to_network(client, network, self.runner.container.id, ip_address):
            logger.error(f"Failed to connect container to network {network_name}")
            return False
        
        # Wait for network changes to take effect
        time.sleep(2)
        
        # Get current network info
        current_network_info = self.get_network_info()
        logger.debug(f"Current network info: {current_network_info}")
        
        # Find the new interface that appeared
        new_interface = None
        for interface, ips in current_network_info.items():
            if ip_address in ips:
                new_interface = interface
                break
        
        if not new_interface:
            logger.error(f"Could not find interface with IP {ip_address}")
            return False
        
        # If the interface name already matches, we're done
        if new_interface == device_name:
            logger.info(f"Interface already named correctly: {device_name}")
            return True
        
        # delete dev if exist
        self.runner.exec(f"ip link del {device_name}")
        
        # Rename interface to match requested device name
        logger.debug(f"Renaming interface {new_interface} to {device_name}")
        rename_cmd = self.set_netdev_name(new_interface, device_name)
        self.runner.exec(rename_cmd)
        
        # Verify the change
        time.sleep(1)
        updated_network_info = self.get_network_info()
        if device_name in updated_network_info and ip_address in updated_network_info[device_name]:
            logger.info(f"Successfully created network device {device_name} with IP {ip_address}")
            return True
        else:
            logger.error(f"Failed to verify network device {device_name} with IP {ip_address}")
            return False
    
    def _get_subnet_from_ip(self, ip_address):
        """Calculate /24 subnet from IP address."""
        try:
            ip_parts = ip_address.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        except Exception as e:
            logger.error(f"Error calculating subnet: {e}")
            return f"192.168.100.0/24"  # Fallback
    
    # def _get_gateway_from_subnet(self, subnet):
    #     """Calculate gateway address (first IP in subnet)."""
    #     try:
    #         base = subnet.split('/')[0]
    #         ip_parts = base.split('.')
    #         return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
    #     except Exception as e:
    #         logger.error(f"Error calculating gateway: {e}")
    #         return "192.168.100.1"  # Fallback
    
    def _get_gateway_from_subnet(self, subnet, reserved_urls):
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
    
    def _find_network_by_subnet(self, client, subnet):
        """Find Docker network by subnet."""
        try:
            networks = client.networks.list()
            for network in networks:
                configs = network.attrs['IPAM']['Config']
                for config in configs:
                    if config.get('Subnet') == subnet:
                        return network
        except Exception as e:
            logger.error(f"Error finding network by subnet: {e}")
        return None
    
    def _delete_network(self, client, network):
        """Delete Docker network."""
        try:
            # First disconnect all containers
            containers = client.containers.list()
            for container in containers:
                try:
                    network.disconnect(container)
                except Exception as e:
                    logger.debug(f"Error disconnecting container {container.id} from network: {e}")
            
            # Then remove the network
            network.remove()
            logger.debug(f"Deleted network {network.name}")
            return True
        except Exception as e:
            logger.error(f"Error deleting network: {e}")
            return False
    
    def _create_network(self, client, network_name, subnet, gateway):
        """Create Docker network with specified subnet and gateway."""
        try:
            # Create IPAM pool configuration
            ipam_pool = docker.types.IPAMPool(subnet=subnet, gateway=gateway)
            ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
            
            # Create the network
            network = client.networks.create(
                name=network_name,
                driver="bridge",
                ipam=ipam_config
            )
            logger.debug(f"Created network {network_name} with subnet {subnet}")
            return network
        except Exception as e:
            logger.error(f"Error creating network: {e}")
            return None
    
    def _connect_container_to_network(self, client, network, container_id, ip_address):
        """Connect container to network with specific IP."""
        try:
            container = client.containers.get(container_id)
            network.connect(container, ipv4_address=ip_address)
            logger.debug(f"Connected container {container_id} to network {network.name} with IP {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Error connecting container to network: {e}")
            return False
    
    @staticmethod
    def get_ip_prefix(ip_address: str) -> str:
        """
        192.168.1.1 -> 192.168.1
        """
        return ".".join(ip_address.split(".")[0:-1])
    
    @staticmethod
    def get_ip_subfix(ip_address: str) -> str:
        """
        192.168.1.254 -> 254
        """
        return ip_address.split(".")[-1]
    
    # @staticmethod
    # def get_ip_by_dev(network_info, netdev):
    #     try:
    #         for dev, ip_list in network_info.items():
    #             ip = ip_list[0]
    #             if dev == netdev:
    #                 return ip
    #     except Exception as e:
    #         print("error get_netdev_ip", e)
    #     return None
    #
    # @staticmethod
    # def get_dev_by_ip(network_info, target_ip):
    #     try:
    #         for dev, ip_list in network_info.items():
    #             ip = ip_list[0]
    #             if ip == target_ip:
    #                 return dev
    #     except Exception as e:
    #         print("error get_netdev_ip", e)
    #     return None
    
    # @staticmethod
    # def clean_host_netdev(netdev):
    #     host_net_dev = subprocess.check_output(["ip", "addr"]).decode()
    #     host_network_info = NetworkUtil.get_interfaces_ips(host_net_dev)
    #     for dev, _ in host_network_info.items():
    #         if dev.startswith(netdev):
    #             subprocess.run(['ip', 'link', 'del', dev])
    
    @staticmethod
    def get_netstat(netstat_output: str) -> str:
        """
        input: text of netstat -antu
        # Active Internet connections (servers and established)
        # Proto Recv-Q Send-Q Local Address           Foreign Address         State
        # tcp        0      0 127.0.0.11:38931        0.0.0.0:*               LISTEN
        # tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN
        # udp        0      0 127.0.0.11:59364        0.0.0.0:*
        # udp        0      0 0.0.0.0:19541           0.0.0.0:*

        output: [['tcp', '127.0.0.11', '38931'], ['tcp', '0.0.0.0', '23'], ['udp', '127.0.0.11', '59364'], ['udp', '0.0.0.0', '19541']]
        """
        
        netstat_info = list()
        
        # 
        # ：(tcp/udp)，(IP:Port)，LISTENUDP
        pattern = re.compile(r"(\btcp\b|\budp\b)\s+\d+\s+\d+\s+([\d\.]+):(\d+)\s+\S*\s*(LISTEN)?")
        
        # 
        matches = pattern.findall(netstat_output)
        
        # ，
        for match in matches:
            proto, ip, port, state = match
            # UDP，LISTEN，
            if proto == 'udp' or state == 'LISTEN':
                # print(f"Type: {proto}, IP: {ip}, Port: {port}")
                netstat_info.append([proto, ip, port])
        
        # ipv6
        for line in netstat_output.splitlines():
            if ":::80" in line:
                netstat_info.append(["tcp", "0.0.0.0", "80"])
            if ":::53" in line:
                netstat_info.append(["tcp", "0.0.0.0", "53"])
            if ":::1900" in line:
                netstat_info.append(["tcp", "0.0.0.0", "1900"])
        
        return netstat_info
    
    @staticmethod
    def port_is_bind(netstat_info, target_port) -> bool:
        """
        input: [['tcp', '127.0.0.11', '38931'], ['tcp', '0.0.0.0', '23'], ['udp', '127.0.0.11', '59364'], ['udp', '0.0.0.0', '19541']]
        """
        for proto, ip, port in netstat_info:
            if target_port == port:
                return True
        return False
    
    @staticmethod
    def get_bind_port_from_qemu(bind_record):
        port_ip = {}
        ports = ['80']
        
        try:
            for line in bind_record:
                line = line.strip()
                if "[IP-PORT]" in line and "IPV6" not in line:
                    data = line.replace("[IP-PORT] : ", "")
                    ip, port = data.split(":")
                    port_ip[port] = ip
                elif "[IP-PORT] IPV6: " in line:
                    data = line.replace("[IP-PORT] IPV6: ", "")
                    ip, port = data.split(":")
                    port_ip[port] = ip
            
            if "8080" in port_ip.keys():
                ports.append("8080")
            if "8000" in port_ip.keys():
                ports.append("8000")
        
        except Exception as e:
            print("[get_ip_port]")
            print(e)
        
        return ports
    
    def get_network_info(self):
        return self.get_interfaces_ips(self.runner.exec("ip addr"))
    
    def get_guest_netdev(self) -> list:
        return self.get_network_interfaces(self.runner.exec("ip link"))
    
    def config_network(self, network_config):
        """
        Configure network interfaces based on network_config dictionary
        Each key is an interface name, and its value is the IP to assign
        Returns the updated network info and interface commands executed
        """
        network_info = self.get_network_info()
        interface_cmds = []
        
        print("network_config")
        pprint(network_config)
        
        print("network_info")
        pprint(network_info)
        
        # some time can't get eth0, use potenial to config network direct to avoid this issue
        if len(network_config) != len(network_info) and "eth0" in network_info and "eth5" in network_info:  # k8 bug
            self.runner.exec("ip link del eth0")  # in pod eth0 can be deleted
            net_dev = self.get_guest_netdev()
            print("fix k8 netdev bug")
            pprint(net_dev)
        
        # if self.runner.category == "user":
        #     assert len(network_config) == len(network_info)  # 0108 host net
        
        # Rename interfaces if necessary
        for interface in network_config.keys():
            if interface not in network_info:
                # Find an existing interface that is not in the target config
                for existing_interface in network_info.keys():
                    if existing_interface not in network_config:
                        # cmd = f"ip link set {existing_interface} name {interface}"
                        cmd = self.set_netdev_name(existing_interface, interface)
                        self.runner.exec(cmd)
                        interface_cmds.append(cmd)
                        network_info[interface] = network_info.pop(existing_interface)
                        break
        
        # Now process the network config as a dictionary
        for interface, ip in network_config.items():
            # Configure IP for interface
            ip = ip[0]
            subnet = self.get_subnet_mask(ip)
            cmd = f"ip addr add {ip}/{subnet} dev {interface}"
            self.runner.exec(cmd)
            interface_cmds.append(cmd)
            
            # Set interface up
            cmd = f"ip link set {interface} up"
            self.runner.exec(cmd)
            interface_cmds.append(cmd)
            
            # Update network_info
            if interface not in network_info:
                network_info[interface] = []
            if ip not in network_info[interface]:
                network_info[interface].append(ip)
        
        return network_info
    
    def get_subnet_mask(self, ip, default="24"):
        """Return subnet mask for the given IP (default: /24)"""
        # Could be extended to use netmask from an external configuration
        return default
    
    def reconfig_network(self, network_info):
        """Reconfigure network interfaces to match the given network_info"""
        if self.runner.category == "system":
            print("TODO, reconfig network in system")
            return
        
        current_network_info = self.get_network_info()
        
        # First check if any interfaces in network_info don't exist in current_network_info
        # and need to be recreated
        for interface, target_ips in network_info.items():
            if interface == 'lo':
                continue
            
            if interface not in current_network_info:
                logger.info(f"Interface {interface} not found in current network, recreating...")
                if target_ips:  # Only recreate if there are IPs to assign
                    self.create_network_device(interface, target_ips[0])
                continue
        
        # Remove IPs that aren't in the target configuration
        for interface, current_ips in current_network_info.items():
            if interface == 'lo':
                continue
            
            # Remove excess IPs
            target_ips = network_info.get(interface, [])
            for ip in current_ips:
                if ip not in target_ips:
                    cmd = f"ip addr flush dev {interface}"
                    self.runner.exec(cmd)
            
            # Remove excess interfaces
            if interface not in network_info:
                cmd = f"ip link del {interface}"
                self.runner.exec(cmd)
            
            # Check connectivity for existing interfaces
            for ip in target_ips:
                try:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                    if result.returncode != 0:
                        logger.info(f"Ping failed for {ip}, recreating network device")
                        self.runner.exec(f"ip link del {interface}")
                        self.create_network_device(interface, ip)
                except Exception as e:
                    logger.error(f"Error checking connectivity for {ip}: {e}")
                    self.runner.exec(f"ip link del {interface}")
                    self.create_network_device(interface, ip)
        
        # Configure remaining interfaces
        for interface, target_ips in network_info.items():
            if interface == 'lo':
                continue
            
            # Make sure interface exists and is up
            if interface not in current_network_info:
                logger.info(f"Interface {interface} still missing after cleanup, recreating...")
                if target_ips:
                    self.create_network_device(interface, target_ips[0])
                continue
            
            cmd = f"ip link set {interface} up"
            self.runner.exec(cmd)
            
            # Add IPs that aren't already configured
            current_ips = current_network_info.get(interface, [])
            for ip in target_ips:
                if ip not in current_ips:
                    cmd = f"ip addr add {ip}/24 dev {interface}"
                    self.runner.exec(cmd)
    
    # @staticmethod
    # def create_network_device2(docker_manager, device_name, ip_address):
    #     """
    #     Create a network device in the Docker container with the specified name and IP address.
    #     Static version that takes docker_manager as parameter instead of using self.runner.

    #     Args:
    #         docker_manager: Docker container manager instance
    #         device_name (str): Name for the network device
    #         ip_address (str): IP address to assign to the device

    #     Returns:
    #         bool: True if successful, False otherwise
    #     """
    #     if not docker_manager or not hasattr(docker_manager, 'container'):
    #         logger.error("Environment or container not initialized")
    #         return False
        
    #     # Check if the device already exists with the correct IP
    #     result = docker_manager.container.exec_run("ip addr")
    #     current_network_info = NetworkUtil.get_interfaces_ips(result.output)
        
    #     if device_name in current_network_info and ip_address in current_network_info[device_name]:
    #         logger.info(f"Device {device_name} with IP {ip_address} already exists")
    #         return True
        
    #     # Check if the IP is already used on a different interface
    #     for interface, ips in current_network_info.items():
    #         if ip_address in ips:
    #             logger.debug(f"IP {ip_address} already exists on interface {interface}, removing it")
    #             docker_manager.container.exec_run(f"ip addr del {ip_address}/24 dev {interface}")
        
    #     # Remove the device if it already exists
    #     if device_name in current_network_info:
    #         logger.debug(f"Device {device_name} already exists, removing it")
    #         docker_manager.container.exec_run(f"ip link del {device_name}")
        
    #     # Special handling for bridge interfaces with labels (e.g., br0:1)
    #     if ':' in device_name:
    #         base_name = device_name.split(':')[0]
    #         label = device_name
            
    #         # Create bridge if it doesn't exist
    #         docker_manager.container.exec_run(f"ip link add name {base_name} type bridge")
    #         docker_manager.container.exec_run(f"ip link set {base_name} up")
            
    #         # Add IP with label
    #         docker_manager.container.exec_run(f"ip addr add {ip_address}/24 dev {base_name} label {label}")
            
    #         # Verify the change
    #         time.sleep(1)
    #         result = docker_manager.container.exec_run("ip addr")
    #         updated_network_info = NetworkUtil.get_interfaces_ips(result.output)
    #         if base_name in updated_network_info and ip_address in updated_network_info[base_name]:
    #             logger.info(f"Successfully created bridge device {device_name} with IP {ip_address}")
    #             return True
    #         else:
    #             logger.error(f"Failed to verify bridge device {device_name} with IP {ip_address}")
    #             return False
        
    #     # Regular network device creation through Docker
    #     try:
    #         client = docker.from_env()
    #     except Exception as e:
    #         logger.error(f"Failed to connect to Docker: {e}")
    #         return False
        
    #     # Calculate subnet from IP
    #     subnet = NetworkUtil._get_subnet_from_ip(ip_address)
    #     gateway = NetworkUtil._get_gateway_from_subnet(subnet, [ip_address])
        
    #     logger.info(f"Creating network device {device_name} with IP {ip_address} (subnet {subnet}, gateway {gateway})")
        
    #     # Check if network with this subnet already exists and delete it
    #     existing_network = NetworkUtil._find_network_by_subnet(client, subnet)
    #     if existing_network:
    #         logger.debug(f"Found existing network with subnet {subnet}, deleting...")
    #         NetworkUtil._delete_network(client, existing_network)
        
    #     # Create new network
    #     network_name = f"firmwell_{device_name}"
    #     network = NetworkUtil._create_network(client, network_name, subnet, gateway)
    #     if not network:
    #         logger.error(f"Failed to create network {network_name}")
    #         return False
        
    #     # Connect container to network with specific IP
    #     if not NetworkUtil._connect_container_to_network(client, network, docker_manager.container.id, ip_address):
    #         logger.error(f"Failed to connect container to network {network_name}")
    #         return False
        
    #     # Wait for network changes to take effect
    #     time.sleep(2)
        
    #     # Get current network info
    #     result = docker_manager.container.exec_run("ip addr")
    #     current_network_info = NetworkUtil.get_interfaces_ips(result.output)
    #     logger.debug(f"Current network info: {current_network_info}")
        
    #     # Find the new interface that appeared
    #     new_interface = None
    #     for interface, ips in current_network_info.items():
    #         if ip_address in ips:
    #             new_interface = interface
    #             break
        
    #     if not new_interface:
    #         logger.error(f"Could not find interface with IP {ip_address}")
    #         return False
        
    #     # If the interface name already matches, we're done
    #     if new_interface == device_name:
    #         logger.info(f"Interface already named correctly: {device_name}")
    #         return True
        
    #     # delete dev if exist
    #     docker_manager.container.exec_run(f"ip link del {device_name}")
        
    #     # Rename interface to match requested device name
    #     logger.debug(f"Renaming interface {new_interface} to {device_name}")
    #     rename_cmd = NetworkUtil.set_netdev_name(new_interface, device_name)
    #     docker_manager.container.exec_run(rename_cmd)
        
    #     # Verify the change
    #     time.sleep(1)
    #     result = docker_manager.container.exec_run("ip addr")
    #     updated_network_info = NetworkUtil.get_interfaces_ips(result.output)
    #     if device_name in updated_network_info and ip_address in updated_network_info[device_name]:
    #         logger.info(f"Successfully created network device {device_name} with IP {ip_address}")
    #         return True
    #     else:
    #         logger.error(f"Failed to verify network device {device_name} with IP {ip_address}")
    #         return False