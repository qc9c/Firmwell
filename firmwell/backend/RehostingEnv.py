from abc import ABC, abstractmethod
from firmwell.backend.utils.ProcessUtil import ProcessUtil
from firmwell.backend.utils.NetworkUtil import NetworkUtil

class RehostingEnv(ABC):
    def __init__(self, category, filesystem):
        self.filesystem = filesystem
        self.category = category  # user or system

    @abstractmethod
    def start_rehosting_env(self, dest=None, ports=None, potential_urls=None, mac=None, enable_basic_procfs=False, use_ipv6=False):
        """Start the rehosting environment"""
        pass

    @abstractmethod
    def exec(self, cmd, **kwargs):
        """Execute a command in the rehosting environment"""
        pass
    
    @abstractmethod
    def read_file(self, path):
        """Read a file from the environment"""
        pass
    
    @abstractmethod
    def docker_cp_to_container(self, src, dest):
        """Copy a file to the environment"""
        pass
    
    @abstractmethod
    def docker_cp_to_host(self, src, dest):
        """Copy a file from the environment to the host"""
        pass
    
    @abstractmethod
    def file_exist_in_container(self, path):
        """Check if a file exists in the environment"""
        pass
    
    @abstractmethod
    def remove_docker(self):
        """Clean up and remove the environment"""
        pass
    
    @abstractmethod
    def check_container_status(self):
        """Check the status of the container/VM"""
        pass