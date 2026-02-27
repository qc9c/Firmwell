import json
from pprint import pprint

class FixRecord:
    """
    ，。
    ，。
    """
    def __init__(self, name="unknown", brand="unknown", hash=""):
        """
        
        
        Args:
            name (str): 
            brand (str): 
            hash (str, optional): ，
        """
        self.name = name
        self.brand = brand
        self.hash = hash
        self.repairs = {}  # 
        self.current_round = 0  # 
        self.binary_counter = {}  # binary
    
    def set_round(self, round_num):
        """"""
        self.current_round = round_num
        return self.current_round
    
    def next_round(self):
        """，"""
        self.current_round += 1
        return self.current_round
    
    def add_fix_record(self, binary, operation, round_num=None):
        """

        
        Args:
            binary (str): 
            operation (dict): 
            round_num (int, optional): ，
        """
        # 
        round_to_use = round_num if round_num is not None else self.current_round
        
        # 
        if binary not in self.repairs:
            self.repairs[binary] = {}
            self.binary_counter[binary] = 0
        
        if round_to_use not in self.repairs[binary]:
            self.repairs[binary][round_to_use] = []
        
        # 
        self.repairs[binary][round_to_use].append(operation)
        self.binary_counter[binary] += 1
        
        self.current_round += 1 # 
        
        return True
    
    def get_fixes(self, binary=None, round_num=None):
        """
        
        
        Args:
            binary (str, optional): None
            round_num (int, optional): None
            
        Returns:
            dict: 
        """
        if binary is None:
            if round_num is None:
                return self.repairs
            else:
                # 
                result = {}
                for bin_name, rounds in self.repairs.items():
                    if round_num in rounds:
                        result[bin_name] = {round_num: rounds[round_num]}
                return result
        else:
            if binary not in self.repairs:
                return {}
            
            if round_num is None:
                return {binary: self.repairs[binary]}
            else:
                if round_num in self.repairs[binary]:
                    return {binary: {round_num: self.repairs[binary][round_num]}}
                else:
                    return {}
    
    def get_statistics(self):
        """
        
        
        Returns:
            dict: 
        """
        stats = {
            "name": self.name,
            "brand": self.brand,
            "hash": self.hash,
            "total_rounds": self.current_round,
            "total_fixes": sum(self.binary_counter.values()),
            "binaries_fixed": len(self.binary_counter),
            "fixes_per_binary": self.binary_counter
        }
        return stats
    
    def save_to_json(self, file_path):
        """
        JSON
        
        Args:
            file_path (str): 
        """
        data = {
            "name": self.name,
            "brand": self.brand,
            "hash": self.hash,
            "total_rounds": self.current_round,
            "repairs": self.repairs
        }
        
        with open(f"{file_path}.json", 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
    
    def list_all_repairs(self):
        """"""
        print(f"Firmware: {self.name} ({self.brand})")
        print(f"Total rounds: {self.current_round}")
        print(f"Total fixes: {sum(self.binary_counter.values())}")
        
        for binary, rounds in self.repairs.items():
            print(f"\nBinary: {binary} ({self.binary_counter[binary]} fixes)")
            for round_num, operations in sorted(rounds.items()):
                print(f"  Round {round_num}:")
                for i, op in enumerate(operations):
                    print(f"    {i+1}. {op}")