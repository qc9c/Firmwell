import json
from pprint import pprint

class FixRecord:
    def __init__(self):
        self.repairs = {}

    def add_fix_record(self, binary, round, operation):
        """"""
        if binary not in self.repairs:
            self.repairs[binary] = {}
        if round not in self.repairs[binary]:
            self.repairs[binary][round] = []
        self.repairs[binary][round].append(operation)

    def get_records(self, binary, round):
        """binaryround"""
        return self.repairs.get(binary, {}).get(round, [])

    def list_all_repairs(self):
        """"""
        for binary, rounds in self.repairs.items():
            print(f"Binary: {binary}")
            for round, operations in rounds.items():
                print(f"  Round: {round}, Operations: {', '.join(operations)}")

    # def modify_operation(self, binary, round, index, new_operation):
    #     """"""
    #     if binary in self.repairs and round in self.repairs[binary] and len(self.repairs[binary][round]) > index:
    #         self.repairs[binary][round][index] = new_operation
    #
    # def delete_operation(self, binary, round, index):
    #     """"""
    #     if binary in self.repairs and round in self.repairs[binary] and len(self.repairs[binary][round]) > index:
    #         del self.repairs[binary][round][index]

    def save_to_json(self, file_path):
        """JSON"""
        with open(f"{file_path}.json", 'w', encoding='utf-8') as f:
            pprint(self.repairs)
            json.dump(self.repairs, f, ensure_ascii=False, indent=4)
