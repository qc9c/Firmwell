import os

target_list = "/shared/extracted_fs_res/targets.list"
extracted_fs_res = "/shared/extracted_fs_res"
extracted_fs = "/shared/extracted_fs"


# get all hashes in extracted_fs
extracted_fs_hashes = set()
for root, dirs, files in os.walk(extracted_fs):
    for file in files:
        if file.endswith(".sqsh"):
            extracted_fs_hashes.add(file.split(".")[0])
            
# print(extracted_fs_hashes)
print(f"len(extracted_fs_hashes): {len(extracted_fs_hashes)}")


# read target list
iid_hash = dict()
with open(target_list, 'r') as f:
    for index,i in enumerate(f.readlines(), start=1):
        line = i.strip()
        sha256sum = line.split(",")[-1]
        iid_hash[index] = sha256sum
        
# print(iid_hash)


not_found = set()
for index, sha256sum in iid_hash.items():
    if sha256sum not in extracted_fs_hashes:
        if os.path.exists(os.path.join(extracted_fs_res, "logs", str(index))):
            print(f"index: {index}, sha256sum: {sha256sum}")
        # print(f"index: {index}, sha256sum: {sha256sum}")
            not_found.add(index)

print(not_found)
print(f"len(not_found): {len(not_found)}")

