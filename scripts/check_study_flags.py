#!/usr/bin/env python3
import os
import re
import yaml

STUDY_DIR = "/home/sanchit/DVAD/STUDY"
VARS_FILE = "/home/sanchit/DVAD/ansible/roles/flag_factory/vars/main.yml"

def get_study_flags():
    flags = set()
    regex = re.compile(r'[A-Z]{2,4}-\d{3}')
    for root, _, files in os.walk(STUDY_DIR):
        for file in files:
            if file.endswith('.md'):
                with open(os.path.join(root, file), 'r') as f:
                    content = f.read()
                    matches = regex.findall(content)
                    flags.update(matches)
    return flags

def get_manifest_flags():
    flags = set()
    with open(VARS_FILE, 'r') as f:
        data = yaml.safe_load(f)
        manifest = data.get('flag_manifest', [])
        for item in manifest:
            flags.add(item['id'])
    return flags

study_flags = get_study_flags()
manifest_flags = get_manifest_flags()

print("========================================")
print(f"Total Unique Flags in STUDY/ Guide: {len(study_flags)}")
print(f"Total Unique Flags in Ansible Manifest: {len(manifest_flags)}")
print("========================================\n")

missing_in_manifest = study_flags - manifest_flags
if missing_in_manifest:
    print("[-] Flags mentioned in STUDY/ but MISSING from Lab Deployment:")
    for flag in sorted(missing_in_manifest):
        print(f"    - {flag}")
else:
    print("[+] Perfect! All flags in STUDY/ are implemented in the Lab.")

print("\n")

missing_in_study = manifest_flags - study_flags
if missing_in_study:
    print("[-] Flags deployed in Lab but MISSING from STUDY/ Guide:")
    for flag in sorted(missing_in_study):
        print(f"    - {flag}")
else:
    print("[+] Perfect! All lab flags have documentation in STUDY/.")
