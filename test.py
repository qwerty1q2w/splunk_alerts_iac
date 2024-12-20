import os
import sys
import yaml
from glob import glob

def find_yaml_files():
    patterns = ['alerts/*/alert.yaml', 'defaults.yaml']
    files = []
    for pattern in patterns:
        matched_files = glob(pattern)
        if not matched_files:
            print(f"Warning: No files found for pattern '{pattern}'.")
        files.extend(matched_files)
    return files

def validate_yaml(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            yaml.safe_load(f)
        print(f"[OK] {file_path} - valid.")
        return True
    except yaml.YAMLError as e:
        print(f"[ERROR] {file_path} - invalid YAML.")
        print(f"Reason: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] {file_path} - error reading file.")
        print(f"Reason: {e}")
        return False

def main():
    yaml_files = find_yaml_files()
    if not yaml_files:
        print("No YAML files were found for validation.")
        sys.exit(1)

    all_valid = True
    for file in yaml_files:
        if not validate_yaml(file):
            all_valid = False

    if all_valid:
        print("All YAML files are valid.")
        sys.exit(0)
    else:
        print("Errors were found in some YAML files.")
        sys.exit(1)

if __name__ == "__main__":
    main()
