import argparse
import logging
import os
import sys
import json
import yaml
import configparser
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Identifies unused configuration parameters in configuration files.")
    parser.add_argument("config_files", nargs="+", help="Path(s) to the configuration file(s).")
    parser.add_argument("--reference_files", nargs="+", help="Path(s) to reference files (source code or usage files) in which parameter use is searched. Required: use is measured against these files, never against the configuration files themselves, because a parameter name always appears in its own definition.", default=[])
    parser.add_argument("--exclude", nargs="+", help="List of parameters to exclude from analysis (e.g., common parameters).", default=[])
    parser.add_argument("--check_comments", action="store_true", help="Include comments in the reference files in the analysis to detect potentially used parameters", default=False)
    parser.add_argument("--disable_security_checks", action="store_true", help="Disable security checks like hardcoded secrets detection (use with caution!).", default=False)
    return parser.parse_args()

def load_config(file_path):
    """
    Loads a configuration file based on its extension (YAML, JSON, INI).

    Args:
        file_path (str): Path to the configuration file.

    Returns:
        dict: A dictionary containing the configuration data. Returns None if loading fails.
    """
    try:
        _, file_extension = os.path.splitext(file_path)
        file_extension = file_extension.lower()

        with open(file_path, 'r') as f:
            if file_extension == '.yaml' or file_extension == '.yml':
                try:
                    return yaml.safe_load(f)
                except yaml.YAMLError as e:
                    logging.error(f"Error loading YAML file '{file_path}': {e}")
                    return None
            elif file_extension == '.json':
                try:
                    return json.load(f)
                except json.JSONDecodeError as e:
                    logging.error(f"Error loading JSON file '{file_path}': {e}")
                    return None
            elif file_extension == '.ini':
                config = configparser.ConfigParser()
                config.read(file_path)
                return {s: dict(config.items(s)) for s in config.sections()}
            else:
                logging.error(f"Unsupported file type: {file_extension} for file '{file_path}'. Supported types are YAML, JSON, and INI.")
                return None
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading '{file_path}': {e}")
        return None

def find_used_parameters(reference_files, check_comments=False):
    """
    Finds used parameters by searching for them in the provided
    reference files, which are separate from the configuration files
    under analysis.

    Args:
        reference_files (list): A list of file paths to reference files.
        check_comments (bool):  Whether to check inside comments for potentially used parameters

    Returns:
        set: A set of used parameters.
    """
    used_parameters = set()

    for file_path in reference_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:  # Explicitly specify encoding
                content = f.read()
                # Basic regex for identifying parameter usage (can be improved)
                # This looks for parameter names surrounded by spaces, brackets, quotes, etc.
                # The regex is designed to be flexible and catch common ways parameters are used.
                if check_comments:
                    # Look inside comments too
                    pattern = re.compile(r"(?<![a-zA-Z0-9_-])([a-zA-Z0-9_-]+)(?![a-zA-Z0-9_-])", re.MULTILINE) # Improved regex
                else:
                    pattern = re.compile(r"(?<![a-zA-Z0-9_-])([a-zA-Z0-9_-]+)(?![a-zA-Z0-9_-])(?![\s#]*#)", re.MULTILINE) # Improved regex

                matches = pattern.findall(content)
                used_parameters.update(matches)

        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
        except Exception as e:
            logging.error(f"Error reading file '{file_path}': {e}")

    return used_parameters

SENSITIVE_NAME_PARTS = ("password", "secret", "token", "api_key", "apikey", "private_key", "access_key")


def looks_like_secret_value(value):
    """
    The stated value rule for the security check: a value counts as a
    possible hardcoded secret only when it is a non-empty string that
    is not a plain number. Plain numeric values never warn, whatever
    the parameter is called.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    try:
        float(text)
        return False
    except ValueError:
        return True


def find_unused_parameters(config_files, exclude_parameters=None, check_comments=False, disable_security_checks=False, reference_files=None):
    """
    Identifies unused configuration parameters in the given configuration files.
    A parameter counts as used when its name appears in the reference
    files; the configuration files themselves are never searched for
    use, because a name always appears in its own definition there.

    Args:
        config_files (list): A list of paths to configuration files.
        exclude_parameters (list): A list of parameters to exclude from the analysis.
        check_comments (bool): Whether to also check comments in the reference files.
        disable_security_checks (bool):  Disable security checks like hardcoded secrets detection.
        reference_files (list): A list of paths to reference files.

    Returns:
        A tuple (unused_parameters_by_file, failed_files, total_parameters).
        failed_files lists the named files that could not be loaded;
        total_parameters counts every parameter collected.
    """
    unused_parameters_by_file = {}
    failed_files = []
    total_parameters = 0
    used_parameters = find_used_parameters(reference_files or [], check_comments)

    for file_path in config_files:
        config_data = load_config(file_path)
        if config_data is None:
            failed_files.append(file_path)
            continue

        all_parameters = set()
        parameter_values = {}
        def collect_parameters(data, prefix=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    name = prefix + str(key)  # Keys are not always strings; convert, never crash
                    all_parameters.add(name)
                    parameter_values[name] = value
                    collect_parameters(value, name + ".")  # Recursive call for nested dictionaries

        collect_parameters(config_data)
        total_parameters += len(all_parameters)

        if exclude_parameters:
            excluded_set = set(exclude_parameters)
            all_parameters = all_parameters.difference(excluded_set)

        unused = sorted(all_parameters.difference(used_parameters))

        if not disable_security_checks:
            # Security check over every collected parameter, not only
            # the unused ones: a sensitive sounding name warns only
            # when its value also passes the value rule above. Names
            # only are logged; values are never printed.
            potentially_sensitive = [
                p for p in sorted(all_parameters)
                if any(part in p.lower() for part in SENSITIVE_NAME_PARTS)
                and looks_like_secret_value(parameter_values.get(p))
            ]
            if potentially_sensitive:
                logging.warning(f"Parameters with sensitive names and non-numeric string values in '{file_path}': {potentially_sensitive}. Review carefully for hardcoded secrets!")

        unused_parameters_by_file[file_path] = unused

    return unused_parameters_by_file, failed_files, total_parameters

def main():
    """
    Main function to execute the unused configuration parameter finder.
    """
    args = setup_argparse()

    # Input validation: Check if files exist
    for file_path in args.config_files:
        if not os.path.exists(file_path):
            logging.error(f"File '{file_path}' does not exist.")
            sys.exit(1)
    for file_path in args.reference_files:
        if not os.path.exists(file_path):
            logging.error(f"Reference file '{file_path}' does not exist.")
            sys.exit(1)

    if not args.reference_files:
        logging.error(
            "No reference files supplied: whether a parameter is used cannot be determined "
            "from the configuration files themselves, because a name always appears in its "
            "own definition. Pass --reference_files with the source or usage files to search. "
            "Nothing was analysed."
        )
        sys.exit(1)

    unused_parameters, failed_files, total_parameters = find_unused_parameters(
        args.config_files, args.exclude, args.check_comments,
        args.disable_security_checks, reference_files=args.reference_files,
    )

    if failed_files:
        for file_path in failed_files:
            logging.error(f"File '{file_path}' could not be loaded or held no configuration mapping; the analysis is incomplete.")
        sys.exit(1)

    if total_parameters == 0:
        print("No parameters were found in the named configuration files. Nothing was analysed.")
        sys.exit(1)

    any_unused = any(unused_list for unused_list in unused_parameters.values())
    if any_unused:
        print("Unused parameters found:")
        for file_path, unused_list in unused_parameters.items():
            if unused_list:
                print(f"  File: {file_path}")
                for param in unused_list:
                    print(f"    - {param}")
        sys.exit(1)

    print("No unused parameters found.")
    sys.exit(0)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a single YAML file against reference (source or usage) files:
#    python3 main.py config.yaml --reference_files app.py
#
# 2. Analyze multiple configuration files (YAML, JSON, INI):
#    python3 main.py config.yaml config.json config.ini --reference_files app.py notes.txt
#
# 3. Exclude specific parameters from the analysis:
#    python3 main.py config.yaml --reference_files app.py --exclude api_key default_value
#
# 4. Include comments in the reference files (be cautious, may increase false positives):
#    python3 main.py config.yaml --reference_files app.py --check_comments
#
# 5. Disable the built-in security checks:
#   python3 main.py config.yaml --reference_files app.py --disable_security_checks
