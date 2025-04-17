import argparse
import logging
import os
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
    parser.add_argument("--exclude", nargs="+", help="List of parameters to exclude from analysis (e.g., common parameters).", default=[])
    parser.add_argument("--check_comments", action="store_true", help="Include comments in the analysis to detect potentially used parameters", default=False)
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

def find_used_parameters(config_files, check_comments=False):
    """
    Finds used parameters by searching for them in the provided configuration files.

    Args:
        config_files (list): A list of file paths to configuration files.
        check_comments (bool):  Whether to check inside comments for potentially used parameters

    Returns:
        set: A set of used parameters.
    """
    used_parameters = set()

    for file_path in config_files:
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

def find_unused_parameters(config_files, exclude_parameters=None, check_comments=False, disable_security_checks=False):
    """
    Identifies unused configuration parameters in the given configuration files.

    Args:
        config_files (list): A list of paths to configuration files.
        exclude_parameters (list): A list of parameters to exclude from the analysis.
        check_comments (bool): Whether to also check comments in the config files.
        disable_security_checks (bool):  Disable security checks like hardcoded secrets detection.

    Returns:
        dict: A dictionary where keys are file paths and values are lists of unused parameters.
    """
    unused_parameters_by_file = {}
    used_parameters = find_used_parameters(config_files, check_comments)

    for file_path in config_files:
        config_data = load_config(file_path)
        if config_data is None:
            continue

        all_parameters = set()
        def collect_parameters(data, prefix=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    all_parameters.add(prefix + key)  # Add parameter name
                    collect_parameters(value, prefix + key + ".")  # Recursive call for nested dictionaries

        collect_parameters(config_data)

        if exclude_parameters:
            excluded_set = set(exclude_parameters)
            all_parameters = all_parameters.difference(excluded_set)

        unused = list(all_parameters.difference(used_parameters))

        if not disable_security_checks:
            # Basic security check: detect potential hardcoded secrets (example)
            potentially_sensitive = [p for p in unused if "password" in p.lower() or "secret" in p.lower() or "token" in p.lower() or "key" in p.lower()]
            if potentially_sensitive:
                logging.warning(f"Potential hardcoded secrets detected in '{file_path}': {potentially_sensitive}. Review carefully!")

        unused_parameters_by_file[file_path] = unused

    return unused_parameters_by_file

def main():
    """
    Main function to execute the unused configuration parameter finder.
    """
    args = setup_argparse()

    # Input validation: Check if files exist
    for file_path in args.config_files:
        if not os.path.exists(file_path):
            logging.error(f"File '{file_path}' does not exist.")
            return

    unused_parameters = find_unused_parameters(args.config_files, args.exclude, args.check_comments, args.disable_security_checks)

    if unused_parameters:
        print("Unused parameters found:")
        for file_path, unused_list in unused_parameters.items():
            if unused_list:
                print(f"  File: {file_path}")
                for param in unused_list:
                    print(f"    - {param}")
    else:
        print("No unused parameters found.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze a single YAML file:
#    python misconfig_UnusedConfigParameterFinder.py config.yaml

# 2. Analyze multiple configuration files (YAML, JSON, INI):
#    python misconfig_UnusedConfigParameterFinder.py config.yaml config.json config.ini

# 3. Exclude specific parameters from the analysis:
#    python misconfig_UnusedConfigParameterFinder.py config.yaml --exclude api_key default_value

# 4. Include comments in the analysis (be cautious, may increase false positives):
#    python misconfig_UnusedConfigParameterFinder.py config.yaml --check_comments

# 5. Analyze all YAML files in the current directory:
#    python misconfig_UnusedConfigParameterFinder.py *.yaml

# 6. Disable the built-in security checks:
#   python misconfig_UnusedConfigParameterFinder.py config.yaml --disable_security_checks