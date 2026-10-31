![Banner](banner.png)

# misconfig-UnusedConfigParameterFinder
Identifies unused configuration parameters across multiple configuration files (e.g., YAML, JSON, INI). Helps reduce complexity and identify potential areas of improvement in configurations. Utilizes `pyyaml`, `json`, and `configparser` libraries. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

A parameter counts as used when its name appears in a separate set of reference files (source code or usage files) that you supply with `--reference_files`. Use is never measured against the configuration files themselves: a parameter name always appears in its own definition there, so that measurement could never report a plain parameter as unused. Running without `--reference_files` analyses nothing and exits 1 with an explanation.

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-unusedconfigparameterfinder`

Install the dependency with `pip install -r requirements.txt` (PyYAML).

## Usage
`python3 main.py CONFIG [CONFIG ...] --reference_files REF [REF ...] [--exclude PARAM ...] [--check_comments] [--disable_security_checks]`

## Security check

Unless `--disable_security_checks` is given, the tool checks every collected parameter, used and unused alike. It warns when a parameter whose name contains `password`, `secret`, `token`, `api_key`, `apikey`, `private_key`, or `access_key` holds a non-empty string value that is not a plain number. Plain numeric values never warn, whatever the parameter is called. The warning lists parameter names only; values are never printed.

## Exit codes

- `0`: at least one file was loaded, parameters were collected, and no unused parameters were found.
- `1`: unused parameters were found, or the analysis could not be completed. A missing configuration or reference file, a file that fails to load, a run with no reference files, and a run that collects no parameters all exit 1 instead of reporting an empty or clean result.

## Parameters
- `-h`: Show help message and exit
- `config_files`: Path(s) to the configuration file(s) (positional, required).
- `--reference_files`: Path(s) to reference files in which parameter use is searched (required).
- `--exclude`: List of parameters to exclude from analysis (e.g., common parameters).
- `--check_comments`: Include comments in the reference files in the analysis to detect potentially used parameters
- `--disable_security_checks`: Disable security checks like hardcoded secrets detection (use with caution!).

## License
Copyright (c) ShadowStrikeHQ
