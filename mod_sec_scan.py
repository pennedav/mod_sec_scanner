#!/usr/bin/env python3

import sys
import re
import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Process ModSecurity log entries.")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Include a verbose log excerpt in the output.')
    return parser.parse_args()

def extract_rule_violations(verbose):
    # Regex to find rule ids, specific file paths, and msg attribute
    rule_id_pattern = re.compile(r'id "(\d+)"')
    file_pattern = re.compile(r'\[file "(/usr/share/modsecurity-crs/rules/[^"]+)"\]')
    msg_pattern = re.compile(r'msg "(.*?)"')

    # Read from standard input
    for line in sys.stdin:
        rule_id_match = rule_id_pattern.search(line)
        file_match = file_pattern.search(line)
        msg_match = msg_pattern.search(line)
        if rule_id_match and msg_match:
            rule_id = rule_id_match.group(1)
            msg = msg_match.group(1)
            file_path = file_match.group(1) if file_match else '-'
            if verbose:
                # Extract the first 1024 characters of the line and ensure it ends without a newline
                log_excerpt = line[:1024].rstrip('\n')
                print(f"\033[91m{rule_id}\033[0m, {file_path}, {msg}, {log_excerpt}\n")
            else:
                print(f"\033[91m{rule_id}\033[0m, {file_path}, {msg}\n", end='')

def main():
    args = parse_arguments()
    extract_rule_violations(args.verbose)

if __name__ == "__main__":
    main()

