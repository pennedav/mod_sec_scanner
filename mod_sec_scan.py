#!/usr/bin/env python3

import sys
import re
import argparse
import textwrap

def parse_arguments():
    parser = argparse.ArgumentParser(description="Process ModSecurity log entries.")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Include detailed attribute listings in the output with color coding.')
    parser.add_argument('-vv', '--very-verbose', action='store_true',
                        help='Include detailed attribute listings and the first 1024 characters of the log line.')
    parser.add_argument('-w', '--wrap', action='store_true',
                        help='Wrap the output so that each line does not exceed 80 characters.')
    return parser.parse_args()

def wrap_text(text, width=78):
    wrapper = textwrap.TextWrapper(width=width, subsequent_indent='  ')
    wrapped_lines = wrapper.wrap(text)
    return ' \\\n'.join(wrapped_lines) if wrapped_lines else text

def print_verbose_output(label, text, args):
    if args.wrap:
        text = wrap_text(f"\033[93m{label}:\033[0m {text}")
    else:
        text = f"\033[93m{label}:\033[0m {text}"
    print(text)

def extract_rule_violations(args):
    # Regex to find rule ids, specific file paths, and msg attribute
    rule_id_pattern = re.compile(r'id "(\d+)"')
    file_pattern = re.compile(r'\[file "(/usr/share/modsecurity-crs/rules/[^"]+)"\]')
    msg_pattern = re.compile(r'msg "(.*?)"')
    uri_pattern = re.compile(r'\[uri "([^"]+)"\]')

    # Read from standard input
    for line in sys.stdin:
        rule_id_match = rule_id_pattern.search(line)
        file_match = file_pattern.search(line)
        uri_match = uri_pattern.search(line)
        msg_match = msg_pattern.search(line)
        if rule_id_match and msg_match:
            rule_id = rule_id_match.group(1)
            msg = msg_match.group(1)
            file_path = file_match.group(1) if file_match else '-'
            uri_path = uri_match.group(1) if uri_match else '-'
            if args.very_verbose:
                log_excerpt = line[:1024].rstrip('\n')
                print_verbose_output('Id', rule_id, args)
                print_verbose_output('File', file_path, args)
                print_verbose_output('Uri', uri_path, args)
                print_verbose_output('Msg', msg, args)
                print_verbose_output('Log Excerpt', log_excerpt, args)
                print()
            elif args.verbose:
                print_verbose_output('Id', rule_id, args)
                print_verbose_output('File', file_path, args)
                print_verbose_output('Uri', uri_path, args)
                print_verbose_output('Msg', msg, args)
                print()
            else:
                print(f"{rule_id}, {file_path}, {uri_path}, {msg}")

def main():
    args = parse_arguments()
    extract_rule_violations(args)

if __name__ == "__main__":
    main()

