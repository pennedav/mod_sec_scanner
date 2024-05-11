# Readme

A simple script to parse ModSecurity audit logs. Developed using ChatGPT-4.

## Usage

For grabbing info about the rule ID, matched file, and message:

```sh
tail -f modsec_audit.log | mod_sec_scan.py -v
```

For mildly verbose output

```sh
tail -f modsec_audit.log | mod_sec_scan.py -v
```

For very verbose output:

```sh
tail -f modsec_audit.log | mod_sec_scan.py -vv
```

