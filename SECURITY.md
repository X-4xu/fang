# Security Policy

## Responsible Testing and Defensive Purpose

`Fang` is an open-source defensive monitoring tool designed to help system administrators and security engineers detect unauthorized access attempts and brute-force attacks against SSH servers.

- **Defensive Monitoring Only**: This tool only inspects local authentication logs. It does not perform network operations, port scanning, or active interception.
- **Safe Parsing Guarantee**: All log data is considered untrusted input. The parser enforces bounded matching, validates IP addresses strictly using standard IP address representations, and never passes log data to shell execution environments.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in `Fang`, please report it responsibly:

1. **Do not open a public GitHub issue.**
2. Submit a private advisory via [GitHub Security Advisories](https://github.com/X-4xu/fang/security/advisories/new) or send an email directly to `hassanaliaa189@gmail.com`.
3. Provide details regarding:
   - Type of issue (e.g. ReDoS in parser, unhandled exception with untrusted input, path traversal in output file handling).
   - Sample log lines that reproduce the issue.
   - Potential impact.

We will acknowledge receipt within 48 hours and work with you to release a patch promptly.
