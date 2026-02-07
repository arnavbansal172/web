# Web Shell

A Python-based web shell service for remote system access.

## Overview

This utility provides a web-based interface for shell access, designed to run as a systemd service.

## Warning

This tool is for EDUCATIONAL and AUTHORIZED PENETRATION TESTING purposes only. Unauthorized access to computer systems is illegal.

## Files

- `web-shell.py` - Main Python web shell script
- `web-shell.service` - Systemd service configuration

## Usage

### Manual Execution
```bash
python3 web-shell.py
```

### As a Service
```bash
sudo cp web-shell.service /etc/systemd/system/
sudo systemctl enable web-shell
sudo systemctl start web-shell
```

## Technologies

- Python 3
- HTTP Server
- Systemd

## Disclaimer

Use responsibly and only on systems you own or have explicit permission to test.
