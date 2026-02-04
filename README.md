# PyWall

PyWall is a terminal-based firewall management tool written in Python.
It provides a structured and safe approach to managing firewall rules with validation, persistence, deduplication, dry-run execution, and rollback-ready backups.

Warning: PyWall interacts with system firewall rules and must be run with root privileges. Always test in a virtual machine or non-production environment.

## Features

- Terminal-based command-line interface
- Rule validation (IP address, port, protocol)
- Persistent rule storage using JSON
- Rule deduplication to prevent duplicates
- Dry-run firewall execution
- Automatic iptables backup with timestamps
- Rollback-ready firewall design
- Safe execution (no blind flushing of rules)

## Project Structure
```bash
PyWall/
├── pywall.py              # Main CLI entry point
├── core/
│   ├── rules.py           # Rule engine (persistence and validation)
│   ├── executor.py        # Firewall executor (dry-run and backup)
│   └── __init__.py
├── config/
│   └── rules.json         # Stored firewall rules (runtime)
├── backups/               # Timestamped iptables backups
├── logs/                  # Logs (optional)
└── README.md
```

## Requirements

- Python 3.10 or newer
- Linux system with iptables
- Root privileges

## Installation

Clone the repository:
```bash
git clone https://github.com/w3nch/PyWall.git
cd PyWall
```
Ensure the script is executable:
```bash
chmod +x pywall.py
```
## Usage

Display help:
```bash
python3 pywall.py --help
```
Check firewall status:
```bash
sudo python3 pywall.py status
```
Add a firewall rule:
```bash
sudo python3 pywall.py add-rule --block --ip 1.2.3.4 --port 80 --protocol tcp
```
List firewall rules:
```bash
sudo python3 pywall.py list-rules
```
Delete a firewall rule:
```bash
sudo python3 pywall.py delete --id 1
```
Start firewall (dry-run with backup):
```bash
sudo python3 pywall.py start
```
## Firewall Backups

Before applying any firewall changes, PyWall automatically creates a backup of the current iptables configuration.

Backups are stored in:
```bash
backups/
```
Backup file format:
```bash
iptables-YYYY-MM-DD_HH-MM-SS.rules
```
These backups can be used for rollback using iptables-restore.

## Design Philosophy

PyWall is designed with safety and predictability in mind:

- Validation before persistence
- Persistence before execution
- Backup before modification
- Dry-run before live execution
- Rollback capability built into the workflow

This approach minimizes the risk of system lockout or misconfiguration.

## Roadmap

Planned enhancements include:

- Safe rule application with automatic rollback on failure
- INPUT and OUTPUT chain support
- Rule priority and ordering
- nftables backend support
- Logging and monitoring
- Daemon mode

## Disclaimer

This project is intended for educational and experimental use.
Use at your own risk. Always maintain out-of-band access when modifying firewall rules.

## License

MIT License
