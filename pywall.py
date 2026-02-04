#!/usr/bin/env python3
import os
import sys
import argparse
import ipaddress

from core.rules import RuleEngine
from core.executor import FirewallExecutor


def check_permission_root():
    if os.getuid() != 0:
        print("Permission denied: PyWall must be run as root.")
        sys.exit(1)


def validate_rule(args):
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print("[-] Invalid IP address")
        sys.exit(1)

    if not (1 <= args.port <= 65535):
        print("[-] Invalid port number (1-65535)")
        sys.exit(1)


def build_cli():
    parser = argparse.ArgumentParser(
        description="PyWall - A simple terminal-based firewall"
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    sub.add_parser("start", help="Start the firewall")
    sub.add_parser("stop", help="Stop the firewall")
    sub.add_parser("status", help="Check firewall status")

    add = sub.add_parser("add-rule", help="Add firewall rule")

    action = add.add_mutually_exclusive_group(required=True)
    action.add_argument("--block", action="store_true", help="Block traffic")
    action.add_argument("--allow", action="store_true", help="Allow traffic")

    add.add_argument("--ip", required=True, help="Target IP address")
    add.add_argument("--port", type=int, required=True, help="Target port")
    add.add_argument(
        "--protocol",
        choices=["tcp", "udp"],
        required=True,
        help="Network protocol"
    )

    delete = sub.add_parser("delete", help="Delete firewall rule")
    delete.add_argument("--id", type=int, required=True)

    return parser


def main():
    parser = build_cli()
    args = parser.parse_args()

    # If no command, show help
    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Allow help without root
    if args.command not in ("status",):
        check_permission_root()

    engine = RuleEngine()

    if args.command == "add-rule":
        validate_rule(args)

        rule = {
            "action": "BLOCK" if args.block else "ALLOW",
            "ip": args.ip,
            "port": args.port,
            "protocol": args.protocol
        }

        rule_id, created = engine.add_rule(rule)
        if created:
            print(f"[+] Rule added successfully (ID: {rule_id})")
        else:
            print(f"[!] Rule already exists (ID: {rule_id}), not adding duplicate")


    elif args.command == "delete":
        if engine.delete_rule(args.id):
            print(f"[+] Rule {args.id} deleted")
        else:
            print(f"[-] Rule {args.id} not found")

    elif args.command == "status":
        rules = engine.list_rules()
        print(f"[+] PyWall READY — {len(rules)} rule(s) loaded")

    elif args.command == "start":
        check_permission_root()

        executor = FirewallExecutor(dry_run=False)
        rules = engine.list_rules()

        if not rules:
            print("[*] No rules to apply")
            return

        # BACKUP FIRST
        backup_file = executor.backup_iptables()
        if not backup_file:
            print("[-] Aborting firewall start (backup failed)")
            return

        print("[+] Applying firewall rules...")



    elif args.command == "stop":
        print("[+] Firewall stop requested (executor not wired yet)")

    else:
        parser.print_help() 



if __name__ == "__main__":
    main()