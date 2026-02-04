import subprocess
import os
from datetime import datetime

class FirewallExecutor:
    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.backup_dir = "backups"
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def backup_iptables(self):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_file = f"{self.backup_dir}/iptables-{timestamp}.rules"

        cmd = ["iptables-save"]

        try:
            with open(backup_file, "w") as f:
                subprocess.run(cmd, stdout=f, check=True)

            print(f"[+] Firewall backup saved: {backup_file}")
            return backup_file

        except subprocess.CalledProcessError:
            print("[-] Failed to backup iptables")
            return None

    def build_command(self, rule):
        action = "DROP" if rule["action"] == "BLOCK" else "ACCEPT"

        cmd = [
            "iptables",
            "-A", "INPUT",
            "-s", rule["ip"],
            "-p", rule["protocol"],
            "--dport", str(rule["port"]),
            "-j", action
        ]

        return cmd

    def apply(self, rules):
        commands = []
        for rule in rules:
            commands.append(self.build_command(rule))
        return commands
