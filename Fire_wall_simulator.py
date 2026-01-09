import random
from ipaddress import IPv4Address, IPv4Network
from datetime import datetime
from typing import Dict, Tuple


def is_valid_ip(ip: str) -> bool:
    """Validate if string is a valid IPv4 address."""
    try:
        IPv4Address(ip)
        return True
    except ValueError:
        return False


def generate_random_ip() -> str:
    """Generate a random valid IPv4 address."""
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def ip_in_network(ip: str, network: str) -> bool:
    """Check if IP is in CIDR network (e.g., 192.168.1.0/24)."""
    try:
        return IPv4Address(ip) in IPv4Network(network, strict=False)
    except ValueError:
        return False


def check_firewall_rules(ip_address: str, rules: Dict[str, str]) -> Tuple[str, str]:
    """
    Check firewall rules and return action and matched rule.
    Supports exact matches and CIDR notation.
    """
    if not is_valid_ip(ip_address):
        return "Deny", "Invalid IP"
    
    for rule, action in rules.items():
        # Check exact IP match
        if ip_address == rule:
            return action, rule
        # Check CIDR network match
        if "/" in rule and ip_in_network(ip_address, rule):
            return action, rule
    
    return "Deny", "Default"


def log_connection(ip: str, action: str, rule: str, port: int = None) -> str:
    """Log connection with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    port_info = f":{port}" if port else ""
    return f"[{timestamp}] IP: {ip}{port_info} - Action: {action} (Rule: {rule})"


def main():
    print("Firewall Simulator\n")
    
    # Enhanced firewall rules with CIDR support
    firewall_rules = {
        "192.168.1.1": "Allow",
        "10.0.0.0/8": "Allow",        # Allow entire private network
        "10.0.0.5": "Deny",           # Specific denial override
        "172.16.0.10": "Allow",
        "8.8.8.8": "Allow",           # Google DNS
    }
    
    stats = {"allowed": 0, "denied": 0}
    log_entries = []
    
    print("Testing 10 connections:\n")
    for _ in range(10):
        ip_addr = generate_random_ip()
        action, matched_rule = check_firewall_rules(ip_addr, firewall_rules)
        port = random.randint(1024, 65535)
        
        log_entry = log_connection(ip_addr, action, matched_rule, port)
        log_entries.append(log_entry)
        print(log_entry)
        
        if action == "Allow":
            stats["allowed"] += 1
        else:
            stats["denied"] += 1
    
    # Print statistics
    print(f"\n{'='*57}")
    print(f"Statistics: Allowed: {stats['allowed']} | Denied: {stats['denied']} | Block Rate: {stats['denied']/(stats['allowed']+stats['denied'])*100:.1f}%")
    print(f"{'='*57}")

if __name__ == "__main__":
    main()