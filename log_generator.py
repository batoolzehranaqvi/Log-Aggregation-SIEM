#!/usr/bin/env python3
"""
Real-Time Log Telemetry Simulator for SIEM Testing
Generates realistic Linux SSH authentication logs (/var/log/auth.log format)
and Nginx web access logs (Combined Log Format) with simulated security events
(SSH Brute-Force, SQL query anomalies, directory traversal attempts, and scanner noise).
"""

import argparse
import random
import time
import os
from datetime import datetime

# Sample IP Address Pools
NORMAL_IPS = ["192.168.1.45", "10.0.0.12", "172.16.0.5", "192.168.1.100", "10.0.0.50"]
ATTACKER_IPS = ["185.220.101.5", "198.51.100.42", "203.0.113.195", "45.146.164.110"]

# Sample Usernames for SSH Attacks
USERNAMES = ["root", "admin", "ubuntu", "postgres", "user", "deploy", "oracle", "test"]

# Nginx User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "SecurityScanner/1.6",
    "AutomatedAuditTool/2.1",
    "CustomHttpClient/1.1"
]

# Nginx Attack Payloads & Web Security Test Paths
ATTACK_PATHS = [
    "/admin/login.php?user=admin_sqli_test",
    "/index.php?id=1_select_union_query",
    "/static/path_traversal_test",
    "/cgi-bin/vulnerable_script_test",
    "/search?q=xss_script_payload_test",
    "/.env",
    "/.git/config"
]

NORMAL_PATHS = [
    "/",
    "/index.html",
    "/api/v1/products",
    "/login",
    "/static/css/main.css",
    "/static/js/app.js",
    "/dashboard",
    "/api/v1/user/profile"
]

def generate_ssh_log(is_attack=False):
    """Generate SSH auth log line (syslog RFC3164 format)."""
    now = datetime.now()
    timestamp = now.strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 9999)
    
    if is_attack:
        ip = random.choice(ATTACKER_IPS)
        username = random.choice(USERNAMES)
        event_type = random.choice(["failed_pass", "invalid_user", "failed_pass"])
    else:
        ip = random.choice(NORMAL_IPS)
        username = random.choice(["ubuntu", "deploy", "admin"])
        event_type = random.choice(["accept_pass", "failed_pass", "accept_pass"])
        
    port = random.randint(30000, 65000)
    if event_type == "failed_pass":
        return f"{timestamp} server sshd[{pid}]: Failed password for {username} from {ip} port {port} ssh2\n"
    elif event_type == "invalid_user":
        return f"{timestamp} server sshd[{pid}]: Invalid user {username} from {ip} port {port}\n"
    else:
        return f"{timestamp} server sshd[{pid}]: Accepted password for {username} from {ip} port {port} ssh2\n"

def generate_nginx_log(is_attack=False):
    """Generate Nginx access log line (Combined Log Format)."""
    now = datetime.now()
    timestamp = now.strftime("%d/%b/%Y:%H:%M:%S -0800")
    
    if is_attack:
        ip = random.choice(ATTACKER_IPS)
        path = random.choice(ATTACK_PATHS)
        status = random.choice([400, 401, 403, 404, 500])
        user_agent = random.choice(USER_AGENTS[2:])
        method = random.choice(["GET", "POST"])
        bytes_sent = random.randint(150, 600)
    else:
        ip = random.choice(NORMAL_IPS)
        path = random.choice(NORMAL_PATHS)
        status = random.choice([200, 200, 200, 201, 304, 404])
        user_agent = random.choice(USER_AGENTS[:2])
        method = "GET" if random.random() > 0.2 else "POST"
        bytes_sent = random.randint(1200, 15000)
        
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{user_agent}"\n'

def main():
    parser = argparse.ArgumentParser(description="SIEM Log Simulation Generator")
    parser.add_argument("--output-dir", default="./logs", help="Directory to save log files")
    parser.add_argument("--count", type=int, default=50, help="Total number of log lines to generate per file")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between lines (0 for instant test run)")
    parser.add_argument("--attack-ratio", type=float, default=0.35, help="Ratio of attack logs (0.0 to 1.0)")
    parser.add_argument("--continuous", action="store_true", help="Run continuously until stopped")
    
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    auth_log_path = os.path.join(args.output_dir, "auth.log")
    nginx_log_path = os.path.join(args.output_dir, "nginx_access.log")
    
    print(f"[+] Starting SIEM Log Simulator")
    print(f"    - Output directory: {args.output_dir}")
    print(f"    - Attack ratio: {int(args.attack_ratio * 100)}%")
    print(f"    - Continuous mode: {args.continuous}")
    print(f"[+] Writing logs to '{auth_log_path}' and '{nginx_log_path}'...\n")
    
    generated = 0
    try:
        with open(auth_log_path, "a") as f_auth, open(nginx_log_path, "a") as f_nginx:
            while args.continuous or generated < args.count:
                is_attack = random.random() < args.attack_ratio
                
                auth_line = generate_ssh_log(is_attack)
                nginx_line = generate_nginx_log(is_attack)
                
                f_auth.write(auth_line)
                f_auth.flush()
                
                f_nginx.write(nginx_line)
                f_nginx.flush()
                
                generated += 1
                if args.delay > 0:
                    time.sleep(args.delay)
                    
        print(f"[✔] Simulation complete! {generated} log pairs written to target directory.")
    except KeyboardInterrupt:
        print(f"\n[!] Simulation stopped by user. Total log pairs generated: {generated}")

if __name__ == "__main__":
    main()
