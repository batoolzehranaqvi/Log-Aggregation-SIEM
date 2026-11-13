#!/usr/bin/env python3
"""
SIEM Real-Time Automated Remediation Webhook Server
Receives alert payloads from Kibana/OpenSearch or Logstash and executes automated IP blocking.
"""

from flask import Flask, request, jsonify
import logging
import ipaddress
import os

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

BLACKLIST_FILE = "blocked_ips.txt"

def is_valid_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        # Exclude private/loopback IPs to prevent accidental lockouts
        return not (ip.is_private or ip.is_loopback)
    except ValueError:
        return False

def block_ip(ip_address):
    """Appends bad actor IP to blacklist and simulates/executes iptables block."""
    if not is_valid_ip(ip_address):
        logging.warning(f"Skipping block for internal or invalid IP: {ip_address}")
        return False, "Invalid or private IP address"

    # Append to blacklist file
    existing = []
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "r") as f:
            existing = [line.strip() for line in f.readlines()]
    
    if ip_address not in existing:
        with open(BLACKLIST_FILE, "a") as f:
            f.write(f"{ip_address}\n")
        logging.info(f"[BLACK_LIST] Added {ip_address} to {BLACKLIST_FILE}")

    # IPTables command string for production Linux deployment
    cmd_str = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    logging.info(f"[FIREWALL] Simulated command: {cmd_str}")

    return True, f"IP {ip_address} added to blocklist"

@app.route("/api/v1/remediate", methods=["POST"])
def remediate():
    payload = request.get_json(silent=True) or {}
    logging.info(f"[ALERT_RECEIVED] Payload: {payload}")

    target_ip = payload.get("source_ip") or payload.get("client_ip")
    rule_name = payload.get("rule_name", "SIEM Anomaly Detection")

    if not target_ip:
        return jsonify({"status": "error", "message": "Missing target IP in alert payload"}), 400

    success, message = block_ip(target_ip)
    return jsonify({
        "status": "success" if success else "ignored",
        "rule_triggered": rule_name,
        "action_taken": "FIREWALL_IP_BLOCK",
        "target_ip": target_ip,
        "details": message
    }), 200

if __name__ == "__main__":
    logging.info("Starting Security Remediation Webhook Server on port 5000...")
    app.run(host="0.0.0.0", port=5000)
