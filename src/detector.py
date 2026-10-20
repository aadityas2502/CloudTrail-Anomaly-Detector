import json
import os
from colorama import Fore, Style, init

init(autoreset=True)

# Define security rules/heuristics
SUSPICIOUS_EVENTS = {
    "ConsoleLogin": {"Fail": "Multiple Failed Console Logins", "Root": "Root Account Usage Detected"},
    "AuthorizeSecurityGroupIngress": "Open Security Group Rule (Potential Port 22/3389 Exposure)"
}

def analyze_logs(log_file_path):
    print(Fore.CYAN + f"[*] Analyzing CloudTrail logs from: {log_file_path}\n")
    
    if not os.path.exists(log_file_path):
        print(Fore.RED + "[!] Log file not found.")
        return

    with open(log_file_path, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(Fore.RED + "[!] Invalid JSON format.")
            return

    records = data.get("Records", [])
    alerts = 0

    for record in records:
        event_name = record.get("eventName")
        user_identity = record.get("userIdentity", {}).get("type", "Unknown")
        source_ip = record.get("sourceIPAddress", "N/A")
        
        # Check rule 1: Root user activity
        if user_identity == "Root":
            alerts += 1
            print(Fore.RED + f"[ALERT] Root activity detected! Event: {event_name} | IP: {source_ip}")

        # Check rule 2: Overly permissive security groups
        if event_name == "AuthorizeSecurityGroupIngress":
            request_parameters = record.get("requestParameters", {})
            # Look for 0.0.0.0/0 exposure
            params_str = json.dumps(request_parameters)
            if "0.0.0.0/0" in params_str:
                alerts += 1
                print(Fore.YELLOW + f"[WARNING] Unrestricted inbound network access (0.0.0.0/0) allowed! IP: {source_ip}")

    print(Fore.GREEN + f"\n[+] Analysis complete. Scanned {len(records)} events. Total alerts generated: {alerts}")

if __name__ == "__main__":
    sample_path = os.path.join("sample_logs", "sample_cloudtrail.json")
    analyze_logs(sample_path)
