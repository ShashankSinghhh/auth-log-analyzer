# Auth Log Analyzer - Day 4
# Detect brute-force attempts per IP

log_file = "/var/log/auth.log"

failed_by_ip = {}

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line or "authentication failure" in line:
            parts = line.split()
            for part in parts:
                if part.count(".") == 3:  # crude IP check
                    ip = part
                    failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

threshold = 5

print("Suspicious IPs:")
for ip, count in failed_by_ip.items():
    if count >= threshold:
        print(f"{ip} → {count} failed attempts")
