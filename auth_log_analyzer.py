# Auth Log Analyzer - Day 6
# Classify authentication-related events by severity

log_file = "/var/log/auth.log"

events = {
    "low": 0,
    "medium": 0,
    "high": 0
}

with open(log_file, "r") as file:
    for line in file:
        if "sudo" in line and "authentication failure" in line:
            events["low"] += 1

        elif "sshd" in line and ("Invalid user" in line or "authentication failure" in line):
            events["medium"] += 1

        elif "Failed publickey" in line or "Failed password" in line:
            events["high"] += 1

print("Event classification summary:")
for severity, count in events.items():
    print(f"{severity.upper()} → {count} events")
