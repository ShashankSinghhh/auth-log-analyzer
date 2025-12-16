# Auth Log Analyzer - Day 7
# Focus: Debugging why detections fail

log_file = "/var/log/auth.log"

# Dictionary to count severity events
events = {
    "low": 0,
    "medium": 0,
    "high": 0
}

# Dictionary to track what patterns we actually saw
patterns_seen = {
    "sudo": 0,
    "sshd": 0,
    "failed_auth": 0
}

total_lines = 0

with open(log_file, "r") as file:
    for line in file:
        total_lines += 1

        if "sudo" in line:
            patterns_seen["sudo"] += 1

        if "sshd" in line:
            patterns_seen["sshd"] += 1

        if "authentication failure" in line or "Failed password" in line or "Failed publickey" in line:
            patterns_seen["failed_auth"] += 1

        if "sudo" in line and "authentication failure" in line:
            events["low"] += 1

        elif "sshd" in line and ("Invalid user" in line or "authentication failure" in line):
            events["medium"] += 1

        elif "Failed password" in line or "Failed publickey" in line:
            events["high"] += 1

print("\n=== DEBUG SUMMARY ===")
print(f"Total log lines read: {total_lines}")

print("\nPatterns observed:")
for pattern, count in patterns_seen.items():
    print(f"{pattern.upper()} → {count}")

print("\nSOC Event Summary:")
print(f"LOW → {events['low']}")
print(f"MEDIUM → {events['medium']}")
print(f"HIGH → {events['high']}")

if events["high"] == 0 and patterns_seen["failed_auth"] == 0:
    print("\nNOTE: No authentication failures detected.")
    print("Reason: System likely uses key-based authentication or no attacks occurred.")
