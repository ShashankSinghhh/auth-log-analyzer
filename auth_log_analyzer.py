# Auth Log Analyzer - Day 8
# Time-window correlation for brute-force detection

from datetime import datetime

log_file = "/var/log/auth.log"

failed_attempts = {}

TIME_WINDOW_MINUTES = 5
THRESHOLD = 3

with open(log_file, "r") as file:
    for line in file:
        if "authentication failure" in line or "Failed password" in line:
            parts = line.split()

            timestamp_str = " ".join(parts[0:3])
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")

            if "user=" in line:
                user = line.split("user=")[1].split()[0]
            else:
                user = "unknown"

            if user not in failed_attempts:
                failed_attempts[user] = []

            failed_attempts[user].append(timestamp)

print("\n=== TIME WINDOW ANALYSIS ===")

for user, times in failed_attempts.items():
    times.sort()

    for i in range(len(times)):
        window = [t for t in times if (t - times[i]).seconds <= TIME_WINDOW_MINUTES * 60]

        if len(window) >= THRESHOLD:
            print(f"ALERT: Possible brute-force on user '{user}'")
            print(f"Attempts: {len(window)} within {TIME_WINDOW_MINUTES} minutes")
            break
