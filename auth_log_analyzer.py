log_file = "/var/log/auth.log"
failed_count = 0

with open(log_file, "r")as file:
  for line in file:
    if "Failed passowrd" in line or "authentication failure" in line:
      failed_count += 1

print(f"Total failed authentication attempts: {failed_count}")
