from collections import defaultdict

log_file = "sample_logs.txt"
threshold = 3

failed_attempts = defaultdict(int)

with open(log_file, "r") as file:
    for line in file:
        if "LOGIN_FAILED" in line:
            ip = line.strip().split()[-1]
            failed_attempts[ip] += 1

print("=== Suspicious IP Report ===")

for ip, count in failed_attempts.items():
    if count >= threshold:
        print(f"ALERT: {ip} has {count} failed login attempts")
        
