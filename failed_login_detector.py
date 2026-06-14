from collections import defaultdict
import csv

# Configuration
log_file = "sample_logs.txt"
alert_file = "alerts.txt"
csv_file = "report.csv"
threshold = 3

# Store failed login counts
failed_attempts = defaultdict(int)

# Read log file
with open(log_file, "r") as file:
    for line in file:
        if "LOGIN_FAILED" in line:
            ip = line.strip().split()[-1]
            failed_attempts[ip] += 1

# Write alerts
with open(alert_file, "w") as alerts:
    alerts.write("=== Suspicious IP Alert Report ===\n\n")

    for ip, count in failed_attempts.items():
        if count >= threshold:
            alert = f"ALERT: {ip} has {count} failed login attempts\n"
            alerts.write(alert)
            print(alert.strip())

# Generate CSV Report
with open(csv_file, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    # Header
    writer.writerow(["IP Address", "Failed Attempts", "Status"])

    # Data Rows
    for ip, count in failed_attempts.items():

        if count >= threshold:
            status = "Suspicious"
        else:
            status = "Normal"

        writer.writerow([ip, count, status])

print(f"\nAlerts saved to: {alert_file}")
print(f"CSV report generated: {csv_file}")