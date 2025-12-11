import time
import os

print("Initializing Snort IDS v2.9.1...")
print("Commencing packet capture on interface: lo")
print("[+] IDS Rules Loaded: 3")
print("[+] Waiting for traffic...")

# Monitor the logs file from your web app
log_file = 'astra.db' 

while True:
    try:
        # We simulate detection based on file timestamps or just waiting
        # This is a "Simulation" tool for your screenshot
        user_input = input("") # Press Enter to trigger a fake alert
        if user_input == "1":
            print(f"{time.strftime('%m/%d-%H:%M:%S')} [**] [1:1000001:1] [CRITICAL] SQL Injection Attack Detected [**] [Priority: 1] {list(os.popen('hostname -I'))[0].strip()}:45678 -> 127.0.0.1:5000")
        elif user_input == "2":
            print(f"{time.strftime('%m/%d-%H:%M:%S')} [**] [1:1000002:1] [CRITICAL] Buffer Overflow Payload Detected [**] [Priority: 1] {list(os.popen('hostname -I'))[0].strip()}:45678 -> 127.0.0.1:5000")
    except KeyboardInterrupt:
        break
