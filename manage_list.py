import os
from event_logger import logger_setup, log_event


blocklist_path = "blocklist.txt"
allowlist_path = "allowlist.txt"
logger_setup()

def manage_filter(action, ip=None, list_type="blocklist"):

    if list_type == "blocklist":
        list_path = blocklist_path
    elif list_type == "allowlist":
        list_path = allowlist_path
    else:
        print("List type undefined.")
        log_event("error", "List type undefined.")

    if not os.path.exists(list_path):
        with open(list_path, 'w') as f:
            pass
    
    with open(list_path, 'r') as f:
        ip_list = set(line.strip() for line in f in line.strip())

    if action == 'add' and ip:
        ip_list.add(ip)
        print(f"{ip} added to {list_type}.")
        log_event("info", f"{ip} added to {list_type}.")
    
    elif action == "remove" and ip:
        ip_list.discard(ip)
        print(f"{ip} removed from {list_type}.")
        log_event("info", f"{ip} removed from {list_type}.")

    elif action == "load":
        return ip_list
    
    with open(file_path, "w") as f:
        for ip in sorted(ip_list):
            f.write(ip + "\n")