import socket
import requests

print("=== Simple Vulnerability Scanner ===")

# Take input
url = input("Enter website URL (include http/https): ")

# ---------------------------
# HTTPS CHECK
# ---------------------------
if url.startswith("https://"):
    print("✅ Website is Secure (HTTPS)")
else:
    print("⚠️ Website is NOT Secure (HTTP)")

# ---------------------------
# EXTRACT HOSTNAME
# ---------------------------
host = url.replace("https://", "").replace("http://", "")
host = host.split("/")[0]

print("🌐 Host:", host)

# ---------------------------
# PORT SCANNING
# ---------------------------
print("\n🔍 Scanning common ports...")
ports = [21, 22, 80, 443, 8080]

open_ports = []

for port in ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)

        sock.close()
    except:
        pass

if open_ports:
    print("🔓 Open Ports:", open_ports)
else:
    print("🔒 No common ports open")

# ---------------------------
# SENSITIVE PATH SCAN
# ---------------------------
print("\n📂 Checking sensitive paths...")

paths = ["/admin", "/login", "/backup", "/.git"]
found_paths = []

for path in paths:
    try:
        response = requests.get(url + path, timeout=3)
        if response.status_code == 200:
            found_paths.append(path)
    except:
        pass

if found_paths:
    print("⚠️ Sensitive paths found:", found_paths)
else:
    print("✅ No sensitive paths accessible")

# ---------------------------
# SERVER INFO
# ---------------------------
print("\n🧾 Fetching server information...")

try:
    response = requests.get(url, timeout=3)
    server = response.headers.get("Server")

    if server:
        print("Server:", server)
    else:
        print("Server info not disclosed")
except:
    print("Could not retrieve server information")

print("\n=== Scan Complete ===")