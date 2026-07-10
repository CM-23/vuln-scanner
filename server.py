import os
import sys
import json
import socket
import urllib.parse
import http.server
import time
import requests

PORT = int(os.environ.get('PORT', 80))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')

class VulnerabilityScannerHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Custom logging format to print request info on the console
        sys.stderr.write("%s - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % args))

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        # Serve static assets or direct routes
        if path == '/':
            self.serve_file(os.path.join(WEB_DIR, 'index.html'), 'text/html')
        elif path == '/style.css':
            self.serve_file(os.path.join(WEB_DIR, 'style.css'), 'text/css')
        elif path == '/app.js':
            self.serve_file(os.path.join(WEB_DIR, 'app.js'), 'application/javascript')
        elif path == '/api/scan':
            self.handle_scan(query)
        else:
            self.send_error(404, "File not found")

    def serve_file(self, file_path, content_type):
        try:
            if not os.path.exists(file_path):
                self.send_error(404, f"File not found: {os.path.basename(file_path)}")
                return
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Internal server error: {e}")

    def send_sse_event(self, event, data):
        try:
            payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
            self.wfile.write(payload.encode('utf-8'))
            self.wfile.flush()
            return True
        except socket.error:
            # Client disconnected
            return False

    def handle_scan(self, query):
        url_param = query.get('url')
        if not url_param or not url_param[0]:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'URL parameter is required'}).encode('utf-8'))
            return

        target_url = url_param[0].strip()
        
        # Parse ports query parameter
        ports_param = query.get('ports')
        ports_to_scan = [21, 22, 80, 443, 8080, 8443] # defaults
        if ports_param and ports_param[0]:
            try:
                ports_to_scan = [int(p.strip()) for p in ports_param[0].split(',') if p.strip().isdigit()]
            except ValueError:
                pass

        # Send headers for Server-Sent Events (SSE)
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        def log_to_client(text, tag=""):
            return self.send_sse_event('log', {'text': text, 'tag': tag})

        def update_progress(pct):
            return self.send_sse_event('progress', {'percent': pct})

        # Initiate scan representation
        if not log_to_client("┌─────────────────────────────────────────────────┐\n", "dim"): return
        if not log_to_client("│  VULNSC RECON ENGINE  v2.0.1 (Web Edition)     │\n", "purple"): return
        if not log_to_client("└─────────────────────────────────────────────────┘\n", "dim"): return
        if not log_to_client(f"\n  TARGET   ", "dim"): return
        if not log_to_client(f"{target_url}\n", "bright"): return
        if not log_to_client(f"  TIME     ", "dim"): return
        if not log_to_client(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n\n", "dim"): return

        # ── 1. Protocol check ────────────────────────────────────────
        update_progress(10)
        if not log_to_client("  [1/4]  ", "accent"): return
        if not log_to_client("PROTOCOL CHECK\n", "bright"): return
        
        is_https = target_url.startswith("https://")
        if is_https:
            if not log_to_client("         ✔  TLS/HTTPS", "green"): return
            if not log_to_client("  — encrypted transport\n", "dim"): return
        else:
            if not log_to_client("         ✘  PLAIN HTTP", "red"): return
            if not log_to_client("  — traffic is unencrypted!\n", "yellow"): return

        # Extract Hostname
        host = target_url.replace("https://","").replace("http://","").split("/")[0]
        host_ip = host.split(":")[0]
        if not log_to_client(f"         HOST  ", "dim"): return
        if not log_to_client(f"{host_ip}\n\n", "accent"): return

        # ── 2. Port scan ──────────────────────────────────────────
        update_progress(35)
        if not log_to_client("  [2/4]  ", "accent"): return
        if not log_to_client("PORT SCAN\n", "bright"): return
        
        open_ports = []
        closed_ports = []
        unreachable_ports = []

        for port in ports_to_scan:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                res = s.connect_ex((host_ip, port))
                if res == 0:
                    open_ports.append(port)
                    if not log_to_client(f"         ◉  {port:<6}", "green"): return
                    if not log_to_client("OPEN\n", "green"): return
                else:
                    closed_ports.append(port)
                    if not log_to_client(f"         ○  {port:<6}", "dim"): return
                    if not log_to_client("closed\n", "dim"): return
                s.close()
            except Exception:
                unreachable_ports.append(port)
                if not log_to_client(f"         ?  {port:<6}", "yellow"): return
                if not log_to_client("unreachable\n", "dim"): return
            time.sleep(0.02) # spacing out for real-time responsiveness

        if not log_to_client(f"\n         Summary: ", "dim"): return
        if not log_to_client(f"{len(open_ports)} open", "green"): return
        if not log_to_client(f"  /  {len(closed_ports) + len(unreachable_ports)} closed\n\n", "dim"): return

        # ── 3. Path scan ──────────────────────────────────────────
        update_progress(65)
        if not log_to_client("  [3/4]  ", "accent"): return
        if not log_to_client("PATH DISCOVERY\n", "bright"): return

        paths = ["/admin", "/login", "/wp-admin", "/dashboard",
                 "/api", "/config", "/.env", "/backup"]
        found_paths = []
        redirect_paths = []
        base = target_url.rstrip("/")

        for path in paths:
            try:
                res = requests.get(base + path, timeout=4,
                                   headers={"User-Agent": "Mozilla/5.0"},
                                   allow_redirects=False)
                code = res.status_code
                if code == 200:
                    found_paths.append(path)
                    if not log_to_client(f"         ◉  {path:<20}", "red"): return
                    if not log_to_client(f"  {code} FOUND\n", "red"): return
                elif code in (301, 302, 307, 308):
                    redirect_paths.append(path)
                    if not log_to_client(f"         →  {path:<20}", "yellow"): return
                    if not log_to_client(f"  {code} REDIRECT\n", "dim"): return
                else:
                    if not log_to_client(f"         ○  {path:<20}", "dim"): return
                    if not log_to_client(f"  {code}\n", "dim"): return
            except Exception:
                if not log_to_client(f"         ×  {path:<20}", "dim"): return
                if not log_to_client("  timeout/error\n", "dim"): return
            time.sleep(0.02)

        if not log_to_client(f"\n         Exposed paths: ", "dim"): return
        if found_paths:
            if not log_to_client(f"{len(found_paths)} detected\n\n", "red"): return
        else:
            if not log_to_client("none detected\n\n", "green"): return

        # ── 4. Server info ────────────────────────────────────────
        update_progress(85)
        if not log_to_client("  [4/4]  ", "accent"): return
        if not log_to_client("HEADER FINGERPRINTING\n", "bright"): return

        headers_found = {}
        try:
            res = requests.get(base, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            interesting = ["Server","X-Powered-By","X-Frame-Options",
                           "Content-Security-Policy","Strict-Transport-Security",
                           "X-Content-Type-Options","Access-Control-Allow-Origin"]
            for h in interesting:
                val = res.headers.get(h)
                headers_found[h] = val
                if val:
                    tag = "dim" if h in ("Server","X-Powered-By") else "green"
                    if not log_to_client(f"         {h:<35}", "dim"): return
                    if not log_to_client(f"{val[:50]}\n", tag): return
                else:
                    if not log_to_client(f"         {h:<35}", "dim"): return
                    if not log_to_client("—\n", "dim"): return
        except Exception as e:
            if not log_to_client(f"         Error: {e}\n", "red"): return

        # ── Done ─────────────────────────────────────────────
        update_progress(100)
        if not log_to_client("\n┌─────────────────────────────────────────────────┐\n", "dim"): return
        if not log_to_client("│  SCAN COMPLETE                                  │\n", "green"): return
        if not log_to_client("└─────────────────────────────────────────────────┘\n", "dim"): return

        # Threat Assessment
        threat_score = 0
        if not is_https:
            threat_score += 2
        threat_score += len(open_ports)
        threat_score += len(found_paths) * 2

        if threat_score <= 1:
            threat_level = "LOW"
        elif threat_score <= 4:
            threat_level = "MEDIUM"
        else:
            threat_level = "HIGH"

        # Send statistical summary
        stats = {
            'https': is_https,
            'host': host_ip,
            'open_ports': open_ports,
            'all_ports': ports_to_scan,
            'exposed_paths': found_paths,
            'all_paths': paths,
            'headers': headers_found,
            'threat_level': threat_level
        }
        self.send_sse_event('stats', stats)
        self.send_sse_event('done', 'Scan complete')

def run_server():
    server_address = ('', PORT)
    httpd = http.server.ThreadingHTTPServer(server_address, VulnerabilityScannerHandler)
    print(f"VULNSC Web Server running at http://localhost:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()
