import os
import sys
import json
import socket
import urllib.parse
import http.server
import time
import uuid
import threading
import requests
from scan_engine import ScanEngine, REPORTS_DIR

PORT = int(os.environ.get('PORT', 80))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')

# Global database for background scans
scans = {}
scans_lock = threading.Lock()

def run_background_scan(scan_id, target_url, ports_to_scan):
    def log_cb(text, tag):
        with scans_lock:
            if scan_id in scans:
                scans[scan_id]["logs"].append({"text": text, "tag": tag})
                
    def progress_cb(pct):
        with scans_lock:
            if scan_id in scans:
                scans[scan_id]["percent"] = pct

    engine = ScanEngine(target_url, ports_to_scan, log_callback=log_cb, progress_callback=progress_cb)
    try:
        stats = engine.execute_scan()
        with scans_lock:
            if scan_id in scans:
                scans[scan_id]["status"] = "completed"
                scans[scan_id]["stats"] = stats
                scans[scan_id]["percent"] = 100
    except Exception as e:
        with scans_lock:
            if scan_id in scans:
                scans[scan_id]["status"] = "failed"
                scans[scan_id]["error"] = str(e)

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
        elif path.startswith('/reports/'):
            filename = os.path.basename(path)
            report_path = os.path.join(REPORTS_DIR, filename)
            self.serve_file(report_path, 'text/html')
        elif path.startswith('/api/scan/'):
            parts = path.strip('/').split('/')
            if len(parts) == 4:
                scan_id = parts[2]
                endpoint = parts[3]
                if endpoint == 'status':
                    self.handle_api_status(scan_id)
                    return
                elif endpoint == 'report':
                    self.handle_api_report(scan_id)
                    return
            self.send_error(404, "Endpoint not found")
        else:
            self.send_error(404, "File not found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        if path == '/api/scan':
            self.handle_api_scan_post()
        else:
            self.send_error(404, "Endpoint not found")

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

        # Run scan using ScanEngine
        engine = ScanEngine(target_url, ports_to_scan, log_callback=log_to_client, progress_callback=update_progress)
        stats = engine.execute_scan()
        
        self.send_sse_event('stats', stats)
        self.send_sse_event('done', 'Scan complete')

    def handle_api_scan_post(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Default options
            target_url = ""
            ports_to_scan = [21, 22, 80, 443, 8080, 8443]
            
            if post_data:
                try:
                    # Attempt to parse JSON
                    data = json.loads(post_data.decode('utf-8'))
                    target_url = data.get('url', '').strip()
                    if 'ports' in data:
                        if isinstance(data['ports'], list):
                            ports_to_scan = [int(p) for p in data['ports']]
                        elif isinstance(data['ports'], str):
                            ports_to_scan = [int(p.strip()) for p in data['ports'].split(',') if p.strip().isdigit()]
                except Exception:
                    # Fallback to form URL encoded if JSON parse failed
                    try:
                        data = urllib.parse.parse_qs(post_data.decode('utf-8'))
                        if 'url' in data:
                            target_url = data['url'][0].strip()
                        if 'ports' in data:
                            ports_to_scan = [int(p.strip()) for p in data['ports'][0].split(',') if p.strip().isdigit()]
                    except Exception:
                        pass
            
            if not target_url:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'URL is required'}).encode('utf-8'))
                return

            scan_id = str(uuid.uuid4())
            with scans_lock:
                scans[scan_id] = {
                    "status": "running",
                    "percent": 0,
                    "target_url": target_url,
                    "logs": [],
                    "stats": None
                }

            # Start scan in a background daemon thread
            t = threading.Thread(target=run_background_scan, args=(scan_id, target_url, ports_to_scan), daemon=True)
            t.start()

            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'scan_id': scan_id, 'status': 'running'}).encode('utf-8'))

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': f'Internal server error: {e}'}).encode('utf-8'))

    def handle_api_status(self, scan_id):
        with scans_lock:
            scan = scans.get(scan_id)
            
        if not scan:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Scan ID not found'}).encode('utf-8'))
            return
            
        response = {
            'scan_id': scan_id,
            'status': scan['status'],
            'percent': scan['percent']
        }
        if 'error' in scan:
            response['error'] = scan['error']
            
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_api_report(self, scan_id):
        with scans_lock:
            scan = scans.get(scan_id)
            
        if not scan:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Scan ID not found'}).encode('utf-8'))
            return
            
        if scan['status'] != 'completed':
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': f'Scan is in state: {scan["status"]}'}).encode('utf-8'))
            return
            
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(scan['stats']).encode('utf-8'))

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
