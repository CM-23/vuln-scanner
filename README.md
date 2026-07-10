# 🛡️ VULNSC - Threat Intelligence & Vulnerability Scanner

A Python-based vulnerability scanner with a modern web dashboard, desktop GUI, and CLI support. 
Designed for basic reconnaissance, port scanning, and web security analysis.

---

## ⚔️ Features

- 🌐 **Web-based Dashboard**: Beautiful, responsive cyber-themed dashboard built with HTML, CSS, and JS.
- ⚡ **Real-Time Log Streaming**: Uses Server-Sent Events (SSE) to stream port scans and path discoveries in real-time.
- 🔍 **Port Scanning**: Custom scanning options for standard system ports (21, 22, 80, 443, 8080, 8443).
- 📂 **Sensitive Path Discovery**: Automatic check for exposed system files (e.g. `/admin`, `/login`, `/.env`, `/backup`).
- 🧾 **Header Fingerprinting**: Security evaluation of response headers (CSP, HSTS, X-Frame-Options, Server, etc.) and Threat Level assessment.
- 🖥️ **Desktop GUI (Tkinter)** & **CLI Support**.

---

## 🛠️ Tech Stack

- **Backend**: Python (standard library `http.server.ThreadingHTTPServer`, `socket`, `requests`)
- **Frontend**: HTML5, Vanilla CSS3 (Glassmorphism, custom grid overlays), JavaScript (ES6, EventSource SSE API)

---

## 🚀 How to Run

### 1. Web Dashboard (Runs in Chrome/Edge/Firefox)

To run the web app locally:

1. Clone the repository and navigate into the folder:
   ```bash
   git clone https://github.com/CM-23/vuln-scanner.git
   cd vuln-scanner
   ```
2. Install the required requests library:
   ```bash
   pip install -r requirements.txt
   ```
3. Run using npm (or run `python server.py` directly):
   ```bash
   npm run dev
   ```
4. Open your browser and navigate to:
   * **`http://localhost:80`** (or just `http://localhost`)

---

### 2. Desktop GUI Version (Tkinter)
```bash
python scanner_gui.py
```

### 3. CLI Version
```bash
python scanner.py
```
