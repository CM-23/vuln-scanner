# 🛡️ VULNSC - Threat Intelligence & Vulnerability Scanner

[![Live Demo](https://img.shields.io/badge/Demo-Live%20on%20Render-brightgreen?style=for-the-badge&logo=render)](https://vuln-scanner-romc.onrender.com/)

A Python-based vulnerability scanner with a modern web dashboard, desktop GUI, and CLI support. 
Designed for basic reconnaissance, port scanning, and web security analysis.

---

## ⚔️ Features

- 🌐 **Web-based Dashboard**: Beautiful, responsive cyber-themed dashboard built with HTML, CSS, and JS.
- ⚡ **Real-Time Log Streaming**: Uses Server-Sent Events (SSE) to stream threaded scans, vulnerabilites, and CVE mappings.
- 🔀 **Multithreaded Scan Engine**: Parallelized port scanning and directory discovery using Python `ThreadPoolExecutor` for fast results.
- 🛡️ **CVE & CVSS Mapping**: Automatic banner grabbing on open ports matched against the NVD API v2.0 with local caching and rate-limit retry logic.
- 🕵️ **Active Web Auditing**: Non-destructive, safe checks for SQL Injection, reflected XSS, default administrative credentials, and insecure session cookie flags.
- 📂 **Sensitive Path Discovery**: Parallelized check for exposed folder directories (e.g., `/admin`, `/.env`, `/backup`).
- 🧾 **Header Fingerprinting**: Evaluation of security headers (CSP, HSTS, X-Frame-Options, CORS, etc.) and global threat level assessments.
- 📊 **Auto-Generated HTML Threat Reports**: Self-contained assessment reports saved with timestamped filenames in the `/reports` directory.
- 🖥️ **Desktop GUI (Tkinter)** & **CLI Support**.

---

## 🛠️ Tech Stack

- **Backend**: Python 3 (standard libraries: `http.server.ThreadingHTTPServer`, `socket`, `concurrent.futures`, `html.parser`, `urllib.parse`, and the pre-existing `requests` package)
- **Frontend**: HTML5, Vanilla CSS3 (Glassmorphism, custom grid overlays), JavaScript (ES6, EventSource SSE API)

---

## 📡 REST API Layer

VULNSC includes a programmatic REST API that can be consumed directly without the browser dashboard:

- **`POST /api/scan`**: Initiates a scan in the background. Returns a unique Scan ID.
  - **Body (JSON or urlencoded)**:
    ```json
    {
      "url": "http://example.com",
      "ports": [80, 443, 8080]
    }
    ```
  - **Response (201 Created)**:
    ```json
    {
      "scan_id": "893d56b0-74e7-49f6-a83d-6b5e02e1fd4e",
      "status": "running"
    }
    ```
- **`GET /api/scan/{id}/status`**: Returns the current percentage and state.
  - **Response (200 OK)**:
    ```json
    {
      "scan_id": "893d56b0-74e7-49f6-a83d-6b5e02e1fd4e",
      "status": "completed",
      "percent": 100
    }
    ```
- **`GET /api/scan/{id}/report`**: Returns the detailed vulnerability findings, port states, and CVE mapping arrays in JSON.

---

## 🚀 How to Run

### 🌐 Live Demo (No Installation Required)

Access the live, fully deployed cyber dashboard directly on Render:
👉 **[vuln-scanner-romc.onrender.com](https://vuln-scanner-romc.onrender.com/)**

---

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
