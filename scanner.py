import sys
from scan_engine import ScanEngine

def main():
    print("=================================================")
    print("  VULNSC • CLI Security Recon Engine  v2.0.1")
    print("=================================================")
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter website URL (include http/https): ").strip()
        
    if not url or url in ("http://", "https://", ""):
        print("[-] Error: A valid target URL is required.")
        sys.exit(1)
        
    ports_to_scan = [21, 22, 80, 443, 8080, 8443]
    print(f"[i] Host: {url}")
    print(f"[i] Ports to scan: {ports_to_scan}")
    print("[i] Launching engine...\n")
    
    # Callback to stream real-time logs directly to stdout
    def console_log(text, tag=""):
        sys.stdout.write(text)
        sys.stdout.flush()
        
    def progress_callback(pct):
        pass
        
    engine = ScanEngine(url, ports_to_scan, log_callback=console_log, progress_callback=progress_callback)
    stats = engine.execute_scan()
    
    print("\n=================================================")
    print("  CLI REPORT SUMMARY")
    print("=================================================")
    print(f"Target Host:       {stats.get('host')}")
    print(f"Assessed Threat:   {stats.get('threat_level')}")
    print(f"Open Ports:        {stats.get('open_ports')}")
    print(f"Exposed Paths:     {stats.get('exposed_paths')}")
    print(f"Vulnerabilities:   {len(stats.get('vuln_findings', []))}")
    print(f"CVE Mappings:      {len(stats.get('cve_results', []))}")
    if stats.get('report_file'):
        print(f"HTML Threat Report Saved: reports/{stats.get('report_file')}")
    print("=================================================")

if __name__ == "__main__":
    main()