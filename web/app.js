document.addEventListener('DOMContentLoaded', () => {
    // DOM Cache
    const btnScan = document.getElementById('btn-scan');
    const btnClear = document.getElementById('btn-clear');
    const inputUrl = document.getElementById('target-url');
    const terminalOutput = document.getElementById('terminal-output');
    
    // Status Indicator
    const statusIndicator = document.getElementById('global-status-indicator');
    const statusText = document.getElementById('global-status-text');
    
    // Progress Bar
    const progressContainer = document.getElementById('scan-progress-container');
    const progressFill = document.getElementById('scan-progress-fill');
    const progressPercentage = document.getElementById('scan-progress-percentage');
    
    // Metrics
    const metricProtocol = document.getElementById('metric-protocol');
    const valProtocol = document.getElementById('val-protocol');
    const lblProtocol = document.getElementById('lbl-protocol');
    
    const metricPorts = document.getElementById('metric-ports');
    const valPorts = document.getElementById('val-ports');
    const lblPorts = document.getElementById('lbl-ports');
    
    const metricPaths = document.getElementById('metric-paths');
    const valPaths = document.getElementById('val-paths');
    const lblPaths = document.getElementById('lbl-paths');
    
    const metricThreat = document.getElementById('metric-threat');
    const valThreat = document.getElementById('val-threat');
    const lblThreat = document.getElementById('lbl-threat');
    
    // Tables
    const headersTableBody = document.getElementById('headers-table-body');
    const portsTableBody = document.getElementById('ports-table-body');
    const pathsTableBody = document.getElementById('paths-table-body');
    const vulnsTableBody = document.getElementById('vulns-table-body');
    const cvesTableBody = document.getElementById('cves-table-body');
    
    // Report Banner
    const reportBannerContainer = document.getElementById('report-banner-container');
    const linkDownloadReport = document.getElementById('link-download-report');
    
    // Tabs
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');
    
    let eventSource = null;
    
    // Tab switching logic
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            
            // Remove active classes
            tabButtons.forEach(b => b.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));
            
            // Add active classes
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Helper: Map ports to service names
    const getServiceName = (port) => {
        const services = {
            21: 'FTP',
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT'
        };
        return services[port] || 'Unknown Service';
    };
    
    // Helper: Add log line to terminal
    const addLogLine = (text, tag = '') => {
        const line = document.createElement('div');
        line.className = `log-line ${tag}`;
        line.innerText = text;
        
        // Insert before the cursor line
        const cursorLine = terminalOutput.querySelector('.cursor-line');
        terminalOutput.insertBefore(line, cursorLine);
        
        // Auto-scroll
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    };
    
    // Helper: Clear terminal
    const clearTerminal = () => {
        const cursorLine = terminalOutput.querySelector('.cursor-line');
        terminalOutput.innerHTML = '';
        terminalOutput.appendChild(cursorLine);
    };
    
    // Reset layout UI
    const resetDashboardUI = () => {
        // Reset Status
        statusIndicator.className = 'status-indicator idle';
        statusText.innerText = 'SYSTEM IDLE';
        
        // Reset Progress
        progressContainer.classList.add('hidden');
        progressFill.style.width = '0%';
        progressPercentage.innerText = '0%';
        
        // Reset Metrics cards classes and content
        metricProtocol.className = 'metric-card';
        valProtocol.innerText = '—';
        lblProtocol.innerText = 'Awaiting scan initiation';
        
        metricPorts.className = 'metric-card';
        valPorts.innerText = '—';
        lblPorts.innerText = 'Awaiting scan initiation';
        
        metricPaths.className = 'metric-card';
        valPaths.innerText = '—';
        lblPaths.innerText = 'Awaiting scan initiation';
        
        metricThreat.className = 'metric-card';
        valThreat.innerText = '—';
        lblThreat.innerText = 'Awaiting scan initiation';
        
        // Reset Tables
        headersTableBody.innerHTML = `<tr><td colspan="3" class="empty-state">No headers analyzed yet.</td></tr>`;
        portsTableBody.innerHTML = `<tr><td colspan="3" class="empty-state">No ports scanned yet.</td></tr>`;
        pathsTableBody.innerHTML = `<tr><td colspan="2" class="empty-state">No path discovery results yet.</td></tr>`;
        vulnsTableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No vulnerabilities scanned yet.</td></tr>`;
        cvesTableBody.innerHTML = `<tr><td colspan="5" class="empty-state">No service CVEs mapped yet.</td></tr>`;
        reportBannerContainer.classList.add('hidden');
    };
    
    // Initiate Scan
    const initiateScan = () => {
        let url = inputUrl.value.trim();
        if (!url) {
            alert('Please enter a target URL.');
            return;
        }
        
        // Add protocol if missing
        if (!/^https?:\/\//i.test(url)) {
            url = 'https://' + url;
            inputUrl.value = url;
        }
        
        // Get selected ports
        const portCheckboxes = document.querySelectorAll('input[name="ports"]:checked');
        const selectedPorts = Array.from(portCheckboxes).map(cb => cb.value);
        if (selectedPorts.length === 0) {
            alert('Please select at least one port to scan.');
            return;
        }
        
        // Close existing event source if running
        if (eventSource) {
            eventSource.close();
        }
        
        // UI Updates for starting state
        btnScan.disabled = true;
        btnScan.classList.add('scanning');
        btnScan.querySelector('.btn-text').innerText = 'SCAN RUNNING...';
        
        progressContainer.classList.remove('hidden');
        progressFill.style.width = '0%';
        progressPercentage.innerText = '0%';
        
        statusIndicator.className = 'status-indicator active';
        statusText.innerText = 'SCAN ACTIVE';
        
        resetDashboardUI();
        clearTerminal();
        addLogLine('[i] Establishing connection with scan server...', 'dim');
        
        // Build API URL
        const scanUrl = `/api/scan?url=${encodeURIComponent(url)}&ports=${encodeURIComponent(selectedPorts.join(','))}`;
        
        // Start EventSource
        eventSource = new EventSource(scanUrl);
        
        eventSource.addEventListener('log', (e) => {
            const data = JSON.parse(e.data);
            addLogLine(data.text, data.tag);
        });
        
        eventSource.addEventListener('progress', (e) => {
            const data = JSON.parse(e.data);
            progressFill.style.width = `${data.percent}%`;
            progressPercentage.innerText = `${data.percent}%`;
        });
        
        eventSource.addEventListener('stats', (e) => {
            const stats = JSON.parse(e.data);
            populateStats(stats);
        });
        
        eventSource.addEventListener('done', () => {
            addLogLine('[✔] Done. Scan processes complete.', 'green');
            statusIndicator.className = 'status-indicator success';
            statusText.innerText = 'SCAN SUCCESSFUL';
            cleanupScan();
        });
        
        eventSource.onerror = (err) => {
            console.error('Scan event source error:', err);
            addLogLine('[✘] Error: Connection lost or failed to scan host.', 'red');
            statusIndicator.className = 'status-indicator error';
            statusText.innerText = 'SCAN FAILED';
            cleanupScan();
        };
    };
    
    // Clean up connections and buttons
    const cleanupScan = () => {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
        btnScan.disabled = false;
        btnScan.classList.remove('scanning');
        btnScan.querySelector('.btn-text').innerText = 'INITIATE SCAN';
    };
    
    // Populate stats into metrics cards and detail panels
    const populateStats = (stats) => {
        // 1. Protocol card
        if (stats.https) {
            metricProtocol.className = 'metric-card secure';
            valProtocol.innerText = 'HTTPS';
            lblProtocol.innerText = 'Transport encrypted';
        } else {
            metricProtocol.className = 'metric-card danger';
            valProtocol.innerText = 'HTTP';
            lblProtocol.innerText = 'Transport unencrypted!';
        }
        
        // 2. Ports card
        const openCount = stats.open_ports.length;
        if (openCount === 0) {
            metricPorts.className = 'metric-card secure';
            valPorts.innerText = '0 Open';
            lblPorts.innerText = 'Secure configuration';
        } else if (openCount <= 2) {
            metricPorts.className = 'metric-card warn';
            valPorts.innerText = `${openCount} Open`;
            lblPorts.innerText = 'Review port visibility';
        } else {
            metricPorts.className = 'metric-card danger';
            valPorts.innerText = `${openCount} Open`;
            lblPorts.innerText = 'High exposure risk!';
        }
        
        // 3. Paths card
        const pathCount = stats.exposed_paths.length;
        if (pathCount === 0) {
            metricPaths.className = 'metric-card secure';
            valPaths.innerText = '0 Detected';
            lblPaths.innerText = 'No exposed system paths';
        } else if (pathCount <= 2) {
            metricPaths.className = 'metric-card warn';
            valPaths.innerText = `${pathCount} Exposed`;
            lblPaths.innerText = 'Sensitive paths visible';
        } else {
            metricPaths.className = 'metric-card danger';
            valPaths.innerText = `${pathCount} Exposed`;
            lblPaths.innerText = 'Critical folders exposed!';
        }
        
        // 4. Threat Level Card
        valThreat.innerText = stats.threat_level;
        if (stats.threat_level === 'LOW') {
            metricThreat.className = 'metric-card secure';
            lblThreat.innerText = 'System is relatively secure';
        } else if (stats.threat_level === 'MEDIUM') {
            metricThreat.className = 'metric-card warn';
            lblThreat.innerText = 'Potential issues identified';
        } else {
            metricThreat.className = 'metric-card danger';
            lblThreat.innerText = 'Severe vulnerability risks!';
        }
        
        // 5. Populate headers table
        headersTableBody.innerHTML = '';
        const headerInfo = {
            'Content-Security-Policy': { desc: 'Prevents XSS attacks', risk: 'HIGH' },
            'Strict-Transport-Security': { desc: 'Enforces secure HTTPS', risk: 'HIGH' },
            'X-Frame-Options': { desc: 'Protects against clickjacking', risk: 'MEDIUM' },
            'X-Content-Type-Options': { desc: 'Disables MIME sniffing', risk: 'LOW' },
            'Access-Control-Allow-Origin': { desc: 'CORS policy mapping', risk: 'LOW' },
            'Server': { desc: 'Discloses server software info', info: true },
            'X-Powered-By': { desc: 'Discloses backend framework', info: true }
        };
        
        Object.keys(headerInfo).forEach(header => {
            const val = stats.headers[header];
            const meta = headerInfo[header];
            let statusBadge = '';
            
            if (meta.info) {
                // Info headers (we want them absent for security by obscurity)
                if (val) {
                    statusBadge = `<span class="badge warn">INFO LEAK</span>`;
                } else {
                    statusBadge = `<span class="badge success">HIDDEN</span>`;
                }
            } else {
                // Standard security headers (we want them present)
                if (val) {
                    if (header === 'Access-Control-Allow-Origin' && val === '*') {
                        statusBadge = `<span class="badge warn">WILDCARD CORS</span>`;
                    } else {
                        statusBadge = `<span class="badge success">SECURE</span>`;
                    }
                } else {
                    const riskClass = meta.risk === 'HIGH' ? 'danger' : 'warn';
                    statusBadge = `<span class="badge ${riskClass}">MISSING (${meta.risk})</span>`;
                }
            }
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>
                    <div style="font-weight: 600;">${header}</div>
                    <div style="font-size: 11px; color: var(--text-dim);">${meta.desc}</div>
                </td>
                <td style="font-family: var(--font-mono); font-size: 11px; word-break: break-all;">
                    ${val ? val : '<span style="color: var(--text-dim);">Not Set</span>'}
                </td>
                <td>${statusBadge}</td>
            `;
            headersTableBody.appendChild(row);
        });
        
        // 6. Populate ports table
        portsTableBody.innerHTML = '';
        stats.all_ports.forEach(port => {
            const isOpen = stats.open_ports.includes(port);
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family: var(--font-mono); font-weight: 700;">${port}</td>
                <td>${getServiceName(port)}</td>
                <td>
                    <span class="badge ${isOpen ? 'danger' : 'dim'}">
                        ${isOpen ? 'OPEN' : 'CLOSED'}
                    </span>
                </td>
            `;
            portsTableBody.appendChild(row);
        });
        
        // 7. Populate paths table
        pathsTableBody.innerHTML = '';
        stats.all_paths.forEach(path => {
            const isExposed = stats.exposed_paths.includes(path);
            const row = document.createElement('tr');
            row.innerHTML = `
                <td style="font-family: var(--font-mono);">${path}</td>
                <td>
                    <span class="badge ${isExposed ? 'danger' : 'dim'}">
                        ${isExposed ? 'EXPOSED (200 OK)' : 'SECURE (404/403)'}
                    </span>
                </td>
            `;
            pathsTableBody.appendChild(row);
        });
        
        // 8. Populate Active Web Vulnerabilities Table
        vulnsTableBody.innerHTML = '';
        if (stats.vuln_findings && stats.vuln_findings.length > 0) {
            stats.vuln_findings.forEach(vuln => {
                const row = document.createElement('tr');
                const confClass = vuln.confidence === 'HIGH' ? 'danger' : 'warn';
                row.innerHTML = `
                    <td style="font-weight: 700;">${vuln.type}</td>
                    <td style="font-family: var(--font-mono); font-size: 11px; word-break: break-all;">${vuln.endpoint}</td>
                    <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); word-break: break-all;">${vuln.evidence}</td>
                    <td><span class="badge ${confClass}">${vuln.confidence}</span></td>
                `;
                vulnsTableBody.appendChild(row);
            });
        } else {
            vulnsTableBody.innerHTML = `<tr><td colspan="4" class="empty-state">No vulnerabilities detected.</td></tr>`;
        }

        // 9. Populate Service CVEs Table
        cvesTableBody.innerHTML = '';
        if (stats.cve_results && stats.cve_results.length > 0) {
            stats.cve_results.sort((a, b) => b.cvss_score - a.cvss_score);
            stats.cve_results.forEach(cve => {
                const row = document.createElement('tr');
                const sevClass = (cve.severity === 'CRITICAL' || cve.severity === 'HIGH') ? 'danger' : (cve.severity === 'MEDIUM' ? 'warn' : 'dim');
                row.innerHTML = `
                    <td style="font-family: var(--font-mono); font-weight: 700;">${cve.cve_id}</td>
                    <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">${cve.cvss_score}</td>
                    <td><span class="badge ${sevClass}">${cve.severity}</span></td>
                    <td style="font-size: 11px;">Port ${cve.port} (${cve.service})</td>
                    <td style="font-size: 11px; color: var(--text-dim); max-width: 320px; word-break: break-word;">${cve.description}</td>
                `;
                cvesTableBody.appendChild(row);
            });
        } else {
            cvesTableBody.innerHTML = `<tr><td colspan="5" class="empty-state">No service CVEs mapped.</td></tr>`;
        }

        // 10. Show report banner
        if (stats.report_file) {
            linkDownloadReport.href = `/reports/${stats.report_file}`;
            reportBannerContainer.classList.remove('hidden');
        }
    };
    
    // Event listeners
    btnScan.addEventListener('click', initiateScan);
    
    btnClear.addEventListener('click', () => {
        cleanupScan();
        resetDashboardUI();
        clearTerminal();
        addLogLine('Terminal Console reset. Ready to initiate scan.', 'dim');
    });
});
