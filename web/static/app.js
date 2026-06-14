console.log("Dashboard initializing");

const state = {
    vms: [],
    alerts: [],
    auditLog: [],
    scanCount: 0,
    uptime: 0,
    syscallData: null,
    hiddenData: null,
    idtData: null,
    fallbackData: null,
    guestData: null,
    monitoringActive: false,
    processedProcesses: [],
    rootkitCount: 0,
    suspiciousCount: 0,
    infoCount: 0
};

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}

function formatTime(timestamp) {
    if (!timestamp) return '--:--:--';
    var d = new Date(timestamp * 1000);
    return d.getHours().toString().padStart(2,'0') + ':' + 
           d.getMinutes().toString().padStart(2,'0') + ':' + 
           d.getSeconds().toString().padStart(2,'0');
}

function classifyAlert(description, severity) {
    var lowerDesc = description.toLowerCase();
    if (severity === 2) return 'rootkit';
    if (lowerDesc.includes('error') || lowerDesc.includes('invalid') || 
        lowerDesc.includes('hook') || lowerDesc.includes('hooked') ||
        lowerDesc.includes('corruption') || lowerDesc.includes('suspicious')) {
        return 'suspicious';
    }
    return 'info';
}

async function fetchVms() {
    try {
        const response = await fetch('/api/vms', { cache: 'no-store' });
        if (response.ok) return await response.json();
    } catch(e) { console.log('fetchVms error:', e); }
    return null;
}

async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts', { cache: 'no-store' });
        if (response.ok) return await response.json();
    } catch(e) { console.log('fetchAlerts error:', e); }
    return [];
}

async function fetchForensicLog() {
    try {
        const response = await fetch('/api/forensic-log', { cache: 'no-store' });
        if (response.ok) return await response.text();
    } catch(e) { console.log('fetchForensicLog error:', e); }
    return '';
}

async function startMonitoring(vmName) {
    try {
        const response = await fetch('/api/monitor/' + vmName, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'start' })
        });
        if (response.ok) {
            console.log('Monitoring started for', vmName);
            return true;
        }
    } catch(e) { console.log('startMonitoring error:', e); }
    return false;
}

async function stopMonitoring(vmName) {
    try {
        const response = await fetch('/api/monitor/' + vmName, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'stop' })
        });
        if (response.ok) {
            console.log('Monitoring stopped for', vmName);
            return true;
        }
    } catch(e) { console.log('stopMonitoring error:', e); }
    return false;
}

async function discoverVMs() {
    try {
        const response = await fetch('/api/discover', { method: 'POST' });
        if (response.ok) {
            const data = await response.json();
            if (data && data.vms) {
                state.vms = data.vms;
                renderVMStatus();
                return data.vms;
            }
        }
    } catch(e) { console.log('discoverVMs error:', e); }
    return [];
}

function parseProcessNamesFromText(data) {
    var processes = [];
    if (!data) return processes;
    
    var lines = data.split('\n');
    
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        // Look for process names in the output
        if (line.includes("Found process name") && line.includes("at physical")) {
            var match = line.match(/Found process name '([^']+)' at physical (0x[0-9a-f]+)/);
            if (match) {
                processes.push({
                    name: match[1],
                    address: match[2]
                });
            }
        }
        // Also look for the format from progressive updates
        else if (line.includes("Found:") && line.includes("at 0x")) {
            var match2 = line.match(/Found: ([^\s]+) at (0x[0-9a-f]+)/);
            if (match2) {
                processes.push({
                    name: match2[1],
                    address: match2[2]
                });
            }
        }
    }
    
    return processes;
}

function renderProcessTable(processes) {
    var hiddenDiv = document.getElementById('hidden-content');
    if (!hiddenDiv) return;
    
    if (!processes || processes.length === 0) {
        hiddenDiv.innerHTML = '<div style="color:#ffaa00; padding:20px; text-align:center;">No process data available yet. Scanning in progress...</div>';
        return;
    }
    
    var html = '<div style="margin-bottom:10px; color:#00ff00;">Found ' + processes.length + ' process name candidates in memory:</div>';
    html += '<div style="overflow-x:auto;">';
    html += '<table style="width:100%; border-collapse:collapse; font-family:monospace; font-size:12px;">';
    html += '<thead><tr style="border-bottom:1px solid #00f3ff;">';
    html += '<th style="text-align:left; padding:8px;">Process Name</th>';
    html += '<th style="text-align:left; padding:8px;">Physical Address</th>';
    html += '</tr></thead><tbody>';
    
    var displayCount = Math.min(processes.length, 200);
    for (var i = 0; i < displayCount; i++) {
        var rowClass = (i % 2 === 0) ? 'style="background:rgba(255,255,255,0.02);"' : '';
        html += '<tr ' + rowClass + '>';
        html += '<td style="padding:6px 8px;">' + escapeHtml(processes[i].name) + '</tr>';
        html += '<td style="padding:6px 8px; color:#00ff00;">' + escapeHtml(processes[i].address) + '</tr>';
        html += '</tr>';
    }
    
    if (processes.length > 200) {
        html += '<tr><td colspan="2" style="padding:6px 8px; text-align:center; color:#888;">... and ' + (processes.length - 200) + ' more processes</td></tr>';
    }
    
    html += '</tbody>柵</div>';
    hiddenDiv.innerHTML = html;
}

async function loadModuleData(module) {
    if (!state.vms || state.vms.length === 0) return;
    
    var vmName = state.vms[0].name;
    var contentDiv = document.getElementById(module + '-content');
    if (!contentDiv) return;
    
    try {
        var response = await fetch('/api/scan/' + vmName + '/' + module, { cache: 'no-store' });
        if (response.ok) {
            var data = await response.text();
            
            if (module === 'syscall') {
                state.syscallData = data;
                if (data && data.length > 50) {
                    contentDiv.innerHTML = '<pre style="margin:0;font-family:monospace;background:#0a0a0f;color:#00ff00;white-space:pre-wrap;font-size:11px;max-height:500px;overflow-y:auto;">' + escapeHtml(data) + '</pre>';
                } else {
                    contentDiv.innerHTML = '<div style="color:#ffaa00; padding:20px;">No syscall data yet. Scan in progress...</div>';
                }
            }
            else if (module === 'hidden') {
                state.hiddenData = data;
                var processes = parseProcessNamesFromText(data);
                state.processedProcesses = processes;
                renderProcessTable(processes);
            }
            else if (module === 'idt') {
                state.idtData = data;
                if (data && data.length > 50) {
                    contentDiv.innerHTML = '<pre style="margin:0;font-family:monospace;background:#0a0a0f;color:#00ff00;white-space:pre-wrap;font-size:12px;">' + escapeHtml(data) + '</pre>';
                } else {
                    contentDiv.innerHTML = '<div style="color:#ffaa00; padding:20px;">IDT detection limited due to KPTI. See syscall detection for active monitoring.</div>';
                }
            }
            else if (module === 'fallback') {
                state.fallbackData = data;
                if (data && data.length > 50) {
                    contentDiv.innerHTML = '<pre style="margin:0;font-family:monospace;background:#0a0a0f;color:#00ff00;white-space:pre-wrap;font-size:12px;">' + escapeHtml(data) + '</pre>';
                } else {
                    contentDiv.innerHTML = '<div style="color:#ffaa00; padding:20px;">Fallback detection in progress. Scanning memory for signatures...</div>';
                }
            }
            else if (module === 'guest') {
                state.guestData = data;
                if (data && data.length > 50 && !data.includes('No scan data')) {
                    contentDiv.innerHTML = '<pre style="margin:0;font-family:monospace;background:#0a0a0f;color:#00ff00;white-space:pre-wrap;font-size:12px;">' + escapeHtml(data) + '</pre>';
                } else {
                    contentDiv.innerHTML = '<div style="color:#ffaa00; padding:20px;">Guest agent not responding. Install qemu-guest-agent in the VM for guest information.</div>';
                }
            }
        }
    } catch(e) {
        console.log('Error loading', module, e);
    }
}

function loadAllModuleData() {
    if (!state.monitoringActive) return;
    loadModuleData('syscall');
    loadModuleData('hidden');
    loadModuleData('idt');
    loadModuleData('fallback');
    loadModuleData('guest');
}

function renderVMStatus() {
    var row = document.getElementById('vm-status-row');
    if (!row) return;
    
    row.innerHTML = '';
    
    if (!state.vms || state.vms.length === 0) {
        row.innerHTML = '<div style="color:var(--text-muted);padding:1rem;">No VMs discovered. Click DISCOVER VMS button.</div>';
        return;
    }
    
    for (var i = 0; i < state.vms.length; i++) {
        var vm = state.vms[i];
        var vmEl = document.createElement('div');
        vmEl.className = 'vm-status';
        
        var isConnected = (vm.is_connected === true);
        var isMonitored = (vm.is_monitored === true);
        
        vmEl.innerHTML = 
            '<span class="vm-label">VM:</span>' +
            '<span class="vm-name">' + escapeHtml(vm.name) + '</span>' +
            '<span class="status-dot ' + (isConnected ? 'online' : 'offline') + '"></span>' +
            '<span>' + (isConnected ? 'ONLINE' : 'OFFLINE') + '</span>' +
            '<button class="vm-monitor-btn" data-vm="' + escapeHtml(vm.name) + '" data-monitored="' + isMonitored + '">' +
            (isMonitored ? 'STOP MONITORING' : 'START MONITORING') +
            '</button>';
        
        var btn = vmEl.querySelector('.vm-monitor-btn');
        btn.addEventListener('click', (function(vmName, currentMonitored) {
            return async function() {
                var success = false;
                var newMonitored = !currentMonitored;
                
                this.textContent = 'PROCESSING...';
                this.disabled = true;
                
                if (newMonitored) {
                    success = await startMonitoring(vmName);
                } else {
                    success = await stopMonitoring(vmName);
                }
                
                if (success) {
                    state.monitoringActive = newMonitored;
                    var vmsData = await fetchVms();
                    if (vmsData && vmsData.vms) {
                        state.vms = vmsData.vms;
                        renderVMStatus();
                    }
                    if (newMonitored) {
                        loadAllModuleData();
                    }
                } else {
                    this.textContent = currentMonitored ? 'STOP MONITORING' : 'START MONITORING';
                    this.disabled = false;
                }
            };
        })(vm.name, isMonitored));
        
        row.appendChild(vmEl);
    }
}

function renderAlerts() {
    var alertList = document.getElementById('alert-list');
    if (!alertList) return;
    
    if (!state.alerts || state.alerts.length === 0) {
        alertList.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:1rem;">No alerts.</div>';
        return;
    }
    
    var recent = state.alerts.slice(-30).reverse();
    var html = '';
    
    for (var i = 0; i < recent.length; i++) {
        var alert = recent[i];
        var classification = classifyAlert(alert.description, alert.severity);
        var severityLabel = classification === 'rootkit' ? 'ROOTKIT' : (classification === 'suspicious' ? 'SUSPICIOUS' : 'INFO');
        var severityClass = classification === 'rootkit' ? 'critical' : (classification === 'suspicious' ? 'high' : 'info');
        
        html += 
            '<div class="alert-item">' +
                '<div class="alert-header">' +
                    '<span class="alert-severity ' + severityClass + '">' + severityLabel + '</span>' +
                    '<span class="alert-time">' + (alert.time || formatTime(alert.timestamp)) + '</span>' +
                '</div>' +
                '<div class="alert-title">' + escapeHtml(alert.description || 'Alert') + '</div>' +
                '<div class="alert-vm">' + escapeHtml(alert.vm || alert.vm_name || 'SYSTEM') + '</div>' +
            '</div>';
    }
    
    alertList.innerHTML = html;
    updateAlertCounts(state.alerts);
}

function updateAlertCounts(alerts) {
    state.rootkitCount = 0;
    state.suspiciousCount = 0;
    state.infoCount = 0;
    
    for (var i = 0; i < alerts.length; i++) {
        var classification = classifyAlert(alerts[i].description, alerts[i].severity);
        if (classification === 'rootkit') state.rootkitCount++;
        else if (classification === 'suspicious') state.suspiciousCount++;
        else state.infoCount++;
    }
    
    var rootkitEl = document.getElementById('rootkit-count');
    var suspiciousEl = document.getElementById('suspicious-count');
    var infoEl = document.getElementById('info-count');
    
    if (rootkitEl) rootkitEl.textContent = state.rootkitCount;
    if (suspiciousEl) suspiciousEl.textContent = state.suspiciousCount;
    if (infoEl) infoEl.textContent = state.infoCount;
}

function renderForensicLog() {
    var logList = document.getElementById('forensic-log-list');
    if (!logList) return;
    
    if (!state.auditLog || state.auditLog.length === 0) {
        logList.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:1rem;">No forensic log entries yet.</div>';
        return;
    }
    
    var lines = state.auditLog.split('\n').filter(function(l) { return l.trim(); }).slice(-30).reverse();
    var html = '';
    
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        var displayClass = '';
        if (line.includes('ROOTKIT')) displayClass = 'style="color:#ff0040;"';
        else if (line.includes('ERROR') || line.includes('HOOK')) displayClass = 'style="color:#ffaa00;"';
        html += '<div class="audit-item"><pre style="margin:0;font-size:0.75rem;' + displayClass + '">' + escapeHtml(line) + '</pre></div>';
    }
    
    logList.innerHTML = html;
}

function renderModules() {
    var moduleList = document.getElementById('module-list');
    if (!moduleList) return;
    
    var modules = [
        { name: 'process_scanner', desc: 'Hidden process detection via VMI - scans memory for process names' },
        { name: 'syscall_detection', desc: 'Syscall table hook monitoring - validates 100 syscall handlers' },
        { name: 'idt_detection', desc: 'IDT integrity verification - limited by KPTI on kernel 6.2.0' },
        { name: 'fallback_detection', desc: 'Heuristic fallback methods - scans for rootkit signatures' }
    ];
    
    var html = '';
    for (var i = 0; i < modules.length; i++) {
        html += 
            '<div class="module-item">' +
                '<div class="module-header">' +
                    '<span class="module-name">' + modules[i].name + '</span>' +
                '</div>' +
                '<div class="module-desc">' + modules[i].desc + '</div>' +
            '</div>';
    }
    
    moduleList.innerHTML = html;
}

function updateStats() {
    var scanCountEl = document.getElementById('scan-count');
    if (scanCountEl) scanCountEl.textContent = state.scanCount;
}

function updateStatus(status) {
    var statusText = document.getElementById('status-text');
    if (statusText) statusText.textContent = status;
}

function startUptimeCounter() {
    setInterval(function() {
        state.uptime++;
        var uptimeEl = document.getElementById('uptime-value');
        if (uptimeEl) {
            var hours = Math.floor(state.uptime / 3600);
            var minutes = Math.floor((state.uptime % 3600) / 60);
            var seconds = state.uptime % 60;
            uptimeEl.textContent = hours.toString().padStart(2,'0') + ':' + 
                                   minutes.toString().padStart(2,'0') + ':' + 
                                   seconds.toString().padStart(2,'0');
        }
    }, 1000);
}

function switchTab(tabName) {
    var tabs = document.querySelectorAll('.nav-tab');
    for (var i = 0; i < tabs.length; i++) {
        if (tabs[i].dataset.tab === tabName) {
            tabs[i].classList.add('active');
        } else {
            tabs[i].classList.remove('active');
        }
    }
    
    var tabContents = ['overview', 'processes', 'syscall', 'idt', 'fallback', 'guest'];
    for (var i = 0; i < tabContents.length; i++) {
        var el = document.getElementById(tabContents[i] + '-tab');
        if (el) {
            el.style.display = (tabContents[i] === tabName) ? 'block' : 'none';
        }
    }
    
    // Refresh data when switching tabs
    if (tabName === 'processes' && state.processedProcesses.length > 0) {
        renderProcessTable(state.processedProcesses);
    } else if (tabName === 'processes') {
        loadModuleData('hidden');
    }
    if (tabName === 'syscall') loadModuleData('syscall');
    if (tabName === 'idt') loadModuleData('idt');
    if (tabName === 'fallback') loadModuleData('fallback');
    if (tabName === 'guest') loadModuleData('guest');
}

// Auto-refresh data every 3 seconds
function startContinuousDataRefresh() {
    setInterval(function() {
        if (state.monitoringActive && state.vms.length > 0) {
            loadModuleData('syscall');
            loadModuleData('hidden');
            loadModuleData('idt');
            loadModuleData('fallback');
            loadModuleData('guest');
        }
    }, 3000);
}

async function loadInitialData() {
    updateStatus('CONNECTING');
    
    var vmsData = await fetchVms();
    if (vmsData && vmsData.vms) {
        state.vms = vmsData.vms;
        renderVMStatus();
    }
    
    var alertsData = await fetchAlerts();
    if (alertsData && Array.isArray(alertsData)) {
        state.alerts = alertsData;
        renderAlerts();
        updateAlertCounts(state.alerts);
    }
    
    var logData = await fetchForensicLog();
    if (logData) {
        state.auditLog = logData;
        renderForensicLog();
    }
    
    renderModules();
    updateStatus('MONITORING');
}

function startPolling() {
    setInterval(async function() {
        var data = await fetchVms();
        if (data && data.vms) {
            var hadMonitoring = state.monitoringActive;
            state.vms = data.vms;
            renderVMStatus();
            for (var i = 0; i < state.vms.length; i++) {
                if (state.vms[i].is_monitored === true) {
                    if (!hadMonitoring) {
                        state.monitoringActive = true;
                        loadAllModuleData();
                    }
                    break;
                }
            }
        }
        state.scanCount++;
        updateStats();
    }, 5000);
    
    setInterval(async function() {
        var alerts = await fetchAlerts();
        if (alerts && Array.isArray(alerts)) {
            state.alerts = alerts;
            renderAlerts();
            updateAlertCounts(state.alerts);
        }
    }, 3000);
    
    setInterval(async function() {
        var log = await fetchForensicLog();
        if (log) {
            state.auditLog = log;
            renderForensicLog();
        }
    }, 5000);
}

document.addEventListener('DOMContentLoaded', function() {
    console.log("DOM loaded");
    
    var navTabs = document.querySelectorAll('.nav-tab');
    for (var i = 0; i < navTabs.length; i++) {
        navTabs[i].addEventListener('click', function() {
            switchTab(this.dataset.tab);
        });
    }
    
    var discoverBtn = document.getElementById('discover-btn');
    if (discoverBtn) {
        discoverBtn.addEventListener('click', async function() {
            updateStatus('DISCOVERING');
            await discoverVMs();
            updateStatus('MONITORING');
        });
    }
    
    var exportBtn = document.getElementById('export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            var exportData = {
                timestamp: new Date().toISOString(),
                vms: state.vms,
                alerts: state.alerts,
                processes: state.processedProcesses,
                syscallTable: state.syscallData,
                rootkitCount: state.rootkitCount,
                suspiciousCount: state.suspiciousCount
            };
            var blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'forensic-evidence-' + Date.now() + '.json';
            a.click();
            URL.revokeObjectURL(url);
        });
    }
    
    startUptimeCounter();
    loadInitialData();
    startPolling();
    startContinuousDataRefresh();
});
