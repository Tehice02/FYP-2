/**
 * NIDS Dashboard JavaScript
 * Handles real-time updates, WebSocket communication, and user interactions
 */

// Global variables
let socket;
let attackPieChart;
let packetLineChart;
let alertCount = 0;
let autoScroll = true;
let isMonitoring = false;
let seenAlertKeys = new Set();

// Chart data
let packetRateData = {
    labels: [],
    values: []
};

const MAX_CHART_POINTS = 30;

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 NIDS Dashboard initializing...');
    
    // Initialize sidebar toggle
    initializeSidebarToggle();
    
    // Initialize WebSocket connection
    initializeWebSocket();
    
    // Initialize charts
    initializeCharts();
    
    // Setup event listeners
    setupEventListeners();
    
    // Load initial data
    loadInitialData();
    
    // Load available interfaces
    loadAvailableInterfaces();
    console.log('✓ Dashboard initialized successfully');
});

// ============================================================================
// SIDEBAR TOGGLE
// ============================================================================

function initializeSidebarToggle() {
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const headerToggle = document.getElementById('header-sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    const body = document.body;
    
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            body.classList.toggle('sidebar-collapsed');
            const isCollapsed = sidebar.classList.contains('collapsed');
            localStorage.setItem('sidebar-collapsed', isCollapsed);
        });
    }
    
    if (headerToggle) {
        headerToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            body.classList.toggle('sidebar-collapsed');
            const isCollapsed = sidebar.classList.contains('collapsed');
            localStorage.setItem('sidebar-collapsed', isCollapsed);
        });
    }
    
    // Restore sidebar state
    const wasCollapsed = localStorage.getItem('sidebar-collapsed') === 'true';
    if (wasCollapsed) {
        sidebar.classList.add('collapsed');
        body.classList.add('sidebar-collapsed');
    }
}

// ============================================================================
// WEBSOCKET SETUP
// ============================================================================

function initializeWebSocket() {
    // Connect to Flask-SocketIO server
    socket = io(window.location.origin);
    
    // Connection events
    socket.on('connect', () => {
        console.log('✓ Connected to NIDS server');
        updateConnectionStatus(true);
    });
    
    socket.on('disconnect', () => {
        console.log('✗ Disconnected from NIDS server');
        updateConnectionStatus(false);
    });
    
    socket.on('connection_response', (data) => {
        console.log('Server response:', data.message);
    });
    
    // New alert received
    socket.on('new_alert', (alert) => {
        console.log('🚨 New alert received:', alert);
        addAlertToFeed(alert);
        updateAlertCount();
        playAlertSound();
    });

    // Benign traffic received
    socket.on('benign_traffic', (traffic) => {
        console.log('✅ Benign traffic:', traffic);
        addAlertToFeed(traffic); // Use same function, it will style differently
    });

    // System status update
    socket.on('system_status_update', (status) => {
        updateSystemMetrics(status);
    });

    // Alerts cleared
    socket.on('alerts_cleared', () => {
        clearAlertsFeed();
    });

    // Monitoring stopped (server-side)
    socket.on('monitoring_stopped', (data) => {
        console.log('Server signalled monitoring stopped', data);
        isMonitoring = false;
        updateMonitoringUI(false);
        showNotification('info', 'Monitoring stopped by server');
    });
}


// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // Start monitoring button
    document.getElementById('start-btn').addEventListener('click', startMonitoring);
    
    // Stop monitoring button
    document.getElementById('stop-btn').addEventListener('click', stopMonitoring);
    
    // Clear logs button
    document.getElementById('clear-logs-btn').addEventListener('click', clearLogs);
    
    // Auto-scroll toggle
    document.getElementById('auto-scroll-toggle').addEventListener('click', toggleAutoScroll);
    
    // Request system status periodically
    setInterval(() => {
        if (isMonitoring) {
            socket.emit('request_system_status');
        }
    }, 5000);
}


// ============================================================================
// MONITORING CONTROL
// ============================================================================

async function startMonitoring() {
    const interface = document.getElementById('interface-select').value;
    const startBtn = document.getElementById('start-btn');

    console.log(`Starting real-time monitoring on ${interface}`);

    // Add loading state
    startBtn.disabled = true;
    startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

    try {
        const response = await fetch('/api/monitoring/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ interface })
        });

        const data = await response.json();

        if (response.ok && data.status === 'success') {
            isMonitoring = true;
            updateMonitoringUI(true);
            showNotification('success', '✅ Real-time monitoring started!');
        } else if (response.status === 400 && data.message === 'Monitoring already active') {
            // Monitoring is already running - sync UI state
            console.log('Monitoring already active, syncing UI...');
            isMonitoring = true;
            updateMonitoringUI(true);
            showNotification('info', 'ℹ️ Monitoring is already running');
        } else {
            showNotification('error', data.message || 'Failed to start monitoring');
            // Reset button on error
            startBtn.disabled = false;
            startBtn.innerHTML = '<i class="fas fa-play"></i> Start Monitoring';
        }
    } catch (error) {
        console.error('Error starting monitoring:', error);
        showNotification('error', 'Failed to start monitoring: ' + error.message);
        // Reset button on error
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-play"></i> Start Monitoring';
    }
}

async function stopMonitoring() {
    const stopBtn = document.getElementById('stop-btn');

    console.log('Stopping monitoring...');

    // Add loading state
    stopBtn.disabled = true;
    stopBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Stopping...';

    try {
        const response = await fetch('/api/monitoring/stop', {
            method: 'POST'
        });

        if (!response.ok) {
            // Try to read error message
            let msg = `Failed to stop monitoring (status ${response.status})`;
            try {
                const err = await response.json();
                msg = err.message || msg;
            } catch (e) {}
            showNotification('error', msg);
            stopBtn.disabled = false;
            stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
            return;
        }

        const data = await response.json();
        if (data.status === 'success') {
            isMonitoring = false;
            updateMonitoringUI(false);
            showNotification('info', '🛑 Monitoring stopped');
        } else {
            showNotification('error', data.message || 'Failed to stop monitoring');
            stopBtn.disabled = false;
            stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
        }
    } catch (error) {
        console.error('Error stopping monitoring:', error);
        showNotification('error', 'Failed to stop monitoring: server unreachable');
        // Reset button on error
        stopBtn.disabled = false;
        stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
    }
}

function updateMonitoringUI(running) {
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const statusBadge = document.getElementById('monitoring-status-badge');
    
    if (running) {
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fas fa-check"></i> Monitoring';
        stopBtn.disabled = false;
        stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
        statusBadge.innerHTML = '<i class="fas fa-play"></i> RUNNING';
        statusBadge.className = 'badge-status running';
    } else {
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="fas fa-play"></i> Start';
        stopBtn.disabled = true;
        stopBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
        statusBadge.innerHTML = '<i class="fas fa-power-off"></i> IDLE';
        statusBadge.className = 'badge-status';
    }
}


// ============================================================================
// ALERTS MANAGEMENT
// ============================================================================

function addAlertToFeed(alert) {
    const tbody = document.getElementById('alerts-table-body');

    // Remove empty state message if present
    if (tbody.querySelector('td[colspan="8"]')) {
        tbody.innerHTML = '';
    }

    const row = document.createElement('tr');

    // Check if it's benign traffic
    const isBenign = !alert.is_attack || alert.attack_type === 'Benign';

    // Apply row styling based on benign vs attack
    if (isBenign) {
        row.className = 'alert-row-new alert-benign';
        row.style.backgroundColor = 'rgba(16, 185, 129, 0.08)'; // Soft green for benign
    } else {
        row.className = 'alert-row-new ' + getSeverityClass(alert.severity);
        // Apply attack row coloring based on severity
        if (alert.severity === 'CRITICAL') {
            row.style.backgroundColor = 'rgba(239, 68, 68, 0.08)'; // Soft red for critical
        } else if (alert.severity === 'HIGH') {
            row.style.backgroundColor = 'rgba(249, 115, 22, 0.08)'; // Soft orange for high
        } else if (alert.severity === 'MEDIUM') {
            row.style.backgroundColor = 'rgba(245, 158, 11, 0.08)'; // Soft yellow for medium
        } else {
            row.style.backgroundColor = 'rgba(107, 114, 128, 0.08)'; // Soft gray for low
        }
    }

    // Robust timestamp parsing: alert.timestamp may be seconds (number) or ISO string
    let tsSeconds = null;
    if (typeof alert.timestamp === 'number') {
        tsSeconds = alert.timestamp;
    } else if (typeof alert.timestamp === 'string') {
        const parsed = Date.parse(alert.timestamp);
        if (!isNaN(parsed)) tsSeconds = parsed / 1000;
    }
    if (!tsSeconds) tsSeconds = Math.floor(Date.now() / 1000);
    const timestamp = new Date(tsSeconds * 1000).toLocaleTimeString();

    // Confidence: normalize/clamp to 0-100 and format with single decimal
    let conf = parseFloat(alert.confidence_score);
    if (isNaN(conf)) conf = 0;
    conf = Math.max(0, Math.min(conf, 100));
    const confidence = conf.toFixed(1);

    // Display attack type or "Benign"
    const displayType = isBenign ? 'Benign' : alert.attack_type;
    const displaySeverity = isBenign ? 'SAFE' : alert.severity;

    row.innerHTML = `
        <td>${timestamp}</td>
        <td><code>${alert.src_ip}</code></td>
        <td><code>${alert.dst_ip}</code></td>
        <td>${alert.dst_port}</td>
        <td><span class="badge bg-secondary">${alert.protocol}</span></td>
        <td><span class="badge ${isBenign ? 'badge-benign' : getAttackTypeBadge(alert.attack_type)}">${displayType}</span></td>
        <td><strong>${confidence}%</strong></td>
        <td><span class="badge ${isBenign ? 'badge-safe' : getSeverityBadge(alert.severity)}">${displaySeverity}</span></td>
    `;

    // Make row clickable to show details
    row.style.cursor = 'pointer';
    row.addEventListener('click', () => {
        showAttackDetails(alert);
    });

    // Add to top of table
    // Dedupe: avoid inserting the same alert twice (from DB + websocket)
    const alertKey = `${alert.src_ip}|${alert.dst_ip}|${alert.src_port}|${alert.dst_port}|${Math.floor(tsSeconds)}`;
    if (seenAlertKeys.has(alertKey)) {
        // skip duplicate
        return;
    }
    seenAlertKeys.add(alertKey);
    tbody.insertBefore(row, tbody.firstChild);

    // Keep only last 100 alerts
    while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }

    // Auto-scroll if enabled
    if (autoScroll) {
        const container = document.getElementById('alerts-container');
        container.scrollTop = 0;
    }

    // Increment alert count (only for actual alerts, not benign)
    if (!isBenign) {
        alertCount++;
        document.getElementById('new-alerts-badge').textContent = alertCount;
    }
    
    // Update charts
    updateChartsWithAlert(alert);
}

function clearAlertsFeed() {
    const tbody = document.getElementById('alerts-table-body');
    tbody.innerHTML = `
        <tr>
            <td colspan="8" class="text-center text-muted py-5">
                <i class="fas fa-inbox fa-3x mb-3"></i>
                <p>No alerts. All logs have been cleared.</p>
            </td>
        </tr>
    `;
    alertCount = 0;
    document.getElementById('new-alerts-badge').textContent = '0';

    // Reset top-level UI metrics
    document.getElementById('total-flow').textContent = '0';
    document.getElementById('alert-count').textContent = '0';
    document.getElementById('detection-rate').textContent = '0%';
    document.getElementById('avg-confidence').textContent = '0%';

    // Reset charts
    try {
        // Reset pie chart
        attackPieChart.data.labels = [];
        attackPieChart.data.datasets[0].data = [];
        attackPieChart.update('none');

        // Reset line chart
        packetRateData.labels = [];
        packetRateData.values = [];
        packetLineChart.data.labels = [];
        packetLineChart.data.datasets[0].data = [];
        packetLineChart.update('none');
    } catch (e) {
        console.warn('Error resetting charts during clear:', e);
    }
    // Clear dedupe cache so new alerts can be re-added
    try { seenAlertKeys.clear(); } catch (e) { seenAlertKeys = new Set(); }
}

async function clearLogs() {
    if (!confirm('Are you sure you want to clear all alerts?')) {
        return;
    }

    const clearBtn = document.getElementById('clear-logs-btn');
    const originalHTML = clearBtn.innerHTML;

    // Add loading state
    clearBtn.disabled = true;
    clearBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';

    try {
        const response = await fetch('/api/alerts/clear', {
            method: 'POST'
        });

        const data = await response.json();

        if (data.status === 'success') {
            // Clear UI and request fresh status
            clearAlertsFeed();
            // Ask server for updated stats once
            try { socket.emit('request_system_status'); } catch(e) {}
            showNotification('success', '🗑️ All alerts cleared!');
        }
    } catch (error) {
        console.error('Error clearing alerts:', error);
        showNotification('error', 'Failed to clear alerts');
    } finally {
        // Reset button
        clearBtn.disabled = false;
        clearBtn.innerHTML = originalHTML;
    }
}

function toggleAutoScroll() {
    autoScroll = !autoScroll;
    const btn = document.getElementById('auto-scroll-toggle');
    btn.innerHTML = `<i class="fas fa-arrows-alt-v"></i> Auto-scroll: ${autoScroll ? 'ON' : 'OFF'}`;
}


// ============================================================================
// CHARTS
// ============================================================================

function initializeCharts() {
    // Pie Chart - Attack Distribution
    const pieCtx = document.getElementById('attack-pie-chart').getContext('2d');
    attackPieChart = new Chart(pieCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#10b981',  // Benign - Green
                    '#dc2626',  // DoS - Red
                    '#f59e0b',  // Reconnaissance - Orange
                    '#991b1b',  // Exploits - Dark Red
                    '#6b7280',  // Generic - Gray
                    '#9333ea',  // Other - Purple
                    '#06b6d4',  // Additional - Cyan
                    '#8b5cf6'   // Additional - Violet
                ],
                borderWidth: 3,
                borderColor: '#0f1419',
                hoverBorderWidth: 4,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 800
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    align: 'center',
                    labels: {
                        color: '#ffffff',
                        padding: 15,
                        font: {
                            size: 12,
                            weight: '500',
                            family: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
                        },
                        usePointStyle: true,
                        pointStyle: 'circle',
                        pointStyleWidth: 8,
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length === 0) {
                                return [{
                                    text: 'No data available',
                                    fillStyle: '#6b7280',
                                    fontColor: '#ffffff',
                                    hidden: false,
                                    index: 0
                                }];
                            }
                            
                            const total = data.datasets[0].data.reduce((a, b) => a + b, 0);
                            return data.labels.map((label, i) => {
                                const value = data.datasets[0].data[i];
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : '0.0';
                                return {
                                    text: `${label}: ${percentage}%`,
                                    fillStyle: data.datasets[0].backgroundColor[i],
                                    strokeStyle: '#ffffff',
                                    fontColor: '#ffffff',
                                    lineWidth: 1,
                                    hidden: false,
                                    index: i
                                };
                            });
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((context.parsed / total) * 100).toFixed(1) : '0.0';
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                },
                // Add data labels on chart segments
                datalabels: false // We'll handle this with custom drawing
            },
            cutout: '45%', // Makes it a doughnut with hole in center
            radius: '85%',
            // Custom center text
            elements: {
                arc: {
                    borderWidth: 3
                }
            }
        },
        plugins: [{
            id: 'centerText',
            beforeDraw: function(chart) {
                if (chart.data.datasets[0].data.length === 0) {
                    const ctx = chart.ctx;
                    const centerX = (chart.chartArea.left + chart.chartArea.right) / 2;
                    const centerY = (chart.chartArea.top + chart.chartArea.bottom) / 2;
                    
                    ctx.save();
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.font = '600 16px Inter';
                    ctx.fillStyle = '#9ca3af';
                    ctx.fillText('No Attacks', centerX, centerY - 10);
                    ctx.font = '400 12px Inter';
                    ctx.fillStyle = '#6b7280';
                    ctx.fillText('Detected', centerX, centerY + 10);
                    ctx.restore();
                } else {
                    const total = chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                    const ctx = chart.ctx;
                    const centerX = (chart.chartArea.left + chart.chartArea.right) / 2;
                    const centerY = (chart.chartArea.top + chart.chartArea.bottom) / 2;
                    
                    ctx.save();
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    // Large white number - professional font
                    ctx.font = '600 28px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
                    ctx.fillStyle = '#ffffff';
                    ctx.fillText(total.toString(), centerX, centerY - 8);
                    // White label text
                    ctx.font = '400 12px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
                    ctx.fillStyle = '#ffffff';
                    ctx.fillText('Total Attacks', centerX, centerY + 18);
                    ctx.restore();
                }
            }
        }]
    });
    
    // Line Chart - Real-Time Activity
    const lineCtx = document.getElementById('packet-line-chart').getContext('2d');
    packetLineChart = new Chart(lineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets/sec',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 3,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: { color: '#b0b3c1' },
                    grid: { color: '#2d3142' }
                },
                y: {
                    ticks: { color: '#b0b3c1' },
                    grid: { color: '#2d3142' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#b0b3c1' }
                }
            }
        }
    });
}

function updateChartsWithAlert(alert) {
    // Update pie chart with new attack type
    const attackType = alert.attack_type;
    const labels = attackPieChart.data.labels;
    const index = labels.indexOf(attackType);
    
    if (index !== -1) {
        attackPieChart.data.datasets[0].data[index]++;
    } else {
        // Add to "Other" category
        const otherIndex = labels.indexOf('Other');
        if (otherIndex !== -1) {
            attackPieChart.data.datasets[0].data[otherIndex]++;
        }
    }
    
    attackPieChart.update();
}

function updatePacketRateChart(rate) {
    const now = new Date().toLocaleTimeString();
    
    // Add new data point
    packetRateData.labels.push(now);
    packetRateData.values.push(rate);
    
    // Keep only last MAX_CHART_POINTS
    if (packetRateData.labels.length > MAX_CHART_POINTS) {
        packetRateData.labels.shift();
        packetRateData.values.shift();
    }
    
    // Update chart
    packetLineChart.data.labels = packetRateData.labels;
    packetLineChart.data.datasets[0].data = packetRateData.values;
    packetLineChart.update('none'); // Update without animation
}


// ============================================================================
// SYSTEM METRICS
// ============================================================================

function updateSystemMetrics(status) {
    console.log('Updating metrics with status:', status);
    
    // Update total flows
    const totalFlows = Math.round(status.total_flows || 0);
    document.getElementById('total-flow').textContent = totalFlows;
    updatePacketRateChart(status.packet_rate || 0); // Keep chart showing packet rate
    
    // Update alert count (real-time alerts today)
    const alertCount = status.alert_count || 0;
    document.getElementById('alert-count').textContent = alertCount;
    
    // Calculate and update real-time metrics
    calculateRealtimeMetrics(status);
}

function calculateRealtimeMetrics(status) {
    // Get total packets and alerts
    const totalPackets = status.total_packets || 0;
    const totalAlerts = status.alert_count || 0;
    
    // Detection Rate = (alerts / packets) * 100
    let detectionRate = 0;
    if (totalPackets > 0) {
        detectionRate = ((totalAlerts / totalPackets) * 100).toFixed(1);
    }
    document.getElementById('detection-rate').textContent = detectionRate + '%';
    
    // Fetch all alerts to calculate average confidence
    fetch('/api/alerts/recent?limit=1000')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.length > 0) {
                const alerts = data.data;
                const confidences = alerts
                    .filter(alert => alert.confidence_score !== undefined && alert.confidence_score !== null)
                    .map(alert => parseFloat(alert.confidence_score)); // Already in 0-100 range
                
                if (confidences.length > 0) {
                    const avgConfidence = (confidences.reduce((a, b) => a + b, 0) / confidences.length).toFixed(1);
                    document.getElementById('avg-confidence').textContent = avgConfidence + '%';
                } else {
                    document.getElementById('avg-confidence').textContent = '0%';
                }
            } else {
                document.getElementById('avg-confidence').textContent = '0%';
            }
        })
        .catch(error => {
            console.error('Error calculating avg confidence:', error);
            document.getElementById('avg-confidence').textContent = '0%';
        });
}

function updateAlertCount() {
    fetch('/api/alerts/count')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                document.getElementById('alert-count').textContent = data.data.count;
            }
        })
        .catch(error => console.error('Error fetching alert count:', error));
}


// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function updateConnectionStatus(connected) {
    const statusElement = document.getElementById('connection-status');
    
    if (connected) {
        statusElement.innerHTML = '<i class="fas fa-circle"></i> Connected';
        statusElement.className = 'badge bg-success me-3';
    } else {
        statusElement.innerHTML = '<i class="fas fa-circle"></i> Disconnected';
        statusElement.className = 'badge bg-danger me-3';
    }
}

function getSeverityClass(severity) {
    const classes = {
        'CRITICAL': 'alert-critical',
        'HIGH': 'alert-high',
        'MEDIUM': 'alert-medium',
        'LOW': 'alert-low'
    };
    return classes[severity] || '';
}

function getSeverityBadge(severity) {
    const badges = {
        'CRITICAL': 'severity-critical',
        'HIGH': 'severity-high',
        'MEDIUM': 'severity-medium',
        'LOW': 'severity-low'
    };
    return 'badge ' + (badges[severity] || 'bg-secondary');
}

function getAttackTypeBadge(attackType) {
    const badges = {
        'DoS': 'attack-dos',
        'Reconnaissance': 'attack-reconnaissance',
        'Exploits': 'attack-exploits',
        'Backdoor': 'attack-backdoor',
        'Generic': 'attack-generic'
    };
    return 'badge ' + (badges[attackType] || 'bg-danger');
}

function playAlertSound() {
    // Optional: Play sound for new alerts
    // const audio = new Audio('/static/sounds/alert.mp3');
    // audio.play().catch(e => console.log('Could not play sound'));
}

function showNotification(type, message) {
    console.log(`[${type.toUpperCase()}] ${message}`);

    // Create toast notification element
    const toast = document.createElement('div');
    toast.className = `toast-notification toast-${type}`;

    const icons = {
        'success': '✅',
        'error': '❌',
        'info': 'ℹ️',
        'warning': '⚠️'
    };

    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
        <span class="toast-message">${message}</span>
    `;

    // Add to page
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        document.body.appendChild(toastContainer);
    }

    toastContainer.appendChild(toast);

    // Animate in
    setTimeout(() => toast.classList.add('show'), 10);

    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function loadAvailableInterfaces() {
    fetch('/api/interfaces')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.interfaces.length > 0) {
                const select = document.getElementById('interface-select');
                select.innerHTML = ''; // Clear default options
                
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface;
                    option.textContent = iface;
                    select.appendChild(option);
                });
                
                console.log('✓ Loaded interfaces:', data.interfaces);
            }
        })
        .catch(error => console.error('Error loading interfaces:', error));
}

function loadInitialData() {
    // Check monitoring status first to sync UI state
    fetch('/api/monitoring/status')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.is_running) {
                console.log('✓ Monitoring is already running, syncing UI...');
                isMonitoring = true;
                updateMonitoringUI(true);
            }
        })
        .catch(error => console.error('Error checking monitoring status:', error));

    // Load recent alerts (only include alerts from the last hour to avoid showing stale/corrupted data)
    const HISTORY_WINDOW_SECONDS = 60 * 60; // 1 hour
    const cutoff = (Date.now() / 1000) - HISTORY_WINDOW_SECONDS;
    fetch('/api/alerts/recent?limit=200')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.length > 0) {
                const recent = data.data.filter(a => {
                    const ts = (typeof a.timestamp === 'number') ? a.timestamp : (Date.parse(a.timestamp) / 1000 || 0);
                    return ts >= cutoff;
                });
                recent.reverse().forEach(alert => addAlertToFeed(alert));
                updateAlertMetrics(recent);
            }
        })
        .catch(error => console.error('Error loading initial data:', error));
    
    // Load statistics
    fetch('/api/statistics/distribution')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                updatePieChartWithDistribution(data.data);
            }
        })
        .catch(error => console.error('Error loading distribution:', error));
    
    // Set up periodic distribution refresh every 5 seconds
    if (!window.distributionRefreshInterval) {
        window.distributionRefreshInterval = setInterval(() => {
            fetch('/api/statistics/distribution')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        updatePieChartWithDistribution(data.data);
                    }
                })
                .catch(error => console.error('Error refreshing distribution:', error));
        }, 5000);
    }
}

function updateAlertMetrics(alerts) {
    // Calculate average confidence from loaded alerts
    if (alerts && alerts.length > 0) {
        const confidences = alerts
            .filter(alert => alert.confidence_score !== undefined && alert.confidence_score !== null)
            .map(alert => {
                let v = parseFloat(alert.confidence_score);
                if (isNaN(v)) v = 0;
                return Math.max(0, Math.min(v, 100));
            });
        
        if (confidences.length > 0) {
            const avgConfidence = (confidences.reduce((a, b) => a + b, 0) / confidences.length).toFixed(1);
            document.getElementById('avg-confidence').textContent = avgConfidence + '%';
        }
    }
}

function updatePieChartWithDistribution(distribution) {
    const labels = Object.keys(distribution);
    const values = Object.values(distribution);
    
    console.log('Updating pie chart with distribution:', distribution);
    
    if (labels.length > 0 && values.some(v => v > 0)) {
        // Define colors based on attack type
        const getColorForAttackType = (attackType) => {
            const colorMap = {
                'Benign': '#10b981',           // Green for benign
                'DoS': '#dc2626',              // Red for DoS
                'Backdoor': '#991b1b',         // Dark red for Backdoor
                'Reconnaissance': '#f59e0b',   // Orange for Reconnaissance
                'Exploits': '#dc2626',         // Red for Exploits
                'Analysis': '#f59e0b',         // Orange for Analysis
                'Fuzzers': '#f59e0b',          // Orange for Fuzzers
                'Shellcode': '#dc2626',        // Red for Shellcode
                'Generic': '#6b7280',          // Gray for Generic
                'Worms': '#dc2626'             // Red for Worms
            };
            return colorMap[attackType] || '#6b7280'; // Default gray
        };
        
        // Generate colors for each label
        const colors = labels.map(label => getColorForAttackType(label));
        
        // Update chart data
        attackPieChart.data.labels = labels;
        attackPieChart.data.datasets[0].data = values;
        attackPieChart.data.datasets[0].backgroundColor = colors;
        
        // Animate the update
        attackPieChart.update('active'); // Use 'active' for smooth animation
    } else {
        // Clear chart if no data
        attackPieChart.data.labels = [];
        attackPieChart.data.datasets[0].data = [];
        attackPieChart.data.datasets[0].backgroundColor = [];
        attackPieChart.update('none');
    }
}

// ============================================================================
// FEATURE NAMES (from NF-UNSW-NB15-v3 dataset)
// ============================================================================

const FEATURE_NAMES = [
    'FLOW_START_MILLISECONDS',
    'IN_BYTES',
    'IN_PKTS',
    'OUT_BYTES',
    'TCP_FLAGS',
    'FLOW_DURATION_MILLISECONDS',
    'DURATION_OUT',
    'MIN_TTL',
    'LONGEST_FLOW_PKT',
    'SHORTEST_FLOW_PKT',
    'MIN_IP_PKT_LEN',
    'SRC_TO_DST_SECOND_BYTES',
    'DST_TO_SRC_SECOND_BYTES',
    'SRC_TO_DST_AVG_THROUGHPUT',
    'NUM_PKTS_UP_TO_128_BYTES',
    'NUM_PKTS_128_TO_256_BYTES',
    'NUM_PKTS_256_TO_512_BYTES',
    'NUM_PKTS_512_TO_1024_BYTES',
    'NUM_PKTS_1024_TO_1514_BYTES',
    'TCP_WIN_MAX_IN',
    'TCP_WIN_MAX_OUT',
    'ICMP_TYPE',
    'DNS_QUERY_ID',
    'DNS_QUERY_TYPE',
    'DNS_TTL_ANSWER',
    'FTP_COMMAND_RET_CODE',
    'SRC_TO_DST_IAT_MIN',
    'SRC_TO_DST_IAT_MAX',
    'SRC_TO_DST_IAT_AVG',
    'SRC_TO_DST_IAT_STDDEV',
    'DST_TO_SRC_IAT_MIN',
    'DST_TO_SRC_IAT_MAX',
    'DST_TO_SRC_IAT_AVG',
    'DST_TO_SRC_IAT_STDDEV'
];

const FEATURE_DESCRIPTIONS = {
    'FLOW_START_MILLISECONDS': 'When the flow started (milliseconds since epoch)',
    'IN_BYTES': 'Bytes received from destination to source (backward)',
    'IN_PKTS': 'Number of packets received from destination to source',
    'OUT_BYTES': 'Bytes sent from source to destination (forward)',
    'TCP_FLAGS': 'Total TCP control flags set in this flow',
    'FLOW_DURATION_MILLISECONDS': 'Total duration of the flow',
    'DURATION_OUT': 'Duration of packets in forward direction',
    'MIN_TTL': 'Minimum TTL value observed',
    'LONGEST_FLOW_PKT': 'Size of the longest packet in flow',
    'SHORTEST_FLOW_PKT': 'Size of the shortest packet in flow',
    'MIN_IP_PKT_LEN': 'Minimum IP packet length',
    'SRC_TO_DST_SECOND_BYTES': 'Forward direction bytes per second',
    'DST_TO_SRC_SECOND_BYTES': 'Backward direction bytes per second',
    'SRC_TO_DST_AVG_THROUGHPUT': 'Average throughput in forward direction',
    'NUM_PKTS_UP_TO_128_BYTES': 'Number of packets ≤128 bytes',
    'NUM_PKTS_128_TO_256_BYTES': 'Number of packets 128-256 bytes',
    'NUM_PKTS_256_TO_512_BYTES': 'Number of packets 256-512 bytes',
    'NUM_PKTS_512_TO_1024_BYTES': 'Number of packets 512-1024 bytes',
    'NUM_PKTS_1024_TO_1514_BYTES': 'Number of packets 1024-1514 bytes',
    'TCP_WIN_MAX_IN': 'Maximum TCP window size (backward)',
    'TCP_WIN_MAX_OUT': 'Maximum TCP window size (forward)',
    'ICMP_TYPE': 'Type of ICMP packet (if applicable)',
    'DNS_QUERY_ID': 'DNS query ID (if DNS traffic)',
    'DNS_QUERY_TYPE': 'DNS query type (if DNS traffic)',
    'DNS_TTL_ANSWER': 'DNS TTL value in answer (if DNS traffic)',
    'FTP_COMMAND_RET_CODE': 'FTP return code (if FTP traffic)',
    'SRC_TO_DST_IAT_MIN': 'Minimum inter-arrival time (forward)',
    'SRC_TO_DST_IAT_MAX': 'Maximum inter-arrival time (forward)',
    'SRC_TO_DST_IAT_AVG': 'Average inter-arrival time (forward)',
    'SRC_TO_DST_IAT_STDDEV': 'Standard deviation of inter-arrival time (forward)',
    'DST_TO_SRC_IAT_MIN': 'Minimum inter-arrival time (backward)',
    'DST_TO_SRC_IAT_MAX': 'Maximum inter-arrival time (backward)',
    'DST_TO_SRC_IAT_AVG': 'Average inter-arrival time (backward)',
    'DST_TO_SRC_IAT_STDDEV': 'Standard deviation of inter-arrival time (backward)'
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function formatFeatureValue(value) {
    const num = parseFloat(value);
    if (isNaN(num)) return value;
    if (num > 1000000) return (num / 1000000).toFixed(2) + 'M';
    if (num > 1000) return (num / 1000).toFixed(2) + 'K';
    return num.toFixed(2);
}

// ============================================================================
// ATTACK DETAILS MODAL
// ============================================================================

function showAttackDetails(alert) {
    if (!alert || !alert.features || !Array.isArray(alert.features)) {
        console.error('Invalid alert data for details modal', alert);
        showNotification('error', 'Cannot display attack details');
        return;
    }

    // Populate basic info
    document.getElementById('modal-attack-type').textContent = alert.attack_type || 'Unknown';
    document.getElementById('modal-severity').textContent = alert.severity || 'UNKNOWN';
    document.getElementById('modal-severity').className = 'badge ' + (alert.severity ? getSeverityBadge(alert.severity) : 'bg-secondary');
    document.getElementById('modal-confidence').textContent = alert.confidence_score.toFixed(2) + '%';
    document.getElementById('modal-timestamp').textContent = new Date(alert.timestamp * 1000).toLocaleString();
    document.getElementById('modal-src-ip').textContent = alert.src_ip;
    document.getElementById('modal-dst-ip').textContent = alert.dst_ip;
    document.getElementById('modal-port-protocol').textContent = alert.dst_port + ' / ' + alert.protocol;

    // Get only anomalous/relevant features
    const anomalousFeatures = getAnomalousFeatures(alert);

    // Populate features table with ONLY anomalous features
    const featuresTableBody = document.getElementById('features-tbody');
    featuresTableBody.innerHTML = '';

    if (anomalousFeatures.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="4" class="text-center text-muted">No significant anomalies (benign traffic)</td>';
        featuresTableBody.appendChild(row);
    } else {
        anomalousFeatures.forEach((featureInfo, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="text-danger"><strong>⚠ ${index + 1}</strong></td>
                <td><strong class="text-warning">${featureInfo.name}</strong></td>
                <td><code class="text-info">${parseFloat(featureInfo.value).toFixed(2)}</code></td>
                <td>
                    <small class="text-muted">${featureInfo.description}</small><br>
                    <small class="text-danger"><strong>→ ${featureInfo.anomalyReason}</strong></small>
                </td>
            `;
            featuresTableBody.appendChild(row);
        });
    }

    // Generate attack reasoning
    const reasoning = generateAttackReasoning(alert, anomalousFeatures);
    document.getElementById('attack-reasoning').innerHTML = reasoning;

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('attackDetailsModal'));
    modal.show();
}

function getAnomalousFeatures(alert) {
    const anomalous = [];
    const features = alert.features;

    if (!Array.isArray(features)) return anomalous;

    // Helper to add anomalous feature
    const addAnomaly = (index, reason) => {
        if (index >= 0 && index < FEATURE_NAMES.length && index < features.length) {
            anomalous.push({
                index: index,
                name: FEATURE_NAMES[index],
                value: features[index],
                description: FEATURE_DESCRIPTIONS[FEATURE_NAMES[index]] || 'Network feature',
                anomalyReason: reason
            });
        }
    };

    // For ATTACK classifications, show ALL features with their descriptions
    if (alert.is_attack) {
        // Show key network features
        // Feature 0: FLOW_START
        addAnomaly(0, `Flow started at: ${new Date(features[0]).toLocaleString()}`);
        
        // Feature 1: IN_BYTES - bytes received
        if (features[1] > 0) {
            addAnomaly(1, `Bytes received: ${(features[1]/1000).toFixed(2)}KB`);
        }
        
        // Feature 2: IN_PKTS - packets received
        if (features[2] > 0) {
            addAnomaly(2, `Packets received: ${parseInt(features[2])}`);
        }
        
        // Feature 3: OUT_BYTES - bytes sent
        if (features[3] > 0) {
            addAnomaly(3, `Bytes sent: ${(features[3]/1000).toFixed(2)}KB`);
        }
        
        // Feature 4: TCP_FLAGS
        if (features[4] > 0) {
            addAnomaly(4, `TCP flags detected: ${parseInt(features[4])}`);
        }
        
        // Feature 5: FLOW_DURATION
        if (features[5] > 0) {
            addAnomaly(5, `Connection duration: ${(features[5]/1000).toFixed(2)} seconds`);
        }
        
        // Feature 6: DURATION_OUT
        if (features[6] > 0) {
            addAnomaly(6, `Outgoing duration: ${(features[6]/1000).toFixed(2)} seconds`);
        }
        
        // Feature 8: MIN_TTL
        if (features[8] > 0) {
            addAnomaly(8, `Minimum TTL: ${parseInt(features[8])}`);
        }
        
        // Feature 9: LONGEST_PKT
        if (features[9] > 0) {
            addAnomaly(9, `Longest packet: ${parseInt(features[9])} bytes`);
        }
        
        // Feature 10: SHORTEST_PKT
        if (features[10] > 0) {
            addAnomaly(10, `Shortest packet: ${parseInt(features[10])} bytes`);
        }
        
        // Feature 11: SRC_TO_DST_BPS
        if (features[11] > 0) {
            addAnomaly(11, `Forward throughput: ${(features[11]/1000000).toFixed(4)}MB/s`);
        }
        
        // Feature 12: DST_TO_SRC_BPS
        if (features[12] > 0) {
            addAnomaly(12, `Reverse throughput: ${(features[12]/1000000).toFixed(4)}MB/s`);
        }
        
        // Feature 13: SRC_TO_DST_AVG_TPUT
        if (features[13] > 0) {
            addAnomaly(13, `Average throughput: ${(features[13]/1000000).toFixed(4)}MB/s`);
        }
        
        // Packet size distribution features (14-18: PKT_BINS)
        if (features[14] > 0) addAnomaly(14, `Packets 0-128 bytes: ${parseInt(features[14])}`);
        if (features[15] > 0) addAnomaly(15, `Packets 128-256 bytes: ${parseInt(features[15])}`);
        if (features[16] > 0) addAnomaly(16, `Packets 256-512 bytes: ${parseInt(features[16])}`);
        if (features[17] > 0) addAnomaly(17, `Packets 512-1024 bytes: ${parseInt(features[17])}`);
        if (features[18] > 0) addAnomaly(18, `Packets 1024-1514 bytes: ${parseInt(features[18])}`);
        
        // TCP Window features
        if (features[19] > 0) addAnomaly(19, `TCP Window (in): ${parseInt(features[19])} bytes`);
        if (features[20] > 0) addAnomaly(20, `TCP Window (out): ${parseInt(features[20])} bytes`);
        
        // ICMP/DNS/FTP features
        if (features[21] > 0) addAnomaly(21, `ICMP type: ${parseInt(features[21])}`);
        if (features[22] > 0) addAnomaly(22, `DNS query ID: ${parseInt(features[22])}`);
        if (features[23] > 0) addAnomaly(23, `DNS query type: ${parseInt(features[23])}`);
        if (features[24] > 0) addAnomaly(24, `DNS TTL answer: ${parseInt(features[24])}`);
        if (features[25] > 0) addAnomaly(25, `FTP return code: ${parseInt(features[25])}`);
        
        // Inter-arrival time features (forward direction)
        if (features[26] > 0) addAnomaly(26, `Min IAT (fwd): ${features[26].toFixed(2)}ms`);
        if (features[27] > 0) addAnomaly(27, `Max IAT (fwd): ${features[27].toFixed(2)}ms`);
        if (features[28] > 0) addAnomaly(28, `Avg IAT (fwd): ${features[28].toFixed(2)}ms`);
        if (features[29] > 0) addAnomaly(29, `StdDev IAT (fwd): ${features[29].toFixed(2)}ms`);
        
        // Inter-arrival time features (backward direction)
        if (features[30] > 0) addAnomaly(30, `Min IAT (bwd): ${features[30].toFixed(2)}ms`);
        if (features[31] > 0) addAnomaly(31, `Max IAT (bwd): ${features[31].toFixed(2)}ms`);
        if (features[32] > 0) addAnomaly(32, `Avg IAT (bwd): ${features[32].toFixed(2)}ms`);
        if (features[33] > 0) addAnomaly(33, `StdDev IAT (bwd): ${features[33].toFixed(2)}ms`);
    }

    return anomalous;
}

function generateAttackReasoning(alert, anomalousFeatures) {
    let reasoning = '';

    if (alert.is_attack) {
        reasoning += `<strong>Why This Was Classified as an Attack:</strong><ul>`;
        
        // Confidence level
        if (alert.confidence_score > 95) {
            reasoning += `<li><strong>Model Confidence (${alert.confidence_score.toFixed(2)}%):</strong> Very strong attack signature detected.</li>`;
        } else if (alert.confidence_score > 80) {
            reasoning += `<li><strong>Model Confidence (${alert.confidence_score.toFixed(2)}%):</strong> Strong indicators of malicious activity.</li>`;
        } else {
            reasoning += `<li><strong>Model Confidence (${alert.confidence_score.toFixed(2)}%):</strong> Suspicious patterns detected.</li>`;
        }

        // Attack-specific reasoning
        const attackType = alert.attack_type || '';
        if (attackType.includes('Backdoor')) {
            reasoning += `<li><strong>Attack Type - Backdoor:</strong> Persistent remote access pattern. May indicate C&C communication or reverse shell.</li>`;
        } else if (attackType.includes('DoS')) {
            reasoning += `<li><strong>Attack Type - DoS:</strong> High volume attack attempting to overwhelm the target.</li>`;
        } else if (attackType.includes('Exploit')) {
            reasoning += `<li><strong>Attack Type - Exploit:</strong> Suspicious payload or protocol abuse detected.</li>`;
        } else if (attackType.includes('Reconnaissance')) {
            reasoning += `<li><strong>Attack Type - Reconnaissance:</strong> Probing behavior detected. Attacker gathering information.</li>`;
        } else if (attackType.includes('Worm')) {
            reasoning += `<li><strong>Attack Type - Worm:</strong> Self-propagating malware activity detected.</li>`;
        } else if (attackType.includes('Shellcode')) {
            reasoning += `<li><strong>Attack Type - Shellcode:</strong> Arbitrary code execution attempt detected.</li>`;
        }

        // List anomalous features
        if (anomalousFeatures.length > 0) {
            reasoning += `<li><strong>Anomalous Features (${anomalousFeatures.length} detected):</strong></li><ul>`;
            
            // Show all anomalous features, but group them nicely
            anomalousFeatures.forEach((feature, index) => {
                reasoning += `<li>${feature.name}: ${feature.anomalyReason}</li>`;
            });
            
            reasoning += `</ul>`;
        }

        reasoning += `</ul>`;
    } else {
        reasoning = `<strong>Benign Traffic Detected:</strong><ul>
            <li>This traffic pattern is normal and legitimate.</li>
            <li>No anomalous features or attack signatures detected.</li>
            <li>Network behavior matches standard application patterns.</li>
        </ul>`;
    }

    return reasoning;
}

// ============================================================================
// EXPORT FUNCTIONALITY
// ============================================================================

document.getElementById('export-btn')?.addEventListener('click', function() {
    const timestamp = document.getElementById('modal-timestamp').textContent;
    const attackType = document.getElementById('modal-attack-type').textContent;
    const srcIp = document.getElementById('modal-src-ip').textContent;
    const dstIp = document.getElementById('modal-dst-ip').textContent;
    const confidence = document.getElementById('modal-confidence').textContent;

    let report = `NIDS Attack Report\n`;
    report += `Generated: ${new Date().toLocaleString()}\n`;
    report += `\n=== ATTACK DETAILS ===\n`;
    report += `Detection Time: ${timestamp}\n`;
    report += `Attack Type: ${attackType}\n`;
    report += `Source IP: ${srcIp}\n`;
    report += `Destination IP: ${dstIp}\n`;
    report += `Confidence: ${confidence}\n`;
    report += `\n=== EXTRACTED FEATURES ===\n`;

    const rows = document.querySelectorAll('#features-tbody tr');
    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 3) {
            report += `${cells[1].textContent}: ${cells[2].textContent}\n`;
        }
    });

    // Download as text file
    const blob = new Blob([report], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `attack_report_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    showNotification('success', 'Report exported successfully');
});


// ============================================================================
// KEYBOARD SHORTCUTS
// ============================================================================

document.addEventListener('keydown', (e) => {
    // Ctrl+K: Focus on search (future feature)
    if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        // Focus search input when implemented
    }
    
    // Ctrl+R: Refresh data
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        loadInitialData();
        showNotification('info', 'Data refreshed');
    }
});

console.log('✓ Dashboard script loaded successfully');
