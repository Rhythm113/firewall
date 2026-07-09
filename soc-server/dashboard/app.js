// Global State
let activeAgent = 'all';
let currentPage = 0;
const limit = 20;

let timelineChart = null;
let threatChart = null;
let sseSource = null;

// Map threat type enum to human readable strings
const threatNames = {
    1: 'PHP Shell Payload',
    2: 'XSS Query Attack',
    3: 'SYN Flood Rate-limit',
    4: 'Slowloris TCP Timeout',
    5: 'IP Address Blocked'
};

// Map severity enum to human readable strings and css classes
const severityMap = {
    0: { name: 'INFO', class: 'badge-info' },
    1: { name: 'WARNING', class: 'badge-warning' },
    2: { name: 'CRITICAL', class: 'badge-critical' }
};

// Format timestamps
function formatTime(unixTime) {
    const d = new Date(unixTime * 1000);
    return d.toLocaleString();
}

// Initial page setup and authentication check
document.addEventListener('DOMContentLoaded', () => {
    // Check auth and load initial dashboard data
    loadDashboard();
    
    // Set up polling interval for stats and tables (fallback / historical updates)
    setInterval(updateStatsAndCharts, 30000); // 30s
    
    // Wire up events
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    document.getElementById('btn-prev').addEventListener('click', () => changePage(-1));
    document.getElementById('btn-next').addEventListener('click', () => changePage(1));
});

// Logout handler
async function handleLogout() {
    // We send dummy credentials to clear cookie and redirect
    await fetch('/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'logout', password: 'xyz' })
    });
    window.location.href = '/login.html';
}

// Load all elements
async function loadDashboard() {
    try {
        const authCheck = await fetch('/api/stats');
        if (authCheck.status === 401) {
            window.location.href = '/login.html';
            return;
        }

        // Initialize empty charts
        initCharts();
        
        // Fetch components
        await updateStatsAndCharts();
        await fetchAgents();
        await fetchEventsTable();

        // Setup real-time event streaming via SSE
        setupSSE();
    } catch (err) {
        console.error("Dashboard initialization failed", err);
    }
}

// Setup SSE
function setupSSE() {
    if (sseSource) sseSource.close();

    // Use current session token (browser sends cookie automatically)
    // In case cookie doesn't match standard cross-origin, we also bind to the relative endpoint
    sseSource = new EventSource('/api/events/live');

    sseSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleIncomingLiveAlert(data);
        } catch (err) {
            console.error("Failed to parse SSE event", err);
        }
    };

    sseSource.onerror = (err) => {
        console.warn("SSE connection lost. Reconnecting in 5s...", err);
        sseSource.close();
        setTimeout(setupSSE, 5000);
    };
}

// Incoming live alert dispatcher
function handleIncomingLiveAlert(event) {
    // 1. Hide "Awaiting alerts" placeholder if present
    const emptyMsg = document.getElementById('feed-empty');
    if (emptyMsg) emptyMsg.remove();

    // 2. Prepend event to Live Feed panel
    const feed = document.getElementById('feed-container');
    const item = document.createElement('div');
    item.className = 'feed-item';

    const timestamp = Math.floor(Date.now() / 1000);
    const dateStr = new Date().toLocaleTimeString();

    // Determine badge class
    const sev = severityMap[event.severity] || { name: 'UNKNOWN', class: 'badge-info' };
    const threatName = threatNames[event.threat_type] || `Threat ${event.threat_type}`;

    item.innerHTML = `
        <div class="feed-meta">
            <span class="badge ${sev.class}">${sev.name}</span>
            <span class="feed-time">${dateStr}</span>
        </div>
        <div class="feed-title">${threatName}</div>
        <div class="feed-desc">${event.src_ip}:${event.src_port} &rarr; ${event.payload_preview}</div>
    `;

    feed.insertBefore(item, feed.firstChild);

    // Limit live feed to 30 elements
    if (feed.children.length > 30) {
        feed.removeChild(feed.lastChild);
    }

    // 3. Dynamically increment global stats cards
    if (activeAgent === 'all' || activeAgent === event.agent_uuid) {
        const totalVal = document.getElementById('stat-total-val');
        const critVal = document.getElementById('stat-crit-val');
        totalVal.textContent = parseInt(totalVal.textContent) + 1;
        if (event.severity === 2) {
            critVal.textContent = parseInt(critVal.textContent) + 1;
        }

        // Prepend to current table if on page 0
        if (currentPage === 0) {
            addEventToTableTop(event);
        }

        // Live update charts
        incrementChartData(event);
    }
}

// Prepend single row to the main event logs table
function addEventToTableTop(event) {
    const tbody = document.getElementById('events-tbody');
    if (tbody.children.length > 0 && tbody.children[0].children.length === 1) {
        tbody.innerHTML = ''; // Clear placeholder
    }

    const tr = document.createElement('tr');
    const sev = severityMap[event.severity] || { name: 'UNKNOWN', class: 'badge-info' };
    const threatName = threatNames[event.threat_type] || `Threat ${event.threat_type}`;

    tr.innerHTML = `
        <td>${formatTime(event.timestamp)}</td>
        <td><span style="font-family:monospace; font-size:0.75rem;">${event.agent_uuid.substring(0, 8)}...</span></td>
        <td>${event.src_ip}:${event.src_port}</td>
        <td>${event.dest_ip}:${event.dest_port}</td>
        <td>${threatName}</td>
        <td><span class="badge ${sev.class}">${sev.name}</span></td>
        <td><span style="font-family:monospace; font-size:0.75rem;">${event.payload_preview}</span></td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);
    
    // Remove last row to preserve page size limit
    if (tbody.children.length > limit) {
        tbody.removeChild(tbody.lastChild);
    }
}

// Retrieve active agents list
async function fetchAgents() {
    try {
        const res = await fetch('/api/agents');
        const agents = await res.json();

        // Update active nodes count card
        document.getElementById('stat-nodes-val').textContent = agents.length;

        const container = document.getElementById('agents-container');
        // Preserve "ALL AGENTS" card
        const allAgentsCard = container.firstElementChild;
        container.innerHTML = '';
        container.appendChild(allAgentsCard);

        agents.forEach(agent => {
            const card = document.createElement('div');
            card.className = `agent-card ${activeAgent === agent.uuid ? 'active' : ''}`;
            card.setAttribute('data-uuid', agent.uuid);
            
            const lastSeenStr = new Date(agent.last_seen * 1000).toLocaleTimeString();

            card.innerHTML = `
                <div class="agent-card-title">Agent ${agent.uuid.substring(0, 8)}</div>
                <div class="agent-card-meta">${agent.ip} &bull; Seen ${lastSeenStr}</div>
            `;

            card.addEventListener('click', () => selectAgent(agent.uuid));
            container.appendChild(card);
        });
    } catch (err) {
        console.error("Failed to load agents list", err);
    }
}

// Select active agent filter
function selectAgent(uuid) {
    activeAgent = uuid;
    currentPage = 0;
    
    // Update active UI classes
    document.querySelectorAll('.agent-card').forEach(card => {
        if (card.getAttribute('data-uuid') === uuid) {
            card.classList.add('active');
        } else {
            card.classList.remove('active');
        }
    });

    updateStatsAndCharts();
    fetchEventsTable();
}

// Retrieve stats cards and chart datasets
async function updateStatsAndCharts() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();

        // Update stats cards
        document.getElementById('stat-total-val').textContent = stats.total_events || 0;
        document.getElementById('stat-crit-val').textContent = stats.by_severity['2'] || 0;

        // Render charts data
        updateCharts(stats);
    } catch (err) {
        console.error("Failed to load stats", err);
    }
}

// Retrieve event logs table data
async function fetchEventsTable() {
    try {
        let url = `/api/events?limit=${limit}&offset=${currentPage * limit}`;
        if (activeAgent !== 'all') {
            url += `&agent=${activeAgent}`;
        }

        const res = await fetch(url);
        const events = await res.json();

        const tbody = document.getElementById('events-tbody');
        tbody.innerHTML = '';

        if (events.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 30px;">No events matched your filter.</td></tr>`;
            document.getElementById('btn-next').disabled = true;
            document.getElementById('btn-prev').disabled = currentPage === 0;
            return;
        }

        events.forEach(event => {
            const tr = document.createElement('tr');
            const sev = severityMap[event.severity] || { name: 'UNKNOWN', class: 'badge-info' };
            const threatName = threatNames[event.threat_type] || `Threat ${event.threat_type}`;

            tr.innerHTML = `
                <td>${formatTime(event.timestamp)}</td>
                <td><span style="font-family:monospace; font-size:0.75rem;">${event.agent_uuid.substring(0, 8)}...</span></td>
                <td>${event.src_ip}:${event.src_port}</td>
                <td>${event.dest_ip}:${event.dest_port}</td>
                <td>${threatName}</td>
                <td><span class="badge ${sev.class}">${sev.name}</span></td>
                <td><span style="font-family:monospace; font-size:0.75rem;">${event.payload_preview}</span></td>
            `;
            tbody.appendChild(tr);
        });

        // Update pagination buttons state
        document.getElementById('btn-prev').disabled = currentPage === 0;
        document.getElementById('btn-next').disabled = events.length < limit;
    } catch (err) {
        console.error("Failed to load events logs table", err);
    }
}

// Change page
function changePage(direction) {
    currentPage += direction;
    if (currentPage < 0) currentPage = 0;
    fetchEventsTable();
}

// Initialize empty Chart.js graphs
function initCharts() {
    // 1. Timeline Chart
    const ctxTimeline = document.getElementById('timeline-chart').getContext('2d');
    timelineChart = new Chart(ctxTimeline, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts Count',
                data: [],
                borderColor: '#3b82f6',
                borderWidth: 2,
                backgroundColor: 'rgba(59, 130, 246, 0.05)',
                fill: true,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.02)' },
                    ticks: { color: '#9ca3af', font: { family: 'Outfit', size: 10 } }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.02)' },
                    ticks: { color: '#9ca3af', font: { family: 'Outfit', size: 10 } },
                    suggestedMin: 0
                }
            }
        }
    });

    // 2. Threat Vector Pie Chart
    const ctxThreat = document.getElementById('threat-chart').getContext('2d');
    threatChart = new Chart(ctxThreat, {
        type: 'doughnut',
        data: {
            labels: ['PHP Shells', 'XSS', 'SYN Flood', 'Slowloris', 'Blocklist'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#8e44ad', '#7f8c8d'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#9ca3af', font: { family: 'Outfit', size: 9 }, boxWidth: 10 }
                }
            },
            cutout: '70%'
        }
    });
}

// Populate charts with stats payload
function updateCharts(stats) {
    // 1. Update Timeline Line Chart
    const labels = [];
    const counts = [];
    
    // Sort timeline chronologically
    const timeline = stats.timeline || [];
    timeline.forEach(point => {
        const timeStr = new Date(point.time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        labels.push(timeStr);
        counts.push(point.count);
    });

    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = counts;
    timelineChart.update();

    // 2. Update Doughnut Chart
    // Threat indexes: 1=PHP Shell, 2=XSS, 3=SYN Flood, 4=Slowloris, 5=Blocklist
    const threatCounts = [
        stats.by_threat['1'] || 0,
        stats.by_threat['2'] || 0,
        stats.by_threat['3'] || 0,
        stats.by_threat['4'] || 0,
        stats.by_threat['5'] || 0
    ];

    threatChart.data.datasets[0].data = threatCounts;
    threatChart.update();
}

// Live increment chart counters on receiving an event
function incrementChartData(event) {
    // Increment doughnut slice
    const index = event.threat_type - 1; // mapping threat 1-5 to index 0-4
    if (index >= 0 && index < 5) {
        threatChart.data.datasets[0].data[index] += 1;
        threatChart.update();
    }

    // Increment last data point in timeline chart
    const dataLen = timelineChart.data.datasets[0].data.length;
    if (dataLen > 0) {
        timelineChart.data.datasets[0].data[dataLen - 1] += 1;
        timelineChart.update();
    }
}
