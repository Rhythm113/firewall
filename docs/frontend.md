# Dashboard Frontend

## Overview

The dashboard is a single-page HTML application served by Spring Boot
at http://localhost:8443.

File: soc-server/dashboard-spring/src/main/resources/static/index.html

## Structure

### HTML Tabs

The page is organized into tabbed sections, each with a nav button
and a content div:

| Tab | ID | Description |
|-----|----|-------------|
| Overview | tab-overview | Stats, timeline chart, recent events |
| Events | tab-events | Paginated event table with filtering |
| Agents | tab-agents | Agent list with online/offline status |
| Agent Logs | tab-agentlogs | Searchable agent interaction logs |
| YARA Rules | tab-yara | YARA rule management |
| IP Reputation | tab-reputation | Local and external reputation views |
| Blacklist | tab-blacklist | Blocklist management |
| Configs | tab-configs | Configuration editor |
| Settings | tab-settings | SMTP and AI settings |
| AI Dataset | tab-dataset | AI analysis results and status |
| Health | tab-health | System health monitoring |

### Authentication Flow

1. Page loads: checks for stored token in localStorage
2. If no token: shows login overlay (username/password form)
3. On login success: stores token, loads dashboard data
4. Token sent as X-Session-Token header on all API requests
5. On 401 response: clears token, shows login screen

### CSS Styling

Dark theme with CSS custom properties:

```css
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-card: #1c2128;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --accent-blue: #58a6ff;
    --accent-green: #3fb950;
    --accent-red: #f85149;
    --accent-yellow: #d29922;
    --border-color: #30363d;
}
```

- Cards with subtle borders and hover effects
- Tables with alternating row backgrounds
- Badge classes for threat types and severity levels
- Responsive grid layout for stat cards
- Canvas-based timeline chart

## JavaScript Functions

### Data Loading

| Function | Description |
|----------|-------------|
| loadOverview() | Fetch and display dashboard stats |
| loadEvents() | Fetch and display paginated event list |
| loadAgents() | Fetch and display agent status list |
| loadAgentLogs() | Fetch and display agent logs with search |
| loadYaraRules() | Fetch and display YARA rules |
| loadReputation() | Fetch and display IP reputation |
| loadExternalReputation() | Fetch external reputation with pagination |
| loadBlocklist() | Fetch and display blocklist entries |
| loadConfig() | Fetch and display configuration |
| loadAIStatus() | Fetch AI analysis progress and status |
| loadDataset() | Fetch AI dataset entries |
| loadHealth() | Fetch system health metrics |

### Event Logging

| Function | Description |
|----------|-------------|
| logEvent(type, msg) | Log to the in-page debug console |
| logDebug(msg) | Debug-level console log |
| logInfo(msg) | Info-level log with blue badge |
| logError(msg) | Error-level log with red badge |

### Utility

| Function | Description |
|----------|-------------|
| sanitizeHtml(str) | Escape HTML entities |
| formatThreatType(t) | Convert threat type number to string label |
| formatSeverity(s) | Convert severity number to string |
| formatTimestamp(ts) | Format epoch timestamp to readable string |
| showSpinner() / hideSpinner() | Loading indicator |

### SSE Connection

```javascript
function connectSSE(token) {
    const source = new EventSource(`/api/v2/events/live?token=${token}`);
    source.onmessage = function(e) {
        const event = JSON.parse(e.data);
        refreshOverviewOnEvent(event);
        playAlertSound(event);
    };
}
```

Receives live events via Server-Sent Events. On each event:
1. Updates overview counts
2. Plays alert sound for CRITICAL/WARNING events
3. Logs event to debug console

### Timeline Chart

The `drawTimeline()` function uses a Canvas element to render a
line chart:

1. Parse timeline data points [{time, count}, ...]
2. Calculate chart dimensions (padding, axis labels)
3. Draw Y-axis with max count rounded up
4. Draw X-axis with time labels
5. Plot line path for data points
6. Fill area under the line with gradient
7. Handle empty data with placeholder message

## Threat Type Labels

```javascript
const THREAT_LABELS = {
    1:  'PHP Shell',
    2:  'XSS',
    3:  'SYN Flood',
    4:  'Slowloris',
    5:  'Blocklist Match',
    6:  'SQL Injection',
    7:  'Cmd Injection',
    8:  'Path Traversal',
    9:  'LFI',
    10: 'RFI',
    11: 'Bot',
    12: 'YARA Match',
    13: 'Low Reputation IP'
};
```

## Severity Badge Classes

- severity-critical: Red background (#f85149)
- severity-warning: Orange background (#d29922)
- severity-info: Gray background

## API Base URL

All API calls go to `/api/v2/` endpoint on the same origin (port
8443). The token is attached as X-Session-Token header.
