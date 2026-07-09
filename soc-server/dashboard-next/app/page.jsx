"use client";

import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, Server, Terminal, List, Settings, Activity, AlertTriangle, 
  RefreshCw, Power, Trash2, ShieldAlert, Cpu, Network, BookOpen, Globe
} from 'lucide-react';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState({ total_events: 0, by_threat: {}, by_severity: {}, timeline: [] });
  const [events, setEvents] = useState([]);
  const [agents, setAgents] = useState([]);
  const [blocklist, setBlocklist] = useState([]);
  const [reputation, setReputation] = useState([]);
  const [yaraRules, setYaraRules] = useState([]);
  const [configs, setConfigs] = useState({});
  const [intel, setIntel] = useState([]);
  
  // Forms state
  const [newIp, setNewIp] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [yaraName, setYaraName] = useState('');
  const [yaraContent, setYaraContent] = useState('');
  const [configKey, setConfigKey] = useState('');
  const [configValue, setConfigValue] = useState('');
  const [configCat, setConfigCat] = useState('general');
  const [statusMessage, setStatusMessage] = useState({ text: '', type: 'info' });
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Live timeline canvas chart ref
  const canvasRef = useRef(null);

  const API_BASE = ""; // Relative to server root

  const showStatus = (text, type = 'info') => {
    setStatusMessage({ text, type });
    setTimeout(() => setStatusMessage({ text: '', type: 'info' }), 4000);
  };

  const fetchData = async () => {
    setIsRefreshing(true);
    try {
      // 1. Stats
      const statsRes = await fetch(`${API_BASE}/api/v2/dashboard/stats`);
      if (statsRes.ok) setStats(await statsRes.json());

      // 2. Events
      const eventsRes = await fetch(`${API_BASE}/api/events?limit=25`);
      if (eventsRes.ok) setEvents(await eventsRes.json());

      // 3. Agents
      const agentsRes = await fetch(`${API_BASE}/api/v2/agents`);
      if (agentsRes.ok) setAgents(await agentsRes.json());

      // 4. Blocklist
      const blockRes = await fetch(`${API_BASE}/api/v2/blocklist`);
      if (blockRes.ok) setBlocklist(await blockRes.json());

      // 5. Reputation
      const repRes = await fetch(`${API_BASE}/api/v2/reputation`);
      if (repRes.ok) setReputation(await repRes.json());

      // 6. YARA
      const yaraRes = await fetch(`${API_BASE}/api/v2/yara/rules`);
      if (yaraRes.ok) setYaraRules(await yaraRes.json());

      // 7. Configs
      const configRes = await fetch(`${API_BASE}/api/v2/config`);
      if (configRes.ok) setConfigs(await configRes.json());

      // 8. Threat Intel
      const intelRes = await fetch(`${API_BASE}/api/v2/threat-intel`);
      if (intelRes.ok) setIntel(await intelRes.json());

    } catch (err) {
      console.error("Failed to fetch dashboard data:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Custom canvas rendering for timeline (no Chart.js needed)
  useEffect(() => {
    if (activeTab === 'overview' && canvasRef.current && stats.timeline) {
      const ctx = canvasRef.current.getContext('2d');
      const w = canvasRef.current.width;
      const h = canvasRef.current.height;
      
      ctx.clearRect(0, 0, w, h);
      
      if (stats.timeline.length < 2) {
        ctx.fillStyle = '#9ca3af';
        ctx.font = '12px Inter';
        ctx.fillText('Insufficient timeline data yet', w/2 - 80, h/2);
        return;
      }

      // Draw grid
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.lineWidth = 1;
      for (int i = 1; i < 5; i++) {
        ctx.beginPath();
        ctx.moveTo(0, h * i / 5);
        ctx.lineTo(w, h * i / 5);
        ctx.stroke();
      }

      // Plot path
      const points = stats.timeline;
      const maxCount = Math.max(...points.map(p => parseInt(p.count)), 5);
      const stepX = w / (points.length - 1);

      ctx.beginPath();
      ctx.strokeStyle = '#00d4ff';
      ctx.lineWidth = 2;
      
      points.forEach((p, idx) => {
        const x = idx * stepX;
        const y = h - (p.count / maxCount * (h - 20)) - 10;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();

      // Area fill
      ctx.lineTo((points.length - 1) * stepX, h);
      ctx.lineTo(0, h);
      ctx.closePath();
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, 'rgba(0, 212, 255, 0.15)');
      grad.addColorStop(1, 'rgba(0, 212, 255, 0.0)');
      ctx.fillStyle = grad;
      ctx.fill();
    }
  }, [activeTab, stats.timeline]);

  // Operations
  const handleBlockIp = async (e) => {
    e.preventDefault();
    if (!newIp) return;
    try {
      const res = await fetch(`${API_BASE}/api/v2/blocklist`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip_cidr: newIp, reason: blockReason || "Dashboard manual block" })
      });
      if (res.ok) {
        showStatus(`IP ${newIp} added to blocklist`, 'success');
        setNewIp('');
        setBlockReason('');
        fetchData();
      } else {
        showStatus("Failed to block IP", 'error');
      }
    } catch (err) {
      showStatus("Network error blocking IP", 'error');
    }
  };

  const handleRemoveBlock = async (ipCidr) => {
    try {
      const res = await fetch(`${API_BASE}/api/v2/blocklist/${ipCidr}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        showStatus("IP removed from blocklist", 'success');
        fetchData();
      }
    } catch (err) {
      showStatus("Failed to remove IP", 'error');
    }
  };

  const handleRemoveAgent = async (uuid) => {
    if (!confirm("Are you sure you want to remove this agent node?")) return;
    try {
      const res = await fetch(`${API_BASE}/api/v2/agents/${uuid}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        showStatus("Agent removed from dashboard registry", 'success');
        fetchData();
      }
    } catch (err) {
      showStatus("Failed to remove agent", 'error');
    }
  };

  const handleUploadYara = async (e) => {
    e.preventDefault();
    if (!yaraName || !yaraContent) return;
    try {
      const res = await fetch(`${API_BASE}/api/v2/yara/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: yaraName, content: yaraContent })
      });
      if (res.ok) {
        showStatus(`YARA rule ${yaraName} uploaded successfully`, 'success');
        setYaraName('');
        setYaraContent('');
        fetchData();
      } else {
        showStatus("Failed to upload YARA rule", 'error');
      }
    } catch (err) {
      showStatus("Network error uploading YARA rule", 'error');
    }
  };

  const handleDeleteYara = async (name) => {
    try {
      const res = await fetch(`${API_BASE}/api/v2/yara/rules/${name}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        showStatus("YARA rule deleted", 'success');
        fetchData();
      }
    } catch (err) {
      showStatus("Failed to delete YARA rule", 'error');
    }
  };

  const handleSaveConfig = async (e) => {
    e.preventDefault();
    if (!configKey || !configValue) return;
    try {
      const res = await fetch(`${API_BASE}/api/v2/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: configKey, value: configValue, category: configCat })
      });
      if (res.ok) {
        showStatus(`Config ${configKey} saved`, 'success');
        setConfigKey('');
        setConfigValue('');
        fetchData();
      }
    } catch (err) {
      showStatus("Failed to save config", 'error');
    }
  };

  const handleIntelFetch = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v2/threat-intel/fetch`, {
        method: 'POST'
      });
      if (res.ok) {
        showStatus("Threat Intelligence feed fetches triggered in background", 'success');
      }
    } catch (err) {
      showStatus("Failed to trigger fetch", 'error');
    }
  };

  // Helper mapping threat names
  const getThreatName = (type) => {
    const map = {
      1: 'PHP Shell Payload',
      2: 'XSS Query Attack',
      3: 'SYN Flood Rate-limit',
      4: 'Slowloris TCP Timeout',
      5: 'IP Address Blocked',
      6: 'SQL Injection',
      7: 'Command Injection',
      8: 'Path Traversal',
      9: 'Local File Inclusion',
      10: 'Remote File Inclusion',
      11: 'Bot / Automated Scanner',
      12: 'YARA Signature Trigger',
      13: 'High Malice IP Reputation'
    };
    return map[type] || `Unknown (${type})`;
  };

  return (
    <div className="flex min-h-screen bg-[#030712] text-gray-100 font-sans">
      
      {/* Sidebar */}
      <aside className="w-64 bg-[#080d1a] border-r border-gray-900 flex flex-col justify-between shrink-0">
        <div>
          <div className="p-6 flex items-center space-x-3 border-b border-gray-900">
            <Shield className="w-8 h-8 text-[#00d4ff] pulse" />
            <div>
              <span className="font-bold text-lg tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-indigo-500">NULLSPLOIT</span>
              <div className="text-[10px] text-cyan-400 font-mono tracking-widest uppercase">WAF Dashboard</div>
            </div>
          </div>
          
          <nav className="p-4 space-y-1">
            {[
              { id: 'overview', name: 'Overview', icon: Activity },
              { id: 'events', name: 'Security Events', icon: ShieldAlert },
              { id: 'agents', name: 'Agents Node', icon: Server },
              { id: 'yara', name: 'YARA Engine', icon: BookOpen },
              { id: 'reputation', name: 'IP Reputation', icon: Network },
              { id: 'intel', name: 'Threat Intelligence', icon: Globe },
              { id: 'configs', name: 'Global Settings', icon: Settings },
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                    activeTab === tab.id 
                      ? 'bg-gradient-to-r from-cyan-950 to-indigo-950 border border-cyan-800/50 text-[#00d4ff] shadow-md shadow-cyan-950/20' 
                      : 'text-gray-400 hover:bg-gray-900 hover:text-gray-100'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span>{tab.name}</span>
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-6 border-t border-gray-900 text-xs text-gray-500 font-mono">
          Nullsploit WAF v2.0<br/>Linux & Docker Only
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0">
        
        {/* Header */}
        <header className="h-16 border-b border-gray-900 flex items-center justify-between px-8 bg-[#050b16]/50 backdrop-blur-md sticky top-0 z-40">
          <h1 className="text-lg font-bold tracking-wide uppercase text-gray-300">
            {activeTab} console
          </h1>

          <div className="flex items-center space-x-4">
            {/* Status alerts */}
            {statusMessage.text && (
              <span className={`px-4 py-1.5 rounded-full text-xs font-mono border ${
                statusMessage.type === 'success' ? 'bg-green-950/50 border-green-800 text-green-400' :
                statusMessage.type === 'error' ? 'bg-red-950/50 border-red-800 text-red-400' :
                'bg-cyan-950/50 border-cyan-800 text-cyan-400'
              }`}>
                {statusMessage.text}
              </span>
            )}

            <button 
              onClick={fetchData} 
              disabled={isRefreshing}
              className="p-2 rounded-lg bg-gray-900 border border-gray-800 hover:bg-gray-800 transition-colors text-gray-400 hover:text-gray-200"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-[#00d4ff]' : ''}`} />
            </button>

            <span className="text-xs text-gray-400 font-mono border border-gray-800 bg-gray-900 px-3 py-1.5 rounded-lg">
              SYSTEM: LINUX_BARE_DOCKER
            </span>
          </div>
        </header>

        {/* Tab Contents */}
        <div className="flex-1 p-8 overflow-y-auto">
          
          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="space-y-8 animate-[fadeIn_0.3s_ease-out]">
              
              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="glass rounded-xl p-6 glow-card">
                  <div className="text-gray-400 text-xs font-mono uppercase tracking-wider">Total Events</div>
                  <div className="text-3xl font-extrabold mt-2 text-[#00d4ff]">{stats.total_events}</div>
                </div>
                <div className="glass rounded-xl p-6 glow-card">
                  <div className="text-gray-400 text-xs font-mono uppercase tracking-wider">Active Agents</div>
                  <div className="text-3xl font-extrabold mt-2 text-green-400">
                    {agents.filter(a => a.status === 'active').length} / {agents.length}
                  </div>
                </div>
                <div className="glass rounded-xl p-6 glow-card">
                  <div className="text-gray-400 text-xs font-mono uppercase tracking-wider">Blocked IPs</div>
                  <div className="text-3xl font-extrabold mt-2 text-red-400">{blocklist.length}</div>
                </div>
                <div className="glass rounded-xl p-6 glow-card">
                  <div className="text-gray-400 text-xs font-mono uppercase tracking-wider">Threat Intel indicators</div>
                  <div className="text-3xl font-extrabold mt-2 text-indigo-400">{intel.length}</div>
                </div>
              </div>

              {/* Chart & Live Alerts */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                {/* Timeline */}
                <div className="lg:col-span-2 glass rounded-xl p-6">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6 flex items-center space-x-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    <span>24-Hour Threat timeline</span>
                  </h3>
                  <canvas ref={canvasRef} width="600" height="220" className="w-full h-56 bg-gray-950/30 rounded-lg border border-gray-900"></canvas>
                </div>

                {/* Severity doughnut equivalents */}
                <div className="glass rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6 flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 text-orange-400" />
                      <span>Severity Distribution</span>
                    </h3>
                    <div className="space-y-4">
                      {Object.keys(stats.by_severity).map((sev) => (
                        <div key={sev} className="flex justify-between items-center text-sm font-mono">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            sev === '2' ? 'bg-red-950 text-red-400 border border-red-900' :
                            sev === '1' ? 'bg-yellow-950 text-yellow-400 border border-yellow-900' :
                            'bg-cyan-950 text-cyan-400 border border-cyan-900'
                          }`}>
                            {sev === '2' ? 'CRITICAL' : sev === '1' ? 'WARNING' : 'INFO'}
                          </span>
                          <span className="font-bold text-gray-300">{stats.by_severity[sev]}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  
                  <div className="border-t border-gray-900 pt-4 mt-6">
                    <span className="text-[10px] text-gray-500 font-mono uppercase">Decay engine: active (-5 pts/hr)</span>
                  </div>
                </div>
              </div>

              {/* Real-time Alerts log */}
              <div className="glass rounded-xl p-6">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6 flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-[#00d4ff]" />
                  <span>Real-time WAF alert log</span>
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-gray-900 text-gray-400">
                        <th className="pb-3 font-semibold">Timestamp</th>
                        <th className="pb-3 font-semibold">Agent Node</th>
                        <th className="pb-3 font-semibold">Threat Vector</th>
                        <th className="pb-3 font-semibold">Severity</th>
                        <th className="pb-3 font-semibold">Source IP</th>
                        <th className="pb-3 font-semibold">Preview / Pattern</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-900">
                      {events.slice(0, 10).map((evt) => (
                        <tr key={evt.id} className="hover:bg-gray-900/30 transition-colors">
                          <td className="py-3.5 text-gray-400">
                            {new Date(evt.timestamp * 1000).toISOString()}
                          </td>
                          <td className="py-3.5 text-[#00d4ff]">{evt.agent_uuid.substring(0, 8)}</td>
                          <td className="py-3.5 font-semibold text-gray-200">{getThreatName(evt.threat_type)}</td>
                          <td className="py-3.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] ${
                              evt.severity === 2 ? 'bg-red-950 text-red-400 border border-red-900' :
                              evt.severity === 1 ? 'bg-yellow-950 text-yellow-400 border border-yellow-900' :
                              'bg-cyan-950 text-cyan-400 border border-cyan-900'
                            }`}>
                              {evt.severity === 2 ? 'CRITICAL' : evt.severity === 1 ? 'WARNING' : 'INFO'}
                            </span>
                          </td>
                          <td className="py-3.5 text-orange-400 font-semibold">{evt.src_ip}</td>
                          <td className="py-3.5 text-gray-300 max-w-xs truncate">{evt.payload_preview}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* EVENTS TAB */}
          {activeTab === 'events' && (
            <div className="glass rounded-xl p-6 animate-[fadeIn_0.3s_ease-out]">
              <div className="flex justify-between items-center mb-6">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">Threat Event Repository</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-gray-900 text-gray-400">
                      <th className="pb-3">Timestamp</th>
                      <th className="pb-3">Source IP</th>
                      <th className="pb-3">Dest IP</th>
                      <th className="pb-3">Port (S/D)</th>
                      <th className="pb-3">Threat</th>
                      <th className="pb-3">Severity</th>
                      <th className="pb-3">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-900">
                    {events.map((evt) => (
                      <tr key={evt.id} className="hover:bg-gray-900/30">
                        <td className="py-3">{new Date(evt.timestamp * 1000).toISOString()}</td>
                        <td className="py-3 text-orange-400 font-semibold">{evt.src_ip}</td>
                        <td className="py-3 text-gray-400">{evt.dest_ip}</td>
                        <td className="py-3 text-gray-500">{evt.src_port} / {evt.dest_port}</td>
                        <td className="py-3 font-semibold">{getThreatName(evt.threat_type)}</td>
                        <td className="py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] ${
                            evt.severity === 2 ? 'bg-red-950 text-red-400 border border-red-900' :
                            evt.severity === 1 ? 'bg-yellow-950 text-yellow-400 border border-yellow-900' :
                            'bg-cyan-950 text-cyan-400 border border-cyan-900'
                          }`}>
                            {evt.severity === 2 ? 'CRITICAL' : evt.severity === 1 ? 'WARNING' : 'INFO'}
                          </span>
                        </td>
                        <td className="py-3 text-gray-300 max-w-sm truncate">{evt.details}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* AGENTS TAB */}
          {activeTab === 'agents' && (
            <div className="space-y-8 animate-[fadeIn_0.3s_ease-out]">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                
                {/* Active Agents List */}
                <div className="glass rounded-xl p-6">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">Connected WAF nodes</h3>
                  <div className="space-y-4">
                    {agents.map((agent) => (
                      <div key={agent.uuid} className="p-4 rounded-lg bg-gray-950 border border-gray-900 flex justify-between items-center">
                        <div className="flex items-center space-x-3">
                          <div className={`w-2.5 h-2.5 rounded-full ${agent.status === 'active' ? 'bg-green-500 pulse' : 'bg-gray-600'}`}></div>
                          <div>
                            <div className="font-semibold text-sm">{agent.hostname}</div>
                            <div className="text-xs font-mono text-gray-400">{agent.ip} | {agent.uuid.substring(0, 16)}...</div>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <button 
                            onClick={() => handleRemoveAgent(agent.uuid)}
                            className="p-1.5 rounded bg-gray-900 border border-gray-800 hover:bg-red-950 hover:border-red-900 text-gray-400 hover:text-red-400 transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Block an IP across specific Agent */}
                <div className="glass rounded-xl p-6">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">Block IP downstream</h3>
                  <form onSubmit={handleBlockIp} className="space-y-4">
                    <div>
                      <label className="block text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Target IP address</label>
                      <input 
                        type="text" 
                        value={newIp}
                        onChange={(e) => setNewIp(e.target.value)}
                        placeholder="e.g. 192.168.1.100" 
                        className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:border-[#00d4ff] text-gray-100"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Block Reason</label>
                      <input 
                        type="text" 
                        value={blockReason}
                        onChange={(e) => setBlockReason(e.target.value)}
                        placeholder="Manual dashboard block" 
                        className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:border-[#00d4ff] text-gray-100"
                      />
                    </div>
                    <button type="submit" className="w-full py-2.5 rounded-lg bg-[#00d4ff] hover:bg-cyan-500 text-gray-950 font-semibold text-sm transition-colors flex items-center justify-center space-x-2">
                      <Shield className="w-4 h-4" />
                      <span>Transmit Block command</span>
                    </button>
                  </form>
                </div>

              </div>

              {/* Blocklist Table */}
              <div className="glass rounded-xl p-6">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">Current active WAF blocklist</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-gray-900 text-gray-400">
                        <th className="pb-3">Block ID</th>
                        <th className="pb-3">IP / CIDR</th>
                        <th className="pb-3">Reason</th>
                        <th className="pb-3">Created At</th>
                        <th className="pb-3">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-900">
                      {blocklist.map((item) => (
                        <tr key={item.id}>
                          <td className="py-3 text-gray-500">{item.id}</td>
                          <td className="py-3 text-red-400 font-bold">{item.ip_cidr}</td>
                          <td className="py-3 text-gray-300">{item.reason}</td>
                          <td className="py-3 text-gray-400">{item.created_at}</td>
                          <td className="py-3">
                            <button 
                              onClick={() => handleRemoveBlock(item.ip_cidr)}
                              className="text-cyan-400 hover:text-cyan-200"
                            >
                              Unblock
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* YARA TAB */}
          {activeTab === 'yara' && (
            <div className="space-y-8 animate-[fadeIn_0.3s_ease-out]">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                {/* Upload YARA rules */}
                <div className="lg:col-span-2 glass rounded-xl p-6">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">Compiled YARA rule deployer</h3>
                  <form onSubmit={handleUploadYara} className="space-y-4">
                    <div>
                      <label className="block text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Rule identifier / Name</label>
                      <input 
                        type="text" 
                        value={yaraName}
                        onChange={(e) => setYaraName(e.target.value)}
                        placeholder="webshell_PHP_eval" 
                        className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:border-[#00d4ff] text-gray-100"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Rule source code (Monaco mock container)</label>
                      <textarea 
                        rows="10"
                        value={yaraContent}
                        onChange={(e) => setYaraContent(e.target.value)}
                        placeholder="rule php_webshell { strings: $a = 'eval(' condition: $a }"
                        className="w-full bg-gray-950 border border-gray-800 rounded-lg p-4 font-mono text-xs focus:outline-none focus:border-[#00d4ff] text-cyan-400"
                      />
                    </div>
                    <button type="submit" className="px-6 py-2.5 rounded-lg bg-[#00d4ff] hover:bg-cyan-500 text-gray-950 font-semibold text-sm transition-colors">
                      Deploy rule to cluster
                    </button>
                  </form>
                </div>

                {/* YARA Rules list */}
                <div className="glass rounded-xl p-6">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">YARA rule catalog</h3>
                  <div className="space-y-4">
                    {yaraRules.map((rule) => (
                      <div key={rule.id} className="p-4 rounded-lg bg-gray-950 border border-gray-900">
                        <div className="flex justify-between items-start mb-2">
                          <span className="font-mono text-sm text-cyan-400 font-bold">{rule.name}</span>
                          <button 
                            onClick={() => handleDeleteYara(rule.name)}
                            className="text-red-500 hover:text-red-400 text-xs"
                          >
                            Delete
                          </button>
                        </div>
                        <div className="text-xs text-gray-400 font-mono">Matches: {rule.match_count}</div>
                        <div className="text-[10px] text-gray-500 font-mono mt-1">Updated: {rule.updated_at}</div>
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            </div>
          )}

          {/* REPUTATION TAB */}
          {activeTab === 'reputation' && (
            <div className="glass rounded-xl p-6 animate-[fadeIn_0.3s_ease-out]">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">IP reputation & Malice scoring system</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-gray-900 text-gray-400">
                      <th className="pb-3">IP Address</th>
                      <th className="pb-3">Reputation Score</th>
                      <th className="pb-3">Local Scored</th>
                      <th className="pb-3">External Scored</th>
                      <th className="pb-3">Attacks Triggered</th>
                      <th className="pb-3">Last Activity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-900">
                    {reputation.map((rep) => (
                      <tr key={rep.ip}>
                        <td className="py-3 text-gray-200 font-bold">{rep.ip}</td>
                        <td className="py-3">
                          <span className={`px-2 py-0.5 rounded font-bold text-xs ${
                            rep.score >= 80 ? 'bg-red-950 text-red-400 border border-red-900' :
                            rep.score >= 40 ? 'bg-yellow-950 text-yellow-400 border border-yellow-900' :
                            'bg-green-950 text-green-400 border border-green-900'
                          }`}>
                            {rep.score} / 100
                          </span>
                        </td>
                        <td className="py-3 text-cyan-400">{rep.local_score}</td>
                        <td className="py-3 text-indigo-400">{rep.external_score}</td>
                        <td className="py-3 text-gray-300">{rep.attack_types || "None"}</td>
                        <td className="py-3 text-gray-400">{rep.updated_at}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* THREAT INTEL TAB */}
          {activeTab === 'intel' && (
            <div className="space-y-8 animate-[fadeIn_0.3s_ease-out]">
              <div className="flex justify-between items-center">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">Feed consensus and IOC database</h3>
                <button 
                  onClick={handleIntelFetch}
                  className="px-4 py-2 bg-gradient-to-r from-cyan-950 to-indigo-950 border border-cyan-800 text-cyan-400 text-xs rounded-lg font-mono flex items-center space-x-2"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Fetch all feeds now</span>
                </button>
              </div>

              <div className="glass rounded-xl p-6">
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-gray-900 text-gray-400">
                        <th className="pb-3">Feed Source</th>
                        <th className="pb-3">IOC Type</th>
                        <th className="pb-3">Indicator Value</th>
                        <th className="pb-3">Threat Vector</th>
                        <th className="pb-3">Confidence</th>
                        <th className="pb-3">Source URL</th>
                        <th className="pb-3">Fetched At</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-900">
                      {intel.map((item) => (
                        <tr key={item.id}>
                          <td className="py-3 text-cyan-400">{item.feed_name}</td>
                          <td className="py-3 text-gray-500 uppercase">{item.indicator_type}</td>
                          <td className="py-3 text-gray-200 font-semibold">{item.indicator_value}</td>
                          <td className="py-3 text-gray-400">{item.threat_type}</td>
                          <td className="py-3">
                            <span className="font-bold text-gray-300">{item.confidence}%</span>
                          </td>
                          <td className="py-3">
                            <a href={item.source_url} target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-200 max-w-xs truncate block">
                              Link
                            </a>
                          </td>
                          <td className="py-3 text-gray-500">{item.fetched_at}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* CONFIGS TAB */}
          {activeTab === 'configs' && (
            <div className="space-y-8 animate-[fadeIn_0.3s_ease-out]">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                
                {/* Save configuration form */}
                <div className="glass rounded-xl p-6">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">Modify system configs</h3>
                  <form onSubmit={handleSaveConfig} className="space-y-4">
                    <div>
                      <label className="block text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Key</label>
                      <input 
                        type="text" 
                        value={configKey}
                        onChange={(e) => setConfigKey(e.target.value)}
                        placeholder="e.g. rep_decay_rate" 
                        className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:border-[#00d4ff] text-gray-100"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Value (JSON format)</label>
                      <input 
                        type="text" 
                        value={configValue}
                        onChange={(e) => setConfigValue(e.target.value)}
                        placeholder='{"rate": 5}' 
                        className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:border-[#00d4ff] text-gray-100"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">Category</label>
                      <select 
                        value={configCat}
                        onChange={(e) => setConfigCat(e.target.value)}
                        className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2.5 font-mono text-sm focus:outline-none focus:border-[#00d4ff] text-gray-400"
                      >
                        <option value="general">General</option>
                        <option value="detection">Detection Engine</option>
                        <option value="feeds">Threat Feeds</option>
                        <option value="agents">Agents settings</option>
                      </select>
                    </div>
                    <button type="submit" className="w-full py-2.5 rounded-lg bg-[#00d4ff] hover:bg-cyan-500 text-gray-950 font-semibold text-sm transition-colors">
                      Commit setting changes
                    </button>
                  </form>
                </div>

                {/* Configurations parameters catalog */}
                <div className="glass rounded-xl p-6">
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400 mb-6">Active configs parameters</h3>
                  <div className="space-y-4">
                    {Object.keys(configs).map((key) => (
                      <div key={key} className="p-4 rounded-lg bg-gray-950 border border-gray-900 font-mono text-xs">
                        <div className="flex justify-between items-center mb-2">
                          <span className="font-bold text-cyan-400">{key}</span>
                          <span className="px-2 py-0.5 bg-cyan-950 text-cyan-400 rounded text-[9px] uppercase">{configs[key].category}</span>
                        </div>
                        <div className="text-gray-300 font-semibold">Value: {JSON.stringify(configs[key].value)}</div>
                        <div className="text-gray-500 mt-1">{configs[key].description}</div>
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            </div>
          )}

        </div>
      </main>

    </div>
  );
}
