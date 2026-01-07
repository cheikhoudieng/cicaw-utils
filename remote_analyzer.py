#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import paramiko
import os
import re
import json
import math
import statistics
import socket
import webbrowser
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from collections import defaultdict
from threading import Thread
import time

# --- CHARGEMENT CONFIGURATION ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# CONFIGURATION SSH & PATHS
PA_HOST = os.getenv("PA_HOST", "ssh.pythonanywhere.com")
PA_USER = os.getenv("PA_USER", "Cicaw")
# Laissez vide pour forcer l'usage des clés SSH ou du mode Offline si échec
PA_PASSWORD = os.getenv("PA_PASSWORD", "") 

REMOTE_LOGS = [
    "/home/Cicaw/cicaw_project/persistent_logs/db_traffic_v15.log",
    "/home/Cicaw/cicaw_project/persistent_logs/cmd_traffic_v2.log"
]

# REGEX LOG PARSING
LOG_PATTERN = re.compile(
    r"^INFO\s+(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"IP:\s+(?P<ip>[\d\.]+)\s+\|\s+"
    r"Path:\s+(?P<path>.*?)\s+\|\s+"
    r"Queries:\s+(?P<queries>\d+)\s+\|\s+"
    r"Rows:\s+(?P<rows>\d+)\s+\|\s+"
    r"Est\. Size:\s+(?P<size>[\d\.]+)\s+KB"
    r"(?:\s+\|\s+Duration:\s+(?P<duration>[\d\.]+)\s*s)?"
    r"(?:\s+\|\s+Mem:\s+(?P<mem>[\d\.]+)\s*MB)?"
)

OUTPUT_FILENAME = "dashboard_omniview_v9.html"
LOCAL_LOG_DIR = "logs_buffer"

class EnterpriseMonitor:
    def __init__(self):
        self.stats = {
            'overview': {
                'total_reqs': 0, 'total_sql': 0, 'total_egress_kb': 0,
                'max_ram': 0, 'unique_ips': set()
            },
            'daily': defaultdict(lambda: {
                'reqs': 0, 'sql': 0, 'egress_kb': 0, 
                'ips': set(), 'duration_sum': 0
            }),
            'hourly': defaultdict(lambda: defaultdict(lambda: {
                'reqs': 0, 'sql': 0, 'egress_kb': 0
            })),
            'hourly_events': defaultdict(lambda: defaultdict(list)),
            'endpoints': defaultdict(lambda: {
                'hits': 0, 
                'sql': [], 
                'rows': [], 
                'size_kb': [], 
                'durations': [], 
                'mems': [], 
                'type': 'WEB',
                'history': defaultdict(lambda: {'hits': 0, 'sql_sum': 0, 'dur_sum': 0, 'mem_max': 0})
            })
        }

    def fetch_logs(self):
        """Récupère les logs via SFTP ou utilise le cache local en cas d'erreur."""
        local_files = []
        if not os.path.exists(LOCAL_LOG_DIR):
            os.makedirs(LOCAL_LOG_DIR)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"🔄 Connexion au cluster {PA_HOST}...")
            
            connect_kwargs = {"hostname": PA_HOST, "username": PA_USER, "timeout": 10}
            if PA_PASSWORD:
                connect_kwargs["password"] = PA_PASSWORD
            
            client.connect(**connect_kwargs)
            sftp = client.open_sftp()
            
            for remote in REMOTE_LOGS:
                local_name = os.path.join(LOCAL_LOG_DIR, os.path.basename(remote))
                try:
                    sftp.get(remote, local_name)
                    local_files.append(local_name)
                    print(f"✅ Sync Réussie: {remote}")
                except Exception as e:
                    print(f"⚠️ Erreur Sync {remote}: {e}")
            
            sftp.close()
            client.close()
        except Exception as e:
            print(f"⚠️ Mode Offline activé (Erreur SSH): {e}")
            # Utiliser les fichiers existants
            for remote in REMOTE_LOGS:
                local_name = os.path.join(LOCAL_LOG_DIR, os.path.basename(remote))
                if os.path.exists(local_name):
                    local_files.append(local_name)
        
        return local_files

    def parse_logs(self, files):
        print("📊 Analyse télémétrique & Clustering IP...")
        for file_path in files:
            is_cmd_file = "cmd" in file_path.lower()
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = LOG_PATTERN.search(line)
                        if not match: continue

                        d = match.groupdict()
                        queries = int(d['queries'])
                        rows = int(d['rows'])
                        size = float(d['size'])
                        duration = float(d['duration']) if d['duration'] else 0.0
                        mem = float(d['mem']) if d['mem'] else 0.0
                        path = d['path'].strip()
                        date = d['date']
                        time_str = d['time']
                        hour = time_str.split(':')[0] 
                        ip = d['ip']
                        
                        row_type = 'CMD' if (is_cmd_file or 'CMD::' in path or duration > 0) else 'WEB'

                        # Overview
                        self.stats['overview']['total_reqs'] += 1
                        self.stats['overview']['total_sql'] += queries
                        self.stats['overview']['total_egress_kb'] += size
                        self.stats['overview']['unique_ips'].add(ip)
                        if mem > self.stats['overview']['max_ram']: self.stats['overview']['max_ram'] = mem

                        # Daily
                        day = self.stats['daily'][date]
                        day['reqs'] += 1
                        day['sql'] += queries
                        day['egress_kb'] += size
                        day['ips'].add(ip)
                        if duration > 0: day['duration_sum'] += duration

                        # Hourly Stats
                        h_stats = self.stats['hourly'][date][hour]
                        h_stats['reqs'] += 1
                        h_stats['sql'] += queries
                        h_stats['egress_kb'] += size

                        # Hourly Events (Limited storage for GeoIP detail view)
                        if len(self.stats['hourly_events'][date][hour]) < 2500:
                             self.stats['hourly_events'][date][hour].append({
                                 'time': time_str, 'ip': ip, 'path': path.replace('CMD::', ''),
                                 'sql': queries, 'dur': duration, 'mem': mem, 'type': row_type
                             })

                        # Endpoints Aggregation
                        ep = self.stats['endpoints'][path]
                        ep['type'] = row_type
                        ep['hits'] += 1
                        ep['sql'].append(queries)
                        ep['rows'].append(rows)
                        ep['size_kb'].append(size)
                        if duration > 0: ep['durations'].append(duration)
                        if mem > 0: ep['mems'].append(mem)

                        # Endpoint History
                        hist = ep['history'][date]
                        hist['hits'] += 1
                        hist['sql_sum'] += queries
                        hist['dur_sum'] += duration
                        if mem > hist['mem_max']: hist['mem_max'] = mem
            except Exception as e:
                print(f"❌ Erreur lecture fichier {file_path}: {e}")

    def calculate_percentile(self, data, percentile=95):
        if not data: return 0
        data.sort()
        k = (len(data) - 1) * (percentile / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c: return data[int(k)]
        return data[int(f)] * (c - k) + data[int(c)] * (k - f)

    def generate_recommendations(self, avg_sql, p95_dur, avg_rows, max_mem, total_hits):
        report = []
        if avg_sql > 50: report.append({ "level": "CRITICAL", "title": "Problème N+1 Critique", "desc": f"Moyenne de {avg_sql:.1f} requêtes SQL.", "action": "Utilisez select_related/prefetch_related." })
        elif avg_sql > 15: report.append({ "level": "WARNING", "title": "Optimisation SQL nécessaire", "desc": f"{avg_sql:.1f} requêtes par appel.", "action": "Installez Django Debug Toolbar." })
        if p95_dur > 5.0: report.append({ "level": "CRITICAL", "title": "Latence Critique", "desc": f"95% > {p95_dur:.1f}s.", "action": "Déplacez vers Celery ou ajoutez des index DB." })
        if avg_rows > 2000: report.append({ "level": "CRITICAL", "title": "Volume de données élevé", "desc": f"{avg_rows:.0f} lignes retournées.", "action": "Pagination requise." })
        if max_mem > 150: report.append({ "level": "WARNING", "title": "Consommation RAM", "desc": f"Pic: {max_mem:.0f} MB.", "action": "Utilisez .iterator()." })
        if not report: report.append({ "level": "SUCCESS", "title": "Endpoint Sain", "desc": "R.A.S.", "action": "Monitoring continu." })
        return report

    def get_peak_hours(self):
        all_hours = []
        for date, hours_data in self.stats['hourly'].items():
            for hour, data in hours_data.items():
                all_hours.append({ 'date': date, 'hour': hour, 'reqs': data['reqs'], 'sql': data['sql'] })
        return sorted(all_hours, key=lambda x: x['reqs'], reverse=True)[:4]

    def generate_html(self):
        s = self.stats
        dates = sorted(s['daily'].keys())
        global_labels = dates
        
        # Données Globales
        global_egress = [round(s['daily'][d]['egress_kb'] / 1024, 2) for d in dates]
        global_sql = [s['daily'][d]['sql'] for d in dates]
        global_reqs = [s['daily'][d]['reqs'] for d in dates] # NOUVEAU INDICATEUR

        # Hourly Data Construction
        hourly_db = {}
        hourly_events_db = {} 
        for d in dates:
            h_data = s['hourly'][d]
            sorted_hours = sorted(h_data.keys())
            hourly_db[d] = {
                'labels': [f"{h}h" for h in sorted_hours],
                'egress': [round(h_data[h]['egress_kb'] / 1024, 2) for h in sorted_hours],
                'sql': [h_data[h]['sql'] for h in sorted_hours],
                'reqs': [h_data[h]['reqs'] for h in sorted_hours], # NOUVEAU INDICATEUR
                'raw_hours': sorted_hours
            }
            hourly_events_db[d] = {}
            for h in sorted_hours:
                hourly_events_db[d][h] = s['hourly_events'][d][h]

        # Endpoint Processing for Table & JS Database
        endpoints_table_data = [] # List for the table (lighter)
        endpoint_details_map = {} # Map for modals (heavier)

        for path, data in s['endpoints'].items():
            if data['hits'] == 0: continue
            
            avg_sql = statistics.mean(data['sql'])
            p95_dur = self.calculate_percentile(data['durations'], 95) if data['durations'] else 0
            max_mem = max(data['mems']) if data['mems'] else 0
            avg_rows = statistics.mean(data['rows']) if data['rows'] else 0
            total_egress_mb = sum(data['size_kb']) / 1024
            
            # Risk Calculation
            n1_class, n1_risk, risk_score = "text-slate-500", "LOW", 1
            if avg_sql > 50: n1_class, n1_risk, risk_score = "text-red-500 font-bold", "CRITICAL", 3
            elif avg_sql > 15: n1_class, n1_risk, risk_score = "text-orange-400 font-bold", "SUSPECT", 2

            # Data object for the frontend table
            endpoints_table_data.append({
                'path': path, 
                'clean_path': path.replace('CMD::', ''),
                'risk_text': n1_risk,
                'risk_score': risk_score,
                'risk_class': n1_class,
                'avg_sql': round(avg_sql, 1), 
                'hits': data['hits'],
                'total_egress': round(total_egress_mb, 2),
                'p95_dur': round(p95_dur, 2), 
                'avg_rows': round(avg_rows, 0)
            })

            # History for Charts
            history_data = []
            for d in dates:
                h = data['history'].get(d, {'hits': 0, 'sql_sum': 0})
                history_data.append({ 'date': d, 'hits': h['hits'], 'avg_sql': round(h['sql_sum'] / h['hits'], 1) if h['hits'] else 0 })

            endpoint_details_map[path] = {
                'meta': {'hits': data['hits'], 'avg_sql': round(avg_sql, 1), 'p95_dur': round(p95_dur, 2), 'max_mem': round(max_mem, 1), 'avg_rows': round(avg_rows, 0)},
                'report': self.generate_recommendations(avg_sql, p95_dur, avg_rows, max_mem, data['hits']),
                'history': history_data
            }

        # Keep Top 500 significant endpoints to avoid browser lag, but sort logic is client-side
        endpoints_table_data = sorted(endpoints_table_data, key=lambda x: x['total_egress'], reverse=True)[:500]
        peak_hours = self.get_peak_hours()

        html_content = f"""
        <!DOCTYPE html>
        <html lang="fr" class="dark">
        <head>
            <meta charset="UTF-8">
            <title>Cicaw OmniView v9 PRO</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ background-color: #0b0e14; font-family: 'Inter', sans-serif; }}
                .glass-panel {{ background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.05); }}
                .clickable-row:hover {{ background-color: rgba(59, 130, 246, 0.1); cursor: pointer; }}
                .clickable-card:hover {{ transform: translateY(-2px); border-color: rgba(239, 68, 68, 0.5); cursor: pointer; }}
                .sort-header {{ cursor: pointer; user-select: none; transition: color 0.2s; }}
                .sort-header:hover {{ color: #60a5fa; }}
                .sort-icon {{ display: inline-block; width: 10px; font-size: 0.8em; margin-left: 4px; }}
                /* Scrollbar */
                ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
                ::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 4px; }}
                ::-webkit-scrollbar-track {{ background: #0f172a; }}
                /* Modals */
                .modal-backdrop {{ opacity: 0; pointer-events: none; transition: opacity 0.3s ease; }}
                .modal-backdrop.show {{ opacity: 1; pointer-events: auto; }}
                .ip-details {{ max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }}
                .ip-details.open {{ max-height: 1000px; overflow-y: auto; }}
            </style>
        </head>
        <body class="text-slate-300 min-h-screen p-4 md:p-8">
            <!-- MODAL DETAIL ENDPOINT -->
            <div id="detailModal" class="modal-backdrop fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
                <div class="glass-panel w-full max-w-6xl max-h-[95vh] rounded-2xl bg-[#0f172a] border border-slate-700 flex flex-col overflow-hidden">
                    <div class="p-6 border-b border-slate-700/50 flex justify-between bg-slate-900/50">
                        <h2 id="modalTitle" class="text-xl font-bold text-white break-all font-mono">...</h2>
                        <button onclick="closeModal('detailModal')" class="text-slate-400 hover:text-white">✕</button>
                    </div>
                    <div class="overflow-y-auto p-6 space-y-6">
                        <div class="grid grid-cols-4 gap-4">
                             <div class="glass-panel p-4 rounded bg-slate-800/50"><div class="text-xs uppercase">Hits</div><div id="m_hits" class="text-2xl font-bold text-white">0</div></div>
                             <div class="glass-panel p-4 rounded bg-slate-800/50"><div class="text-xs uppercase">Avg SQL</div><div id="m_sql" class="text-2xl font-bold text-blue-400">0</div></div>
                             <div class="glass-panel p-4 rounded bg-slate-800/50"><div class="text-xs uppercase">Max Mem</div><div id="m_mem" class="text-2xl font-bold text-purple-400">0</div></div>
                             <div class="glass-panel p-4 rounded bg-slate-800/50"><div class="text-xs uppercase">Rows</div><div id="m_rows" class="text-2xl font-bold text-yellow-400">0</div></div>
                        </div>
                        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                            <div class="lg:col-span-2 glass-panel p-4 rounded h-[300px]"><canvas id="modalChart"></canvas></div>
                            <div class="glass-panel rounded overflow-hidden flex flex-col">
                                <div class="p-3 bg-slate-800 font-bold text-sm">📋 RAPPORT</div>
                                <div id="reportContainer" class="p-4 space-y-3 overflow-y-auto max-h-[250px]"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- MODAL SESSION INSPECTOR -->
            <div id="sessionModal" class="modal-backdrop fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
                 <div class="glass-panel w-full max-w-6xl max-h-[90vh] rounded-2xl bg-[#0f172a] border border-slate-700 flex flex-col overflow-hidden">
                    <div class="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-900">
                        <div><div class="text-xs font-mono text-purple-400">SESSION INSPECTOR v9</div><h2 id="sessionTitle" class="text-xl font-bold text-white">GeoIP Cluster Analysis</h2></div>
                        <button onclick="closeModal('sessionModal')" class="bg-slate-800 hover:bg-slate-700 px-3 py-1 rounded text-white">Fermer</button>
                    </div>
                    <div id="sessionContent" class="flex-grow overflow-y-auto p-4 space-y-2"></div>
                 </div>
            </div>

            <!-- HEADER -->
            <header class="flex flex-col md:flex-row justify-between items-end mb-8 max-w-[90rem] mx-auto">
                <div>
                    <h1 class="text-4xl font-black text-white mb-1">Cicaw<span class="text-blue-500">OmniView</span> <span class="text-sm bg-purple-900 text-purple-300 px-2 rounded">PRO v9.0</span></h1>
                    <p class="text-sm text-slate-500">Server Performance & Traffic Analytics</p>
                </div>
                <div class="text-right">
                    <div class="text-3xl font-bold text-white">{s['overview']['total_reqs']:,}</div>
                    <div class="text-xs text-slate-500 uppercase">Total Requests</div>
                </div>
            </header>

            <main class="max-w-[90rem] mx-auto space-y-8">
                <!-- PEAK CARDS -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    {''.join([f'''
                    <div onclick="openSessionModal('{p['date']}', '{p['hour']}')" class="clickable-card transition glass-panel p-4 rounded-xl border-l-4 border-red-500 bg-gradient-to-br from-slate-900 to-slate-800 relative group">
                        <div class="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition text-xs text-blue-400">🔍 Inspecter IPs</div>
                        <div class="flex justify-between items-start mb-2"><span class="text-xs font-bold text-red-400 uppercase tracking-wider">Peak Traffic</span><span class="text-xs text-slate-500">{p['date']}</span></div>
                        <div class="text-3xl font-bold text-white mb-1">{p['hour']}h <span class="text-lg text-slate-500 font-normal">00</span></div>
                        <div class="text-sm text-slate-400 flex gap-3"><span>🔥 {p['reqs']} reqs</span><span class="text-blue-400">🗄️ {p['sql']} sql</span></div>
                    </div>
                    ''' for p in peak_hours])}
                </div>

                <!-- MAIN CHART -->
                <div class="glass-panel p-6 rounded-xl border-t border-slate-700">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-sm font-bold text-white flex items-center gap-2"><span id="chartTitle">Global Load Overview (Daily)</span></h3>
                        <select id="dateFilter" class="bg-slate-900 border border-slate-700 text-white text-sm rounded px-3 py-1.5 focus:outline-none focus:border-blue-500">
                            <option value="ALL">🌍 Vue Globale</option>
                            {''.join([f'<option value="{d}">{d}</option>' for d in dates])}
                        </select>
                    </div>
                    <div class="relative h-64 w-full"><canvas id="mainChart"></canvas></div>
                </div>

                <!-- SORTABLE TABLE -->
                <div class="glass-panel rounded-xl overflow-hidden border border-slate-700/50">
                    <div class="p-4 bg-slate-800/80 flex justify-between items-center">
                        <h3 class="font-bold text-white">Top Endpoints Performance</h3>
                        <span class="text-xs text-slate-500">Click headers to sort</span>
                    </div>
                    <table class="w-full text-left text-xs">
                        <thead class="bg-slate-800/50 text-slate-400 uppercase font-semibold">
                            <tr>
                                <th class="p-4 sort-header" onclick="sortTable('path')">Path <span id="sort-path" class="sort-icon"></span></th>
                                <th class="p-4 text-center sort-header" onclick="sortTable('risk_score')">Risk <span id="sort-risk_score" class="sort-icon"></span></th>
                                <th class="p-4 text-right sort-header" onclick="sortTable('avg_sql')">Avg SQL <span id="sort-avg_sql" class="sort-icon"></span></th>
                                <th class="p-4 text-right sort-header" onclick="sortTable('hits')">Hits <span id="sort-hits" class="sort-icon"></span></th>
                                <th class="p-4 text-right sort-header" onclick="sortTable('total_egress')">Data (MB) <span id="sort-total_egress" class="sort-icon">▼</span></th>
                                <th class="p-4 text-right sort-header" onclick="sortTable('p95_dur')">P95 Time <span id="sort-p95_dur" class="sort-icon"></span></th>
                            </tr>
                        </thead>
                        <tbody id="endpointsBody" class="divide-y divide-slate-700/50">
                            <!-- JS Generated Rows -->
                        </tbody>
                    </table>
                </div>
            </main>

            <script>
                // DATA INJECTION
                const ENDPOINT_DETAILS = {json.dumps(endpoint_details_map)};
                const GLOBAL_DATA = {{ 
                    labels: {json.dumps(global_labels)}, 
                    egress: {json.dumps(global_egress)}, 
                    sql: {json.dumps(global_sql)},
                    reqs: {json.dumps(global_reqs)}
                }};
                const HOURLY_DB = {json.dumps(hourly_db)};
                const HOURLY_EVENTS = {json.dumps(hourly_events_db)};
                let TABLE_DATA = {json.dumps(endpoints_table_data)}; // Raw data for sorting

                // STATE
                let sortState = {{ key: 'total_egress', dir: 'desc' }};
                
                // --- TABLE LOGIC ---
                function renderTable() {{
                    const tbody = document.getElementById('endpointsBody');
                    tbody.innerHTML = '';
                    
                    TABLE_DATA.forEach(row => {{
                        const tr = document.createElement('tr');
                        tr.className = 'clickable-row transition';
                        tr.onclick = () => openEndpointModal(row.path);
                        
                        // Formatting special fields
                        const sqlClass = row.avg_sql > 50 ? 'text-red-400 font-bold' : 'text-slate-400';
                        
                        tr.innerHTML = `
                            <td class="p-4 font-mono text-slate-300 truncate max-w-[300px]" title="${{row.path}}">${{row.clean_path}}</td>
                            <td class="p-4 text-center"><span class="${{row.risk_class}}">${{row.risk_text}}</span></td>
                            <td class="p-4 text-right font-mono ${{sqlClass}}">${{row.avg_sql}}</td>
                            <td class="p-4 text-right text-slate-500">${{row.hits}}</td>
                            <td class="p-4 text-right font-bold text-purple-400">${{row.total_egress}}</td>
                            <td class="p-4 text-right font-bold text-orange-400">${{row.p95_dur}}s</td>
                        `;
                        tbody.appendChild(tr);
                    }});
                    updateSortIcons();
                }}

                function sortTable(key) {{
                    // Toggle direction if clicking same header, else default to desc
                    if (sortState.key === key) {{
                        sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        sortState.key = key;
                        sortState.dir = 'desc'; // Default new sorts to descending (usually more useful)
                    }}

                    TABLE_DATA.sort((a, b) => {{
                        let valA = a[key];
                        let valB = b[key];
                        
                        // String comparison for paths
                        if (typeof valA === 'string') {{
                            valA = valA.toLowerCase(); valB = valB.toLowerCase();
                        }}

                        if (valA < valB) return sortState.dir === 'asc' ? -1 : 1;
                        if (valA > valB) return sortState.dir === 'asc' ? 1 : -1;
                        return 0;
                    }});

                    renderTable();
                }}

                function updateSortIcons() {{
                    // Clear all icons
                    document.querySelectorAll('.sort-icon').forEach(el => el.innerText = '');
                    // Set active icon
                    const activeIcon = document.getElementById('sort-' + sortState.key);
                    if (activeIcon) {{
                        activeIcon.innerText = sortState.dir === 'asc' ? '▲' : '▼';
                        activeIcon.parentElement.style.color = '#60a5fa'; // Blue Highlight
                    }}
                }}

                // Initial Render
                renderTable();


                // --- CHART LOGIC ---
                Chart.defaults.color = '#64748b'; Chart.defaults.font.family = 'Inter';
                let mainChartInstance = null; let modalChartInstance = null; let currentViewMode = 'ALL'; 

                function initMainChart(labels, egressData, sqlData, reqsData, isHourly) {{
                    const ctx = document.getElementById('mainChart').getContext('2d');
                    if (mainChartInstance) mainChartInstance.destroy();
                    mainChartInstance = new Chart(ctx, {{
                        type: 'bar',
                        data: {{
                            labels: labels,
                            datasets: [
                                {{ 
                                    label: 'Egress (MB)', 
                                    data: egressData, 
                                    backgroundColor: '#3b82f6', 
                                    borderRadius: 4, 
                                    yAxisID: 'y' 
                                }},
                                {{ 
                                    label: 'Total Requests', 
                                    data: reqsData, 
                                    type: 'line', 
                                    borderColor: '#a855f7', // Violet
                                    backgroundColor: 'rgba(168, 85, 247, 0.1)',
                                    fill: true,
                                    borderWidth: 2, 
                                    tension: 0.4, 
                                    pointRadius: isHourly ? 3 : 1, 
                                    yAxisID: 'y1' 
                                }},
                                {{ 
                                    label: 'SQL Queries', 
                                    data: sqlData, 
                                    type: 'line', 
                                    borderColor: '#10b981', // Vert
                                    borderWidth: 2, 
                                    borderDash: [5, 5], // Pointillés pour différencier
                                    tension: 0.4, 
                                    pointRadius: isHourly ? 4 : 2, 
                                    yAxisID: 'y1' 
                                }}
                            ]
                        }},
                        options: {{
                            responsive: true, maintainAspectRatio: false,
                            interaction: {{ mode: 'index', intersect: false }},
                            onClick: (e, activeEls) => {{
                                if(activeEls.length === 0) return;
                                const idx = activeEls[0].index; const label = labels[idx];
                                if(currentViewMode === 'ALL') {{ document.getElementById('dateFilter').value = label; applyFilter(label); }} 
                                else {{ const rawHour = HOURLY_DB[currentViewMode].raw_hours[idx]; openSessionModal(currentViewMode, rawHour); }}
                            }},
                            scales: {{ 
                                x: {{ grid: {{ display: false }} }}, 
                                y: {{ 
                                    type: 'linear', display: true, position: 'left', 
                                    title: {{ display: true, text: 'Data (MB)' }},
                                    grid: {{ color: '#1e293b' }} 
                                }}, 
                                y1: {{ 
                                    type: 'linear', display: true, position: 'right',
                                    title: {{ display: true, text: 'Count (Reqs & SQL)' }},
                                    grid: {{ display: false }} 
                                }} 
                            }}
                        }}
                    }});
                }}

                function applyFilter(val) {{
                    const titleEl = document.getElementById('chartTitle'); currentViewMode = val;
                    if (val === 'ALL') {{ 
                        titleEl.innerText = "Global Load Overview (Daily)"; 
                        initMainChart(GLOBAL_DATA.labels, GLOBAL_DATA.egress, GLOBAL_DATA.sql, GLOBAL_DATA.reqs, false); 
                    }} 
                    else if (HOURLY_DB[val]) {{ 
                        titleEl.innerHTML = `Hourly Analysis for <span class="text-blue-400">${{val}}</span>`; 
                        const hData = HOURLY_DB[val]; 
                        initMainChart(hData.labels, hData.egress, hData.sql, hData.reqs, true); 
                    }}
                }}
                document.getElementById('dateFilter').addEventListener('change', (e) => applyFilter(e.target.value));
                // Init with Global Data
                initMainChart(GLOBAL_DATA.labels, GLOBAL_DATA.egress, GLOBAL_DATA.sql, GLOBAL_DATA.reqs, false);

                // --- MODALS & UTILS ---
                const FLAG_CACHE = {{}};
                async function resolveFlag(ip, elementId) {{
                    if(FLAG_CACHE[ip]) {{ document.getElementById(elementId).innerText = FLAG_CACHE[ip]; return; }}
                    if(ip.startsWith('57.141.') || ip.startsWith('157.240.') || ip.startsWith('66.220.')) {{ updateFlag(ip, elementId, '🇺🇸'); return; }}
                    if(ip.startsWith('66.249.') || ip.startsWith('64.233.')) {{ updateFlag(ip, elementId, '🇺🇸'); return; }}
                    try {{
                        const response = await fetch(`http://ip-api.com/json/${{ip}}?fields=countryCode`);
                        if(response.ok) {{ const data = await response.json(); updateFlag(ip, elementId, getFlagEmoji(data.countryCode)); }} else {{ updateFlag(ip, elementId, '🌐'); }}
                    }} catch(e) {{ updateFlag(ip, elementId, '🌐'); }}
                }}
                function updateFlag(ip, elementId, flag) {{ FLAG_CACHE[ip] = flag; const el = document.getElementById(elementId); if(el) el.innerText = flag; }}
                function getFlagEmoji(countryCode) {{ if(!countryCode) return '🌐'; const codePoints = countryCode.toUpperCase().split('').map(char =>  127397 + char.charCodeAt()); return String.fromCodePoint(...codePoints); }}

                function openSessionModal(date, hour) {{
                    const container = document.getElementById('sessionContent');
                    const title = document.getElementById('sessionTitle');
                    container.innerHTML = '';
                    title.innerHTML = `Analyses IP du <span class="text-blue-400">${{date}}</span> à <span class="text-blue-400">${{hour}}h</span>`;
                    const events = (HOURLY_EVENTS[date] && HOURLY_EVENTS[date][hour]) ? HOURLY_EVENTS[date][hour] : [];
                    if (events.length === 0) {{ container.innerHTML = '<div class="p-6 text-center text-slate-500">Aucune donnée.</div>'; document.getElementById('sessionModal').classList.add('show'); return; }}
                    
                    const ipClusters = {{}};
                    events.forEach(ev => {{
                        if(!ipClusters[ev.ip]) ipClusters[ev.ip] = {{ count: 0, sql_sum: 0, type: ev.type, paths: new Set(), events: [] }};
                        const c = ipClusters[ev.ip]; c.count++; c.sql_sum += ev.sql; c.paths.add(ev.path); c.events.push(ev);
                    }});
                    const sortedIps = Object.keys(ipClusters).sort((a,b) => ipClusters[b].count - ipClusters[a].count);

                    sortedIps.forEach((ip, index) => {{
                        const data = ipClusters[ip];
                        const avgSql = (data.sql_sum / data.count).toFixed(1);
                        const cardId = 'ip-' + ip.replace(/[\.:]/g, '-');
                        const flagId = 'flag-' + ip.replace(/[\.:]/g, '-');
                        let badgeColor = 'bg-slate-700 text-slate-300';
                        if(ip.startsWith('57.141.') || ip.startsWith('66.220.')) badgeColor = 'bg-blue-600 text-white'; 
                        
                        const html = `
                        <div class="glass-panel rounded-lg border border-slate-700 overflow-hidden mb-2">
                            <div onclick="toggleIp('${{cardId}}')" class="p-3 bg-slate-800/80 flex justify-between items-center cursor-pointer hover:bg-slate-800 transition">
                                <div class="flex items-center gap-3">
                                    <span id="${{flagId}}" class="flag-icon" title="Resolving...">⏳</span>
                                    <span class="font-mono font-bold text-lg text-white">${{ip}}</span>
                                    <span class="text-xs px-2 py-0.5 rounded ${{badgeColor}}">Hits: ${{data.count}}</span>
                                    <span class="text-xs text-slate-500">${{data.type}}</span>
                                </div>
                                <div class="flex gap-4 text-sm text-slate-400">
                                    <span>Avg SQL: <span class="${{avgSql > 30 ? 'text-red-400 font-bold' : 'text-blue-300'}}">${{avgSql}}</span></span>
                                    <span>Paths: ${{data.paths.size}}</span>
                                    <span>▼</span>
                                </div>
                            </div>
                            <div id="${{cardId}}" class="ip-details bg-slate-900/50">
                                <table class="w-full text-left text-xs font-mono">
                                    <thead class="text-slate-500 border-b border-slate-700"><tr><th class="p-2 w-20">Time</th><th class="p-2 w-16 text-right">SQL</th><th class="p-2 w-16 text-right">Dur</th><th class="p-2">Path</th></tr></thead>
                                    <tbody class="divide-y divide-slate-800/50 text-slate-300">
                                        ${{data.events.map(ev => `<tr class="hover:bg-slate-800/30"><td class="p-2 text-slate-500">${{ev.time}}</td><td class="p-2 text-right">${{ev.sql}}</td><td class="p-2 text-right">${{ev.dur}}s</td><td class="p-2 truncate max-w-md">${{ev.path}}</td></tr>`).join('')}}
                                    </tbody>
                                </table>
                            </div>
                        </div>`;
                        container.innerHTML += html;
                        setTimeout(() => resolveFlag(ip, flagId), index * 50);
                    }});
                    document.getElementById('sessionModal').classList.add('show');
                }}

                function toggleIp(id) {{
                    const el = document.getElementById(id);
                    if(el.style.maxHeight) {{ el.style.maxHeight = null; el.classList.remove('open'); }} 
                    else {{ el.classList.add('open'); el.style.maxHeight = el.scrollHeight + "px"; }}
                }}
                
                function openEndpointModal(path) {{
                    const data = ENDPOINT_DETAILS[path]; if (!data) return;
                    document.getElementById('modalTitle').innerText = path;
                    document.getElementById('m_hits').innerText = data.meta.hits;
                    document.getElementById('m_sql').innerText = data.meta.avg_sql;
                    document.getElementById('m_mem').innerText = data.meta.max_mem + ' MB';
                    document.getElementById('m_rows').innerText = data.meta.avg_rows;
                    const ctx = document.getElementById('modalChart').getContext('2d');
                    if (modalChartInstance) modalChartInstance.destroy();
                    modalChartInstance = new Chart(ctx, {{ type: 'line', data: {{ labels: data.history.map(x => x.date), datasets: [ {{ label: 'Avg SQL', data: data.history.map(x => x.avg_sql), borderColor: '#f59e0b', backgroundColor: 'rgba(245, 158, 11, 0.1)', fill: true }} ] }}, options: {{ responsive: true, maintainAspectRatio: false }} }});
                    const reportContainer = document.getElementById('reportContainer'); reportContainer.innerHTML = '';
                    data.report.forEach(item => {{ let color = item.level === 'CRITICAL' ? 'border-red-500 bg-red-500/10' : 'border-green-500 bg-green-500/10'; reportContainer.innerHTML += `<div class="p-3 rounded border-l-4 ${{color}} text-sm mb-2"><div class="font-bold text-white">${{item.title}}</div></div>`; }});
                    document.getElementById('detailModal').classList.add('show');
                }}
                function closeModal(id) {{ document.getElementById(id).classList.remove('show'); }}
                window.onclick = function(event) {{ if (event.target.classList.contains('modal-backdrop')) {{ event.target.classList.remove('show'); }} }}
            </script>
        </body>
        </html>
        """
        
        with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\n🚀 Fichier généré : {os.path.abspath(OUTPUT_FILENAME)}")

# --- SERVER UTILS ---
class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Servir le dashboard à la racine
        if self.path == '/':
            self.path = OUTPUT_FILENAME
        return super().do_GET()

    def log_message(self, format, *args):
        # Silence logs
        pass

def start_server_and_open():
    port = 8000
    while True:
        try:
            # S'assurer que le socket est bien fermé/réutilisable
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                break # Port est libre
        except OSError:
            port += 1
    
    url = f"http://localhost:{port}"
    print(f"\n🌐 SERVEUR WEB ACTIF")
    print(f"👉 Dashboard accessible ici : \033[94m{url}\033[0m")
    print(f"   (CTRL+C pour arrêter)")

    # Thread séparé pour ouvrir le navigateur sans bloquer le démarrage du serveur
    def open_browser():
        time.sleep(1)
        try: webbrowser.open(url)
        except: pass
    
    Thread(target=open_browser).start()

    with TCPServer(("", port), CustomHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Serveur arrêté.")

if __name__ == "__main__":
    monitor = EnterpriseMonitor()
    files = monitor.fetch_logs()
    
    if files:
        monitor.parse_logs(files)
        monitor.generate_html()
        start_server_and_open()
    else:
        print("❌ Aucune donnée de logs disponible. Vérifiez vos chemins ou la connexion SSH.")