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

# --- MODULE IA (Gestion d'erreur si non installé) ---
try:
    from sklearn.linear_model import LinearRegression
    import numpy as np
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("⚠️ Scikit-Learn/Numpy non trouvés. Le module de prédiction IA sera désactivé.")
    print("👉 Installez-les via: pip install scikit-learn numpy")

# --- CONFIGURATION ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

PA_HOST = os.getenv("PA_HOST", "ssh.pythonanywhere.com")
PA_USER = os.getenv("PA_USER", "Cicaw")
PA_PASSWORD = os.getenv("PA_PASSWORD", "") 

REMOTE_LOGS = [
    "/home/Cicaw/cicaw_project/persistent_logs/db_traffic_v15.log",
]

# --- REGEX AJUSTÉE POUR TES LOGS ---
# Match: INFO 2025-12-29 04:15:05,696 middleware IP: ...
LOG_PATTERN = re.compile(
    r"^INFO\s+(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+middleware\s+"
    r"IP:\s+(?P<ip>[\d\.]+)\s+\|\s+"
    r"Path:\s+(?P<path>.*?)\s+\|\s+"
    r"Queries:\s+(?P<queries>\d+)\s+\|\s+"
    r"Rows:\s+(?P<rows>\d+)\s+\|\s+"
    r"Est\. Size:\s+(?P<size>[\d\.]+)\s+KB"
)

OUTPUT_FILENAME = "dashboard_omniview_v2_1.html"
LOCAL_LOG_DIR = "logs_buffer"

class EnterpriseMonitor:
    def __init__(self):
        self.stats = {
            'overview': {
                'total_reqs': 0, 'total_sql': 0, 'total_egress_kb': 0,
                'unique_ips': set()
            },
            'daily': defaultdict(lambda: {
                'reqs': 0, 'sql': 0, 'egress_kb': 0, 
                'ips': set()
            }),
            'hourly': defaultdict(lambda: defaultdict(lambda: {
                'reqs': 0, 'sql': 0, 'egress_kb': 0
            })),
            'endpoints': defaultdict(lambda: {
                'hits': 0, 
                'sql': [], 
                'rows': [], 
                'size_kb': []
            })
        }

    def fetch_logs(self):
        local_files = []
        if not os.path.exists(LOCAL_LOG_DIR):
            os.makedirs(LOCAL_LOG_DIR)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"🔄 Connexion SSH à {PA_HOST}...")
            
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
                    print(f"✅ Téléchargé : {remote}")
                except Exception as e:
                    print(f"⚠️ Erreur fichier {remote}: {e}")
            
            sftp.close()
            client.close()
        except Exception as e:
            print(f"⚠️ Mode Offline (Erreur SSH): {e}")
            for remote in REMOTE_LOGS:
                local_name = os.path.join(LOCAL_LOG_DIR, os.path.basename(remote))
                if os.path.exists(local_name):
                    local_files.append(local_name)
        
        return local_files

    def clean_path(self, path):
        """
        ROBUSTESSE : Regroupe les URLs similaires.
        Ex: /details/3598/produit-xyz -> /details/{id}/produit-xyz
        """
        path = path.strip()
        
        # Ignorer les assets statiques et fichiers well-known pour ne pas polluer
        if path.startswith('/.well-known'): return "System: Well-Known"
        
        # Remplacement UUID
        path = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '{uuid}', path)
        
        # Remplacement ID numérique spécifique à ton URL structure (/details/1234/...)
        path = re.sub(r'/details/\d+/', '/details/{id}/', path)
        path = re.sub(r'/api/products/\d+/', '/api/products/{id}/', path)
        
        # Remplacement générique ID en fin d'URL
        path = re.sub(r'/\d+$', '/{id}', path)
        
        if '?' in path:
            path = path.split('?')[0]
            
        return path

    def parse_logs(self, files):
        print("📊 Analyse et Clustering des données...")
        for file_path in files:
            if "cmd" in os.path.basename(file_path).lower():
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = LOG_PATTERN.search(line)
                        if not match: continue

                        d = match.groupdict()
                        path_raw = d['path'].strip()

                        queries = int(d['queries'])
                        rows = int(d['rows'])
                        size = float(d['size'])
                        date = d['date']
                        time_str = d['time']
                        hour = time_str.split(':')[0] 
                        ip = d['ip']

                        clean_path = self.clean_path(path_raw)

                        # Overview
                        self.stats['overview']['total_reqs'] += 1
                        self.stats['overview']['total_sql'] += queries
                        self.stats['overview']['total_egress_kb'] += size
                        self.stats['overview']['unique_ips'].add(ip)

                        # Daily
                        day = self.stats['daily'][date]
                        day['reqs'] += 1
                        day['sql'] += queries
                        day['egress_kb'] += size
                        day['ips'].add(ip)

                        # Hourly Stats
                        h_stats = self.stats['hourly'][date][hour]
                        h_stats['reqs'] += 1
                        h_stats['sql'] += queries
                        h_stats['egress_kb'] += size

                        # Endpoints Aggregation
                        ep = self.stats['endpoints'][clean_path]
                        ep['hits'] += 1
                        ep['sql'].append(queries)
                        # On limite le stockage pour la RAM
                        if len(ep['rows']) < 5000: 
                            ep['rows'].append(rows)
                            ep['size_kb'].append(size)

            except Exception as e:
                print(f"❌ Erreur lecture fichier {file_path}: {e}")

    def predict_sql_load(self, target_visitors=1000):
        if not HAS_SKLEARN: return None
        X_train, y_train = [], []

        for date, hours in self.stats['hourly'].items():
            for hour, data in hours.items():
                if data['reqs'] > 5: # Filtre bruit
                    X_train.append(data['reqs'])
                    y_train.append(data['sql'])

        if len(X_train) < 5:
            return {"error": "Pas assez de données (< 5 heures)"}

        try:
            X = np.array(X_train).reshape(-1, 1)
            y = np.array(y_train)
            model = LinearRegression()
            model.fit(X, y)
            
            predicted_sql = model.predict([[target_visitors]])[0]
            r2_score = model.score(X, y) * 100
            
            return {
                "target": target_visitors,
                "prediction": int(predicted_sql) if predicted_sql > 0 else 0,
                "cost_per_req": round(model.coef_[0], 2),
                "confidence": round(r2_score, 1)
            }
        except Exception as e:
            return {"error": f"Erreur math: {e}"}

    def generate_html(self):
        s = self.stats
        dates = sorted(s['daily'].keys())
        global_labels = dates
        global_sql = [s['daily'][d]['sql'] for d in dates]
        global_reqs = [s['daily'][d]['reqs'] for d in dates]

        ai_data = self.predict_sql_load(1000)

        endpoints_table_data = []
        for path, data in s['endpoints'].items():
            if data['hits'] == 0: continue
            
            avg_sql = statistics.mean(data['sql']) if data['sql'] else 0
            avg_rows = statistics.mean(data['rows']) if data['rows'] else 0
            total_egress_mb = sum(data['size_kb']) / 1024 if data['size_kb'] else 0
            
            risk_score = 0
            if avg_sql > 50: risk_score += 3
            elif avg_sql > 15: risk_score += 1
            if avg_rows > 100: risk_score += 1 # Remplacé Duration par Rows car Duration indisponible

            endpoints_table_data.append({
                'path': path,
                'hits': data['hits'],
                'avg_sql': round(avg_sql, 1),
                'avg_rows': round(avg_rows, 0),
                'egress_mb': round(total_egress_mb, 2),
                'risk': risk_score
            })

        endpoints_table_data.sort(key=lambda x: x['avg_sql'] * x['hits'], reverse=True)
        endpoints_table_data = endpoints_table_data[:300]

        html_content = f"""
        <!DOCTYPE html>
        <html lang="fr" class="dark">
        <head>
            <meta charset="UTF-8">
            <title>OmniView v2.1 - SQL Analytics</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ background-color: #0f172a; font-family: system-ui, sans-serif; color: #cbd5e1; }}
                .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; }}
                .metric-label {{ font-size: 0.75rem; text-transform: uppercase; color: #64748b; }}
                .metric-val {{ font-size: 1.5rem; font-weight: 700; color: #f1f5f9; }}
                .table-th {{ text-align: left; padding: 0.75rem; font-size: 0.75rem; color: #94a3b8; border-bottom: 1px solid #334155; }}
                .table-td {{ padding: 0.75rem; border-bottom: 1px solid #1e293b; font-family: monospace; font-size: 0.85rem; }}
                tr:hover td {{ background-color: #334155; }}
            </style>
        </head>
        <body class="p-6 max-w-7xl mx-auto space-y-6">
            
            <div class="flex justify-between items-center">
                <h1 class="text-3xl font-bold text-white">Cicaw <span class="text-blue-500">OmniView</span> v2.1</h1>
                <span class="text-xs bg-slate-700 text-slate-300 px-2 rounded">Log Format: Custom (No Duration)</span>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="card p-4">
                    <div class="metric-label">Total Requêtes</div>
                    <div class="metric-val">{s['overview']['total_reqs']:,}</div>
                </div>
                <div class="card p-4">
                    <div class="metric-label">Total SQL Queries</div>
                    <div class="metric-val text-blue-400">{s['overview']['total_sql']:,}</div>
                </div>
                <div class="card p-4">
                    <div class="metric-label">Bandwidth (KB)</div>
                    <div class="metric-val text-purple-400">{int(s['overview']['total_egress_kb']):,}</div>
                </div>
                <div class="card p-4">
                    <div class="metric-label">Unique IPs</div>
                    <div class="metric-val text-yellow-400">{len(s['overview']['unique_ips'])}</div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="card p-6 lg:col-span-2">
                    <h3 class="font-bold text-white mb-4">Activité SQL Quotidienne</h3>
                    <div class="h-64"><canvas id="mainChart"></canvas></div>
                </div>

                <div class="card p-6 border-l-4 border-blue-500 bg-slate-800/50">
                    <h3 class="font-bold text-white mb-2">🔮 Prédiction Charge (IA)</h3>
                    {self._render_prediction_html(ai_data)}
                </div>
            </div>

            <div class="card overflow-hidden">
                <div class="p-4 bg-slate-800/50 border-b border-slate-700">
                    <h3 class="font-bold text-white">Top Endpoints (Par impact SQL)</h3>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr>
                                <th class="table-th">Path (Clustered)</th>
                                <th class="table-th text-right">Avg SQL</th>
                                <th class="table-th text-right">Avg Rows</th>
                                <th class="table-th text-right">Hits</th>
                                <th class="table-th text-center">Status</th>
                            </tr>
                        </thead>
                        <tbody class="text-slate-300">
                            {''.join([self._render_row(row) for row in endpoints_table_data])}
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
                const ctx = document.getElementById('mainChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'line',
                    data: {{
                        labels: {json.dumps(global_labels)},
                        datasets: [
                            {{
                                label: 'Requêtes Web',
                                data: {json.dumps(global_reqs)},
                                borderColor: '#3b82f6',
                                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                fill: true,
                                tension: 0.4,
                                yAxisID: 'y'
                            }},
                            {{
                                label: 'Requêtes SQL',
                                data: {json.dumps(global_sql)},
                                borderColor: '#10b981',
                                borderDash: [5, 5],
                                tension: 0.4,
                                yAxisID: 'y1'
                            }}
                        ]
                    }},
                    options: {{
                        responsive: true, maintainAspectRatio: false,
                        interaction: {{ mode: 'index', intersect: false }},
                        scales: {{
                            y: {{ position: 'left', grid: {{ color: '#334155' }} }},
                            y1: {{ position: 'right', grid: {{ display: false }} }}
                        }}
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\n🚀 Dashboard généré : {os.path.abspath(OUTPUT_FILENAME)}")

    def _render_prediction_html(self, data):
        if not data: return '<p class="text-slate-500">IA inactive.</p>'
        if "error" in data: return f'<p class="text-red-400 text-sm">{data["error"]}</p>'
        
        return f"""
        <div class="space-y-4 mt-4">
            <div>
                <div class="text-xs text-slate-400">Simulation pour</div>
                <div class="text-2xl font-bold text-white">{data['target']:,} <span class="text-sm font-normal">visiteurs</span></div>
            </div>
            <div class="p-3 bg-slate-900 rounded border border-slate-700">
                <div class="text-xs text-slate-400">Charge SQL Estimée</div>
                <div class="text-xl font-bold text-blue-400">{data['prediction']:,} queries</div>
            </div>
            <div class="flex justify-between text-sm">
                <span class="text-slate-400">Coût SQL/Visite :</span>
                <span class="font-mono text-white font-bold">{data['cost_per_req']}</span>
            </div>
            <div class="flex justify-between text-sm">
                <span class="text-slate-400">Fiabilité Modèle :</span>
                <span class="font-bold { 'text-green-400' if data['confidence'] > 70 else 'text-orange-400' }">{data['confidence']}%</span>
            </div>
        </div>
        """

    def _render_row(self, row):
        sql_color = "text-slate-400"
        if row['avg_sql'] > 50: sql_color = "text-red-500 font-bold"
        elif row['avg_sql'] > 15: sql_color = "text-orange-400"

        badge = '<span class="px-2 py-0.5 rounded bg-green-900 text-green-300 text-[10px]">OK</span>'
        if row['risk'] >= 3: badge = '<span class="px-2 py-0.5 rounded bg-red-900 text-red-300 text-[10px]">LOURD</span>'
        elif row['risk'] >= 1: badge = '<span class="px-2 py-0.5 rounded bg-orange-900 text-orange-300 text-[10px]">MODÉRÉ</span>'

        return f"""
        <tr class="transition border-b border-slate-800/50">
            <td class="table-td text-white truncate max-w-[250px]" title="{row['path']}">{row['path']}</td>
            <td class="table-td text-right {sql_color}">{row['avg_sql']}</td>
            <td class="table-td text-right text-slate-500">{row['avg_rows']}</td>
            <td class="table-td text-right text-slate-500">{row['hits']}</td>
            <td class="table-td text-center">{badge}</td>
        </tr>
        """

# --- SERVEUR WEB ---
class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/': self.path = OUTPUT_FILENAME
        return super().do_GET()
    def log_message(self, format, *args): pass

def start_server():
    port = 8000
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                break 
        except OSError: port += 1
    
    url = f"http://localhost:{port}"
    print(f"\n🌐 Dashboard prêt : \033[94m{url}\033[0m")
    
    def open_browser():
        time.sleep(1)
        webbrowser.open(url)
    Thread(target=open_browser).start()

    with TCPServer(("", port), CustomHandler) as httpd:
        try: httpd.serve_forever()
        except KeyboardInterrupt: print("\n🛑 Arrêt.")

if __name__ == "__main__":
    monitor = EnterpriseMonitor()
    files = monitor.fetch_logs()
    
    if files:
        monitor.parse_logs(files)
        monitor.generate_html()
        start_server()
    else:
        print("❌ Echec : Aucun log disponible.")