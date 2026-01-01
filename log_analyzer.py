#!/usr/bin/env python3
import re
import argparse
import sys
import os
from collections import defaultdict

# --- SEUILS D'ANOMALIE (Modifiables) ---
THRESHOLD_SQL_PER_HIT = 30    # Alerte si + de 30 requêtes SQL pour un seul appel
THRESHOLD_ROWS_PER_HIT = 100   # Alerte si + de 100 lignes extraites pour un seul appel
THRESHOLD_MB_PER_HIT = 0.5     # Alerte si + de 0.5 MB pour un seul appel
THRESHOLD_IP_TRAFFIC_PCT = 20  # Alerte si une IP fait + de 20% du trafic total

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BG_RED = '\033[41m'

LOG_PATTERN = re.compile(
    r"^INFO\s+(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"IP:\s+(?P<ip>[\d\.]+)\s+\|\s+"
    r"Path:\s+(?P<path>.*?)\s+\|\s+"
    r"Queries:\s+(?P<queries>\d+)\s+\|\s+"
    r"Rows:\s+(?P<rows>\d+)\s+\|\s+"
    r"Est\. Size:\s+(?P<size>[\d\.]+)\s+KB"
)

def get_ip_range(ip):
    parts = ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else ip

def print_table(title, headers, data, col_widths, color=Colors.CYAN):
    print(f"\n{color}{Colors.BOLD}>>> {title} <<<{Colors.ENDC}")
    header_str = " | ".join([f"{h:<{w}}" for h, w in zip(headers, col_widths)])
    print(header_str)
    print("-+-".join(["-" * w for w in col_widths]))
    for row in data:
        print(" | ".join([f"{str(item):<{w}}" for item, w in zip(row, col_widths)]))

def analyze_logs(filepath):
    if not os.path.exists(filepath):
        print(f"{Colors.RED}Fichier introuvable.{Colors.ENDC}")
        sys.exit(1)

    # Initialisation
    stats = {
        'global': {'reqs': 0, 'mb': 0.0, 'rows': 0, 'queries': 0, 'errors': 0},
        'daily': defaultdict(lambda: {'reqs': 0, 'mb': 0.0, 'rows': 0}),
        'paths': defaultdict(lambda: {'reqs': 0, 'rows': 0, 'mb': 0.0, 'queries': 0}),
        'ips': defaultdict(lambda: {'reqs': 0, 'rows': 0, 'mb': 0.0}),
        'ranges': defaultdict(lambda: {'reqs': 0, 'ips': set()})
    }
    
    anomalies = []

    with open(filepath, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            match = LOG_PATTERN.search(line.strip())
            if not match:
                if line.strip(): stats['global']['errors'] += 1
                continue

            d = match.groupdict()
            req_queries = int(d['queries'])
            req_rows = int(d['rows'])
            req_mb = float(d['size']) / 1024.0
            path = d['path'].strip()
            ip = d['ip']
            date = d['date']

            # Détection immédiate d'anomalies par requête
            if req_queries > THRESHOLD_SQL_PER_HIT:
                anomalies.append(f"Ligne {line_num}: SQL excessif ({req_queries} q) sur {path}")
            if req_rows > THRESHOLD_ROWS_PER_HIT:
                anomalies.append(f"Ligne {line_num}: Volume Rows élevé ({req_rows} r) sur {path}")

            # Accumulation
            stats['global']['reqs'] += 1
            stats['global']['mb'] += req_mb
            stats['global']['rows'] += req_rows
            stats['global']['queries'] += req_queries

            stats['daily'][date]['reqs'] += 1
            stats['daily'][date]['mb'] += req_mb
            stats['daily'][date]['rows'] += req_rows

            stats['paths'][path]['reqs'] += 1
            stats['paths'][path]['rows'] += req_rows
            stats['paths'][path]['mb'] += req_mb
            stats['paths'][path]['queries'] += req_queries

            stats['ips'][ip]['reqs'] += 1
            stats['ips'][ip]['rows'] += req_rows
            stats['ips'][ip]['mb'] += req_mb
            
            stats['ranges'][get_ip_range(ip)]['reqs'] += 1
            stats['ranges'][get_ip_range(ip)]['ips'].add(ip)

    # --- CALCUL DES INDICATEURS D'ANOMALIE ---
    
    # 1. Analyse des IPs suspectes (DDoS ou Scraping)
    total_reqs = stats['global']['reqs']
    for ip, data in stats['ips'].items():
        pct = (data['reqs'] / total_reqs) * 100 if total_reqs > 0 else 0
        if pct > THRESHOLD_IP_TRAFFIC_PCT:
            anomalies.append(f"IP SUSPECTE: {ip} génère {pct:.1f}% du trafic total")

    # 2. Analyse de l'efficacité des Paths (N+1 queries ou manque d'index)
    path_inefficiency = []
    for path, data in stats['paths'].items():
        avg_q = data['queries'] / data['reqs']
        avg_r = data['rows'] / data['reqs']
        if avg_q > THRESHOLD_SQL_PER_HIT or avg_r > THRESHOLD_ROWS_PER_HIT:
            path_inefficiency.append((path, f"{avg_q:.1f}", f"{avg_r:.1f}"))

    # --- AFFICHAGE ---

    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*50}")
    print(f"      SUPER-ANALYSEUR DE TRAFIC & ANOMALIES")
    print(f"{'='*50}{Colors.ENDC}")

    # Section Anomalies (EN ROUGE SI PRÉSENTES)
    if anomalies or path_inefficiency:
        print(f"\n{Colors.BG_RED}{Colors.BOLD} ⚠️  ALERTES & ANOMALIES DÉTECTÉES ({len(anomalies)}) {Colors.ENDC}")
        for alert in anomalies[:10]: # Limiter à 10 alertes
            print(f" {Colors.RED}• {alert}{Colors.ENDC}")
        if len(anomalies) > 10: print(f" ... et {len(anomalies)-10} autres alertes.")
        
        if path_inefficiency:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}Paths Inefficaces (Moyenne par Hit) :{Colors.ENDC}")
            for p, q, r in path_inefficiency[:5]:
                print(f" - {p[:50]}... -> {q} SQL/hit | {r} Rows/hit")

    # Résumé Global
    g = stats['global']
    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] RÉSUMÉ GLOBAL :{Colors.ENDC}")
    print(f" • Requêtes: {g['reqs']:,} | Volume: {g['mb']:.2f} MB")
    print(f" • SQL total: {g['queries']:,} | Rows total: {g['rows']:,}")
    print(f" • IPs Uniques: {len(stats['ips'])} | Erreurs format: {g['errors']}")

    # Tableaux
    print_table("STATISTIQUES JOURNALIÈRES", ["Date", "Requêtes", "Volume (MB)", "Rows"], 
                [(d, s['reqs'], f"{s['mb']:.2f}", s['rows']) for d, s in sorted(stats['daily'].items())], [12, 10, 12, 10])

    top_ips = sorted(stats['ips'].items(), key=lambda x: x[1]['reqs'], reverse=True)[:15]
    print_table("TOP 15 ADRESSES IP (ACTIVITÉ)", ["IP Address", "Hits", "Rows", "MB"], 
                [(ip, s['reqs'], s['rows'], f"{s['mb']:.2f}") for ip, s in top_ips], [18, 8, 10, 10])

    top_paths_mb = sorted(stats['paths'].items(), key=lambda x: x[1]['mb'], reverse=True)[:15]
    print_table("TOP 15 PATHS PAR POIDS (MB)", ["Path", "Total MB", "Hits", "SQL/Hit"], 
                [(p[:55], f"{s['mb']:.2f}", s['reqs'], f"{s['queries']/s['reqs']:.1f}") for p, s in top_paths_mb], [55, 10, 8, 8])

    top_paths_rows = sorted(stats['paths'].items(), key=lambda x: x[1]['rows'], reverse=True)[:15]
    print_table("TOP 15 PATHS PAR CHARGE BDD (ROWS)", ["Path", "Total Rows", "Hits", "Rows/Hit"], 
                [(p[:55], s['rows'], s['reqs'], f"{s['rows']/s['reqs']:.1f}") for p, s in top_paths_rows], [55, 10, 8, 8])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    args = parser.parse_args()
    analyze_logs(args.logfile)