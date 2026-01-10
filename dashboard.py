import streamlit as st
import pandas as pd
import paramiko
import os
import re
import json
import plotly.graph_objects as go
from io import StringIO
from datetime import datetime
from dotenv import load_dotenv

# --- CONFIGURATION ---
st.set_page_config(page_title="Mission Control - Performance", layout="wide", page_icon="🚀")

try:
    load_dotenv()
except ImportError:
    pass

# Récupération des secrets (soit via .env, soit via l'interface si vide)
PA_HOST = os.getenv("PA_HOST", "ssh.pythonanywhere.com")
PA_USER = os.getenv("PA_USER", "Cicaw")
PA_PASSWORD = os.getenv("PA_PASSWORD", "")  # Mettre le mdp ici ou dans .env

REMOTE_DIR = "/home/Cicaw/cicaw_project"
LOG_FILES = [
    f"{REMOTE_DIR}/persistent_logs/db_traffic_v18.log",
    f"{REMOTE_DIR}/persistent_logs/cmd_traffic_v3.log"
]
NPLUS1_DIR = f"{REMOTE_DIR}/debug_nplus1"

# --- 1. FONCTIONS BACKEND (SSH & PARSING) ---

@st.cache_data(ttl=60)  # Cache les données pour 60 secondes pour éviter de spammer le SSH
def fetch_data_from_pa(host, user, password):
    """Se connecte via SSH, télécharge les logs et les JSON N+1."""
    logs_content = []
    nplus1_files = []
    
    status_text = st.empty()
    status_text.text("🔌 Connexion à PythonAnywhere...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=password)
        sftp = ssh.open_sftp()

        # 1. Récupérer les Logs
        for log_path in LOG_FILES:
            try:
                status_text.text(f"📥 Téléchargement de {os.path.basename(log_path)}...")
                with sftp.open(log_path, 'r') as f:
                    content = f.read().decode('utf-8')
                    # On ajoute une étiquette source pour savoir d'où ça vient
                    source_tag = "CMD" if "cmd" in log_path else "WEB"
                    logs_content.append((source_tag, content))
            except FileNotFoundError:
                st.warning(f"Fichier non trouvé: {log_path}")

        # 2. Récupérer les fichiers N+1 (JSON)
        try:
            status_text.text("🕵️ Recherche des rapports N+1...")
            files = sftp.listdir(NPLUS1_DIR)
            json_files = [f for f in files if f.endswith('.json')]
            
            for jf in json_files:
                with sftp.open(f"{NPLUS1_DIR}/{jf}", 'r') as f:
                    data = json.load(f)
                    nplus1_files.append(data)
        except FileNotFoundError:
            pass # Le dossier n'existe peut-être pas encore

        sftp.close()
        ssh.close()
        status_text.empty()
        return logs_content, nplus1_files

    except Exception as e:
        status_text.error(f"Erreur de connexion : {e}")
        return [], []

def parse_logs(logs_raw_data):
    """Transforme les logs bruts texte en DataFrame Pandas structuré."""
    data = []
    
    # Regex pour extraire les valeurs clés (basé sur ton format de log)
    # Format attendu dans le message: IP: ... | Path: ... | CPU: ... | etc.
    # Note: On suppose que le log commence par un timestamp standard logging ou on le simule
    
    for source, content in logs_raw_data:
        lines = content.split('\n')
        for line in lines:
            if not line.strip():
                continue
            
            # Parsing "doigt mouillé" robuste
            try:
                entry = {'Source': source, 'Raw': line}
                
                # Extraction basique des valeurs via split '|'
                # On nettoie la partie logging standard (INFO:root:...) si présente
                if "IP:" in line:
                    parts = line.split('|')
                    for part in parts:
                        p = part.strip()
                        if "IP:" in p: entry['IP'] = p.split('IP:')[1].strip()
                        if "Path:" in p: entry['Path'] = p.split('Path:')[1].strip()
                        if "CPU:" in p: entry['CPU (ms)'] = float(re.findall(r"[\d\.]+", p)[0])
                        if "RAM Δ:" in p: entry['RAM Delta (KB)'] = float(re.findall(r"[-?\d\.]+", p)[0]) # peut être négatif
                        if "RAM Peak:" in p: entry['RAM Peak (KB)'] = float(re.findall(r"[\d\.]+", p)[0])
                        if "DB Q:" in p or "Queries:" in p: entry['Queries'] = int(re.findall(r"\d+", p)[0])
                        if "Rows:" in p: entry['Rows'] = int(re.findall(r"\d+", p)[0])
                    
                    # Simuler un timestamp (ou l'extraire si le formatter logging l'ajoute au début de ligne)
                    # Ici on prend juste l'ordre d'arrivée pour la démo, ou on parse s'il y a une date
                    # Idéalement configure ton logging pour mettre %(asctime)s
                    match_date = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
                    if match_date:
                        entry['Time'] = datetime.strptime(match_date.group(), '%Y-%m-%d %H:%M:%S')
                    else:
                        # Fallback: on utilise l'index
                        entry['Time'] = datetime.now() 

                    data.append(entry)
            except Exception:
                continue # Ignore les lignes mal formées

    df = pd.DataFrame(data)
    if not df.empty and 'Time' in df.columns:
        df = df.sort_values(by='Time', ascending=False).reset_index(drop=True)
    return df

# --- 2. RECUPERATION DONNEES ---

if not PA_PASSWORD:
    st.error("⚠️ Mot de passe SSH manquant. Vérifiez vos variables d'environnement.")
    st.stop()

raw_logs, nplus1_data = fetch_data_from_pa(PA_HOST, PA_USER, PA_PASSWORD)
df = parse_logs(raw_logs)

if df.empty:
    st.warning("Aucune donnée de log trouvée ou format incompatible.")
    st.stop()

# --- 3. INTERFACE VISUELLE ---

st.title("🛰️ Mission Control Center")
st.caption(f"Connected to {PA_HOST} | User: {PA_USER}")

# --- ZONE 1: BARRE DE SANTE (KPIs) ---
st.subheader("1. État du Système (Live)")

kpi1, kpi2, kpi3, kpi4 = st.columns(4)

# Calculs
avg_cpu = df['CPU (ms)'].mean()
max_ram = df['RAM Peak (KB)'].max() / 1024 # En MB
avg_queries = df['Queries'].mean()
total_req = len(df)

kpi1.metric("Requêtes Analysées", f"{total_req}", delta="Log count")
kpi2.metric("Temps CPU Moyen", f"{avg_cpu:.1f} ms", delta_color="inverse")
kpi3.metric("Max RAM Peak", f"{max_ram:.2f} MB", delta="Attention" if max_ram > 100 else "Normal", delta_color="inverse")
kpi4.metric("Moy. SQL / Req", f"{avg_queries:.1f}", delta="> 20 est élevé" if avg_queries > 20 else "Ok", delta_color="inverse")

st.divider()

# --- ZONE 2: GRAPHIQUES DE TENDANCES ---
st.subheader("2. Analyse Temporelle")

col_chart1, col_chart2 = st.columns(2)

# Graphique A : Ressources (CPU vs RAM)
with col_chart1:
    st.markdown("**Resource Usage (CPU vs RAM)**")
    # Utilisation de l'index inversé comme axe temps si pas de timestamp précis, sinon Time
    chart_data = df[['CPU (ms)', 'RAM Peak (KB)']].copy()
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(y=chart_data['CPU (ms)'], name='CPU (ms)', line=dict(color='cyan')))
    fig.add_trace(go.Scatter(y=chart_data['RAM Peak (KB)'], name='RAM (KB)', line=dict(color='purple'), yaxis='y2'))
    
    fig.update_layout(
        yaxis=dict(title='CPU (ms)'),
        yaxis2=dict(title='RAM (KB)', overlaying='y', side='right'),
        margin=dict(l=0, r=0, t=30, b=0),
        height=300
    )
    st.plotly_chart(fig, use_container_width=True)

# Graphique B : Traffic DB
with col_chart2:
    st.markdown("**Database Traffic (Queries per Request)**")
    chart_db = df[['Queries']].copy()
    
    # Couleurs conditionnelles pour le bar chart
    colors = ['green' if x < 20 else 'orange' if x < 50 else 'red' for x in chart_db['Queries']]
    
    fig2 = go.Figure()
    fig2.add_trace(go.Bar(y=chart_db['Queries'], marker_color=colors, name='Queries'))
    fig2.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
    st.plotly_chart(fig2, use_container_width=True)

st.divider()

# --- ZONE 3 & 4 : LIVE LOGS & N+1 HUNTER ---

col_logs, col_sidebar = st.columns([3, 1])

with col_logs:
    st.subheader("3. Live Log Monitor")
    
    # Filtrage
    search = st.text_input("🔍 Filtrer par Path ou IP", "")
    if search:
        display_df = df[df['Path'].str.contains(search, na=False) | df['IP'].str.contains(search, na=False)]
    else:
        display_df = df

    # Fonction de styling pour le tableau
    def style_dataframe(row):
        styles = [''] * len(row)
        # Index des colonnes (à adapter selon le df final)
        try:
            q_idx = row.index.get_loc('Queries')
            ram_idx = row.index.get_loc('RAM Peak (KB)')
            
            if row['Queries'] > 50:
                styles[q_idx] = 'background-color: #ffcccc; color: red; font-weight: bold' # Rouge clair
            elif row['Queries'] > 20:
                styles[q_idx] = 'color: orange'
            
            if row['RAM Peak (KB)'] > 50000: # 50MB
                styles[ram_idx] = 'background-color: #ffe6cc; color: darkred'
        except:
            pass
        return styles

    # Affichage du tableau
    st.dataframe(
        display_df[['Source', 'IP', 'Path', 'CPU (ms)', 'RAM Peak (KB)', 'Queries', 'Rows']],
        use_container_width=True,
        height=500,
        # Note: Streamlit supporte le styling pandas limité, sinon on utilise column_config pour des barres
        column_config={
            "Queries": st.column_config.ProgressColumn(
                "DB Queries",
                help="Nombre de requêtes SQL",
                format="%d",
                min_value=0,
                max_value=100, # Echelle arbitraire pour la barre visuelle
            ),
            "RAM Peak (KB)": st.column_config.NumberColumn(
                "RAM Peak",
                format="%.1f KB"
            )
        }
    )

with col_sidebar:
    st.subheader("4. N+1 Hunter 🕵️")
    st.markdown("---")
    
    if not nplus1_data:
        st.success("Aucun problème N+1 détecté récemment.")
    else:
        for report in nplus1_data:
            with st.expander(f"🚨 {report.get('command', 'Unknown')} ({report.get('issues_found', 0)})"):
                st.caption(f"Date: {report.get('timestamp')}")
                st.write(f"**Total Queries:** {report.get('total_queries')}")
                st.write(f"**Exec Time:** {report.get('execution_time_ms'):.2f}ms")
                
                details = report.get('details', [])
                for issue in details:
                    st.error(f"SQL répété {issue['count']} fois !")
                    st.code(issue['sql'], language="sql")
                    if 'stack' in issue and issue['stack']:
                        st.markdown("**Origine:**")
                        st.text(issue['stack'][-1]) # Affiche la dernière ligne de la stack

# Bouton de rafraîchissement manuel
if st.button("Rafraîchir les données"):
    st.cache_data.clear()
    st.rerun()