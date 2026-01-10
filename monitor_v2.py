import streamlit as st
import pandas as pd
import paramiko
import os
import re
import numpy as np
import plotly.express as px
from datetime import datetime
from dotenv import load_dotenv
from sklearn.linear_model import LinearRegression

# --- CONFIGURATION ---
st.set_page_config(page_title="OmniView v3 - Full Metrics", layout="wide", page_icon="🧠")

try:
    load_dotenv()
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Variables d'environnement
PA_HOST = os.getenv("PA_HOST", "ssh.pythonanywhere.com")
PA_USER = os.getenv("PA_USER", "Cicaw")
PA_PASSWORD = os.getenv("PA_PASSWORD", "") 

# Liste des fichiers à analyser
REMOTE_LOGS = [
    "/home/Cicaw/cicaw_project/persistent_logs/db_traffic_v18.log",
    # "/home/Cicaw/cicaw_project/persistent_logs/cmd_traffic_v3.log"
]

# --- 1. MOTEUR DE PARSING ROBUSTE ---

def parse_log_line(line):
    """
    Parse une ligne du nouveau middleware format Pipe (|).
    """
    data = {}
    
    # 1. Extraction Timestamp
    ts_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
    if ts_match:
        data['timestamp'] = datetime.strptime(ts_match.group(1), '%Y-%m-%d %H:%M:%S')
    else:
        return None

    # 2. Découpage par Pipe '|'
    parts = line.split('|')
    
    for p in parts:
        p = p.strip() # Nettoyage des espaces
        try:
            # Parsing plus souple
            if "IP:" in p: 
                data['ip'] = p.split('IP:')[1].strip()
            elif "Path:" in p: 
                data['raw_path'] = p.split('Path:')[1].strip()
            
            # Métriques numériques
            elif "CPU:" in p: 
                data['cpu_ms'] = float(re.findall(r"[\d\.]+", p)[0])
            elif "RAM Peak:" in p: 
                data['ram_peak_kb'] = float(re.findall(r"[\d\.]+", p)[0])
            elif "DB Q:" in p or "Queries:" in p: 
                data['queries'] = int(re.findall(r"\d+", p)[0])
            elif "Rows:" in p: 
                data['rows'] = int(re.findall(r"\d+", p)[0])
        except Exception:
            continue 

    if 'raw_path' in data:
        return data
    return None

def clean_path_logic(path):
    """Regroupe les URLs."""
    if not path: return "Unknown"
    if "CMD::" in path: return path 
    path = path.split('?')[0]
    path = re.sub(r'[0-9a-fA-F-]{36}', '{uuid}', path)
    path = re.sub(r'/\d+/', '/{id}/', path)
    path = re.sub(r'/\d+$', '/{id}', path)
    return path

@st.cache_data(ttl=300)
def fetch_and_process_data():
    """Récupère via SSH et transforme en DataFrame."""
    logs_data = []
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = {"hostname": PA_HOST, "username": PA_USER, "timeout": 10}
        if PA_PASSWORD: connect_kwargs["password"] = PA_PASSWORD
        
        ssh.connect(**connect_kwargs)
        sftp = ssh.open_sftp()
        
        raw_content = ""
        for log_path in REMOTE_LOGS:
            try:
                with sftp.open(log_path, 'r') as f:
                    raw_content += f.read().decode('utf-8')
            except Exception: pass
            
        sftp.close()
        ssh.close()
        
    except Exception as e:
        st.error(f"Erreur SSH: {e}")
        return pd.DataFrame()

    for line in raw_content.split('\n'):
        parsed = parse_log_line(line)
        if parsed:
            parsed['path_group'] = clean_path_logic(parsed.get('raw_path', ''))
            logs_data.append(parsed)
            
    df = pd.DataFrame(logs_data)
    
    if df.empty:
        return df

    # --- CORRECTION DU BUG "Column not found" ---
    # On s'assure que toutes les colonnes nécessaires existent
    required_cols = {
        'ip': 'Server',         # Valeur par défaut si IP manquante
        'cpu_ms': 0.0,
        'ram_peak_kb': 0.0,
        'queries': 0,
        'rows': 0
    }
    
    for col, default_val in required_cols.items():
        if col not in df.columns:
            df[col] = default_val
        else:
            df[col] = df[col].fillna(default_val)
            
    return df

# --- 2. IA ENGINE ---

def run_simulation(df, visitors_per_hour):
    if df.empty: return None

    # Agrégation par heure
    df['date_hour'] = df['timestamp'].dt.floor('h')
    training_data = df.groupby('date_hour').agg({
        'path_group': 'count', 
        'queries': 'sum',       
        'cpu_ms': 'sum'
    }).rename(columns={'path_group': 'hits'})

    training_data = training_data[training_data['hits'] > 5]
    if len(training_data) < 3: return "NOT_ENOUGH_DATA"

    X = training_data[['hits']].values
    
    model_sql = LinearRegression().fit(X, training_data['queries'])
    pred_sql = model_sql.predict([[visitors_per_hour]])[0]
    
    model_cpu = LinearRegression().fit(X, training_data['cpu_ms'])
    pred_cpu = model_cpu.predict([[visitors_per_hour]])[0]

    return {
        'sql': max(0, int(pred_sql)),
        'cpu_sec': max(0, int(pred_cpu / 1000)),
        'sql_coef': model_sql.coef_[0]
    }

# --- 3. DASHBOARD UI ---

st.title("🧠 OmniView v3")
st.caption(f"Monitoring Intelligent (CPU • RAM • SQL) | Connecté à: {PA_HOST}")

with st.spinner('Téléchargement et analyse des logs...'):
    df = fetch_and_process_data()

if df.empty:
    st.warning("Aucune donnée disponible. Vérifiez les chemins des logs.")
    st.stop()

# KPI
col1, col2, col3, col4 = st.columns(4)
col1.metric("Traffic Analysé", f"{len(df)} reqs")
col2.metric("Temps CPU Moyen", f"{df['cpu_ms'].mean():.1f} ms")
col3.metric("RAM Peak Max", f"{(df['ram_peak_kb'].max() / 1024):.1f} MB")
col4.metric("Total SQL Queries", f"{df['queries'].sum():,}")

st.divider()

# SIMULATEUR
st.subheader("🔮 Prédiction de Charge (IA)")
col_sim_ctrl, col_sim_res = st.columns([1, 2])

with col_sim_ctrl:
    visitors = st.slider("Visiteurs / Heure", 100, 20000, 1000, step=500)
    sim_results = run_simulation(df, visitors)

with col_sim_res:
    if sim_results == "NOT_ENOUGH_DATA":
        st.info("Pas assez de données pour l'IA.")
    elif sim_results:
        c1, c2 = st.columns(2)
        c1.info(f"💾 **DB Load:** {sim_results['sql']:,} queries")
        c2.warning(f"⚡ **CPU Time:** {sim_results['cpu_sec']} sec/h")

st.divider()

# GRAPHIQUES
tab1, tab2 = st.tabs(["📊 Scatter Plot", "📋 Top Endpoints"])

with tab1:
    st.markdown("#### Corrélation: CPU vs Mémoire")
    # Le bug était ici : on utilise désormais des colonnes garanties d'exister
    fig = px.scatter(
        df, 
        x="cpu_ms", 
        y="ram_peak_kb", 
        size="queries", 
        color="queries",
        hover_data=["raw_path", "ip"], # Maintenant 'ip' existe forcément
        color_continuous_scale="Bluered"
    )
    st.plotly_chart(fig, use_container_width=True)

with tab2:
    stats = df.groupby('path_group').agg({
        'queries': 'mean',
        'cpu_ms': 'mean',
        'ram_peak_kb': 'max',
        'path_group': 'count'
    }).rename(columns={'path_group': 'hits'})
    
    stats['impact'] = (stats['queries'] * stats['hits']) 
    stats = stats.sort_values('impact', ascending=False).head(50).reset_index()
    
    st.dataframe(stats, use_container_width=True, height=600)

if st.button("🔄 Rafraîchir"):
    st.cache_data.clear()
    st.rerun()