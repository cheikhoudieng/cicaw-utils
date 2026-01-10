import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json

# Configuration de la page
st.set_page_config(page_title="Supabase Usage Dashboard", layout="wide")

# --- CONSTANTES & HEADERS ---
# Note : Dans un environnement de production, mettez le Token dans st.secrets
BASE_URL = "https://api.supabase.com/platform/organizations/ogcilhtisexjcsmmbepk/usage/daily"

# Les headers extraits de votre requête précédente
HEADERS = {
    "accept": "application/json",
    "accept-encoding": "gzip, deflate",  # On évite 'br' pour simplifier sans librairie externe
    "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "authorization": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjNlNjE5YzJjIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2FsdC5zdXBhYmFzZS5pby9hdXRoL3YxIiwic3ViIjoiYzY5ODQ5YTgtZWIxMC00MWFiLTljOWItZDUyY2YxZWM2Yzc4IiwiYXVkIjoiYXV0aGVudGljYXRlZCIsImV4cCI6MTc2Nzk2OTA0NCwiaWF0IjoxNzY3OTY3MjQ0LCJlbWFpbCI6ImNoZWlraG91ZGllbmcwMzJAZ21haWwuY29tIiwicGhvbmUiOiIiLCJhcHBfbWV0YWRhdGEiOnsicHJvdmlkZXIiOiJnaXRodWIiLCJwcm92aWRlcnMiOlsiZ2l0aHViIl19LCJ1c2VyX21ldGFkYXRhIjp7ImF2YXRhcl91cmwiOiJodHRwczovL2F2YXRhcnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3UvMzM1ODAwODc_dj00IiwiZW1haWwiOiJjaGVpa2hvdWRpZW5nMDMyQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczovL2FwaS5naXRodWIuY29tIiwicGhvbmVfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJjaGVpa2hvdWRpZW5nIiwicHJvdmlkZXJfaWQiOiIzMzU4MDA4NyIsInN1YiI6IjMzNTgwMDg3IiwidXNlcl9uYW1lIjoiY2hlaWtob3VkaWVuZyJ9LCJyb2xlIjoiYXV0aGVudGljYXRlZCIsImFhbCI6ImFhbDEiLCJhbXIiOlt7Im1ldGhvZCI6Im9hdXRoIiwidGltZXN0YW1wIjoxNzYxNjUxODk5fV0sInNlc3Npb25faWQiOiIwMmVlNTgyNC04NmM3LTQyMjctYTk3YS0xOTFmZTA0OTQyNjUiLCJpc19hbm9ueW1vdXMiOmZhbHNlfQ.ZBpmFCodHpFbiFipTSuty_PSvLOlaoay0zC_2rvzSCYKbm0SKwhmvcJWRFItS7B4WA6l49WkbfPYmj7aZrrHkun_ayCHjRhcKN_wt19uLWuMaMnEoULUbZROiA30CVerrQNUw6to-qKozSQga4ippfZ-XtcqRBJ-Z0P7IgY23qk6vgs5heO32BrHYI5ZcDLVrx2pBKS6bPBHxEH1V6GkLLdb-fq69HB7HIKzuqA-Yqs-daFAxV-NOvc9a1nrl5sQjHWd1DNdmiD7w4KnHYbBKhqgMryk2E8PZ-DzzXsLHvFAwcElvmyfzX4EhD5BbmPNuiqMiZG_5gpER8RLmDeYww",
    "origin": "https://supabase.com",
    "referer": "https://supabase.com/dashboard/org/ogcilhtisexjcsmmbepk/usage",
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "cookie": "anonymous_id=019b3afe-47b9-7eef-964c-c3cb9fc45118; FPID=FPID2.2.CaJPdehRmf88apj%2BjqjDHEnf2Ue2RNXfqDU1%2BlYRbGs%3D.1766218441; FPAU=1.2.502496922.1766221302; _ga=GA1.1.997433085.1766227569; __stripe_mid=0e0f3872-564c-4a9b-a883-ab39ab7f3e295e1a82; user_id=c69849a8-eb10-41ab-9c9b-d52cf1ec6c78; session_id=019ba2f3-fe24-7998-928f-bd0c18e4cf39; ph_phc_q2wUqNSr9AsKvH56PBbg9RX5dGKypQZi1gxk3cuSXJ5_posthog=%7B%22distinct_id%22%3A%22c69849a8-eb10-41ab-9c9b-d52cf1ec6c78%22%2C%22%24sesid%22%3A%5B1767965462519%2C%22019ba2f3-fe24-7998-928f-bd0c18e4cf39%22%2C1767965457956%5D%2C%22%24epp%22%3Atrue%2C%22%24initial_person_info%22%3A%7B%22r%22%3A%22https%3A%2F%2Fwww.google.com%2F%22%2C%22u%22%3A%22https%3A%2F%2Fsupabase.com%2F%22%7D%7D; _ga_7811VTCM91=GS2.1.s1767965463$o43$g0$t1767965463$j60$l0$h2141136977; FPLC=aSTxx%2BIHr72NI%2Fzgtnmu87No%2FMZuhisrd%2FPjTrIqnjcQ2zTK2hw9Jh3yuALSUp0o1cFtOIvSg8wEBw7cflJozv1FeyOe%2Fglw4GH3eXfNLZFPZBA53WSHeYV5GSqlhg%3D%3D; __cf_bm=ZJNqXa1s2quy6onahr6ph5_oG1IpK9Eqc6IKwSrJH4A-1767965483.1840105-1.0.1.1-N8nXb2BpTqs3_KqgiHGVJ1G1utRXS5X1PDsuHPD6WpGD17n_Txbfycnm2qdK3jZSkKrgDdWyToKRWFYn3FEdBITUH1NeaHAFQNe95SSVWtYaYLtxU.nk5gN91XwczYuA"
}

# --- FONCTIONS ---

@st.cache_data(ttl=3600)  # Cache des données pour éviter de spammer l'API
def fetch_usage_data(start_date, end_date):
    """Récupère les données depuis l'API Supabase"""
    
    # Formatage des dates au format ISO 8601 requis par Supabase (ex: 2025-12-10T13:31:33Z)
    params = {
        "start": f"{start_date.strftime('%Y-%m-%d')}T00:00:00Z",
        "end": f"{end_date.strftime('%Y-%m-%d')}T23:59:59Z"
    }

    try:
        response = requests.get(BASE_URL, params=params, headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        st.error(f"Erreur HTTP : {e}")
        if response.status_code == 401:
            st.error("Le token d'authentification a expiré. Veuillez mettre à jour le header 'Authorization'.")
        return None
    except Exception as e:
        st.error(f"Erreur technique : {e}")
        return None

def process_data(json_data):
    """Transforme le JSON en DataFrame Pandas"""
    if not json_data or 'usages' not in json_data:
        return pd.DataFrame()
    
    df = pd.DataFrame(json_data['usages'])
    df['date'] = pd.to_datetime(df['date'])
    return df

# --- INTERFACE UTILISATEUR ---

st.title("📊 Supabase Usage Analytics")
st.markdown("Visualisez l'évolution de votre consommation Supabase (Stockage, Egress, Compute, etc.)")

# 1. BARRE LATÉRALE : FILTRES
with st.sidebar:
    st.header("Paramètres")
    
    # Sélecteur de date
    today = datetime.now()
    # Par défaut : du 10 déc 2025 au 9 janv 2026 (selon votre exemple)
    default_start = datetime(2025, 12, 10)
    default_end = datetime(2026, 1, 9)
    
    date_range = st.date_input(
        "Période",
        value=(default_start, default_end),
        format="DD/MM/YYYY"
    )
    
    btn_refresh = st.button("🔄 Actualiser les données", type="primary")

    if len(date_range) != 2:
        st.warning("Veuillez sélectionner une date de début et de fin.")
        st.stop()

    start_date, end_date = date_range

# 2. CHARGEMENT DES DONNÉES
if btn_refresh or 'data_loaded' not in st.session_state:
    with st.spinner("Récupération des données Supabase..."):
        raw_json = fetch_usage_data(start_date, end_date)
        if raw_json:
            st.session_state.df = process_data(raw_json)
            st.session_state.data_loaded = True
        else:
            st.stop()

df = st.session_state.get('df', pd.DataFrame())

if df.empty:
    st.info("Aucune donnée disponible pour cette période.")
    st.stop()

# 3. FILTRES AVANCÉS (MAIN PAGE)
col_filter1, col_filter2 = st.columns([2, 1])

with col_filter1:
    available_metrics = df['metric'].unique().tolist()
    selected_metrics = st.multiselect(
        "Filtrer par Métrique", 
        options=available_metrics, 
        default=available_metrics
    )

# Filtrage du DataFrame principal
df_filtered = df[df['metric'].isin(selected_metrics)]

# 4. GRAPHIQUE 1 : ÉVOLUTION GLOBALE (Line Chart)
st.subheader("📈 Évolution de la consommation")

if not df_filtered.empty:
    # On crée un graphique linéaire avec Plotly
    fig_line = px.line(
        df_filtered, 
        x='date', 
        y='usage', 
        color='metric',
        markers=True,
        title="Consommation journalière par type",
        labels={'usage': 'Utilisation (Unités : Go, Heures, etc.)', 'date': 'Date', 'metric': 'Type'},
        template="plotly_dark"
    )
    fig_line.update_layout(hovermode="x unified")
    st.plotly_chart(fig_line, use_container_width=True)
else:
    st.warning("Veuillez sélectionner au moins une métrique.")

# 5. GRAPHIQUE 2 : ANALYSE DÉTAILLÉE (BREAKDOWN)
# Certains métriques comme EGRESS ont un champ "breakdown" qui détaille la conso.
# On va extraire ces données pour faire un Stacked Bar Chart.

st.subheader("🔍 Analyse détaillée (Breakdown)")

# On cherche les lignes qui ont un breakdown non nul
df_with_breakdown = df_filtered[df_filtered['breakdown'].notna()]

if not df_with_breakdown.empty:
    # Liste des métriques qui ont un détail dispo
    metrics_with_breakdown = df_with_breakdown['metric'].unique()
    
    # Onglets si plusieurs métriques ont des détails
    tabs = st.tabs([f"Détail : {m}" for m in metrics_with_breakdown])
    
    for i, metric in enumerate(metrics_with_breakdown):
        with tabs[i]:
            # Filtrer pour cette métrique spécifique
            df_m = df_with_breakdown[df_with_breakdown['metric'] == metric].copy()
            
            # Normaliser la colonne JSON 'breakdown' en colonnes séparées
            breakdown_expanded = pd.json_normalize(df_m['breakdown'])
            breakdown_expanded.index = df_m.index # Réaligner les index
            
            # Combiner avec la date
            df_viz = pd.concat([df_m[['date']], breakdown_expanded], axis=1)
            
            # Convertir les bytes en GB pour la lisibilité si c'est de l'EGRESS
            if 'EGRESS' in metric:
                # Les colonnes breakdown sont souvent en octets bruts, on divise par 10^9 pour Go
                numeric_cols = df_viz.select_dtypes(include=['number']).columns
                df_viz[numeric_cols] = df_viz[numeric_cols] / 1e9
                y_label = "Volume (Go)"
            else:
                y_label = "Valeur Brute"

            # Transformer en format long pour Plotly
            df_melted = df_viz.melt(id_vars=['date'], var_name='Sous-composant', value_name='Valeur')

            # Bar chart empilé
            fig_bar = px.bar(
                df_melted,
                x='date',
                y='Valeur',
                color='Sous-composant',
                title=f"Répartition détaillée pour {metric}",
                labels={'Valeur': y_label},
                template="plotly_dark"
            )
            st.plotly_chart(fig_bar, use_container_width=True)
else:
    st.caption("Aucune donnée détaillée (breakdown) disponible pour les métriques sélectionnées.")

# 6. TABLEAU DE DONNÉES BRUTES
with st.expander("Voir les données brutes"):
    st.dataframe(
        df_filtered[['date', 'metric', 'usage', 'usage_original', 'breakdown']].sort_values(by=['date', 'metric']),
        use_container_width=True
    )