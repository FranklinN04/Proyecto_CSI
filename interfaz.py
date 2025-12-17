import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(
    page_title="Monitor de Amenazas de Red",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- ESTILOS CSS PERSONALIZADOS ---
st.markdown("""
    <style>
    .stMetric {
        background-color: #0E1117;
        padding: 15px;
        border-radius: 5px;
        border: 1px solid #262730;
    }
    </style>
    """, unsafe_allow_html=True)

# --- TÍTULO Y HEADER ---
col_logo, col_title = st.columns([1, 10])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown("# Monitor de Anomalías: Desglose por Malware")

st.markdown("---")

# 1. CARGA DE DATOS (SIDEBAR)
with st.sidebar:
    st.header("📂 Ingesta de Datos")
    uploaded_file = st.file_uploader("Cargar métricas detalladas (CSV)", type=["csv"])


if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)

        # --- VALIDACIÓN DE ESTRUCTURA ---
        required_columns = [
            'timestamp_id', 'total_bytes', 'total_packets', 
            'porcent_blacklist', 'porcent_spam', 'porcent_sshscan', 
            'porcent_udpscan', 'porcent_malware_total'
        ]

        if not set(required_columns).issubset(df.columns):
            st.error("❌ **Error de Formato**")
            st.markdown("El archivo no contiene las columnas de desglose de malware.")
            st.stop()

        # --- PROCESAMIENTO ---
        with st.spinner('Analizando vectores de ataque...'):
            first_val = str(df['timestamp_id'].iloc[0])
            
            if first_val.startswith('T'):
                start_date = pd.Timestamp.now().floor('min')
                df['idx'] = df['timestamp_id'].astype(str).str.extract(r'(\d+)').astype(float).fillna(0).astype(int)
                df['fecha'] = df['idx'].apply(lambda x: start_date + pd.Timedelta(minutes=x))
            else:
                # Solo si NO empieza por T intentamos convertir a fecha real
                df['fecha'] = pd.to_datetime(df['timestamp_id'], errors='coerce')

            df = df.sort_values('fecha')

            # --- LÓGICA DE DETECCIÓN ---
            def analizar_amenaza(row):
                tipos_detectados = []
                if row['porcent_blacklist'] > 0: tipos_detectados.append("Blacklist")
                if row['porcent_spam'] > 0: tipos_detectados.append("Spam")
                if row['porcent_sshscan'] > 0: tipos_detectados.append("SSH Scan")
                if row['porcent_udpscan'] > 0: tipos_detectados.append("UDP Scan")
                
                pct_total = row['porcent_malware_total']
                
                if pct_total == 0: nivel = "🟢 Seguro"
                elif pct_total < 5: nivel = "🟡 Bajo"
                elif pct_total < 20: nivel = "🟠 Medio"
                else: nivel = "🔴 Crítico"

                desc = ", ".join(tipos_detectados) if tipos_detectados else "Tráfico Limpio"
                return pd.Series([desc, nivel])

            df[['Tipo Amenaza', 'Severidad']] = df.apply(analizar_amenaza, axis=1)
            incidentes = df[df['porcent_malware_total'] > 0].copy()

        # --- DASHBOARD VISUAL ---
        col1, col2, col3, col4 = st.columns(4)

        trafico_gb = df['total_bytes'].sum() / (1024**3)
        max_infeccion = df['porcent_malware_total'].max()
        cols_malware = ['porcent_blacklist', 'porcent_spam', 'porcent_sshscan', 'porcent_udpscan']
        top_threat = df[cols_malware].mean().idxmax().replace('porcent_', '').upper()
        pkts_maliciosos_estimados = int((df['total_packets'] * (df['porcent_malware_total']/100)).sum())

        with col1: st.metric("Tráfico Total", f"{trafico_gb:.2f} GB")
        with col2: st.metric("Paquetes Maliciosos (Est.)", f"{pkts_maliciosos_estimados:,}")
        with col3: st.metric("Pico de Infección", f"{max_infeccion:.2f}%", delta="Nivel de Tráfico Comprometido", delta_color="off")
        with col4: st.metric("Amenaza Predominante", top_threat, delta="Tendencia Principal", delta_color="inverse")

        # 2. Gráfica Principal
        st.subheader("📡 Composición del Tráfico Malicioso")

        fig = make_subplots(specs=[[{"secondary_y": True}]])

        fig.add_trace(
            go.Scatter(
                x=df['fecha'], y=df['total_packets'], name="Paquetes Totales",
                line=dict(color='rgba(255, 255, 255, 0.3)', width=1, dash='dot'),
                hoverinfo='skip'
            ), secondary_y=False
        )

        colors = {'blacklist': '#636EFA', 'spam': '#EF553B', 'sshscan': '#00CC96', 'udpscan': '#AB63FA'}
        for m_type in ['blacklist', 'spam', 'sshscan', 'udpscan']:
            col_name = f'porcent_{m_type}'
            if df[col_name].sum() > 0:
                fig.add_trace(
                    go.Bar(
                        x=df['fecha'], y=df[col_name], name=m_type.upper(),
                        marker_color=colors.get(m_type, 'grey')
                    ), secondary_y=True
                )

        fig.update_layout(
            barmode='stack', template="plotly_dark",
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            legend=dict(orientation="h", y=1.1), height=450,
            title_text="Paquetes Totales (Línea) vs % Composición de Malware (Barras)"
        )
        fig.update_yaxes(title_text="Paquetes / Minuto", showgrid=False, secondary_y=False)
        fig.update_yaxes(title_text="% Del Tráfico Malicioso", showgrid=True, range=[0, max(max_infeccion * 1.2, 5)], secondary_y=True)


        try:
            st.plotly_chart(fig, use_container_width=True)
        except TypeError:
            st.plotly_chart(fig)

        # 3. Tabla Detallada
        st.subheader("🚨 Desglose de Incidentes")
        
        if not incidentes.empty:
            cols_to_show = ['fecha', 'Tipo Amenaza', 'Severidad', 'porcent_malware_total', 
                           'porcent_blacklist', 'porcent_spam', 'porcent_sshscan', 'porcent_udpscan']
            
 
            st.dataframe(
                incidentes[cols_to_show],
                use_container_width=True, 
                column_config={
                    "fecha": st.column_config.DatetimeColumn("Tiempo", format="HH:mm"),
                    "Tipo Amenaza": st.column_config.TextColumn("Vectores Detectados", width="medium"),
                    "Severidad": st.column_config.TextColumn("Nivel", width="small"),
                    "porcent_malware_total": st.column_config.ProgressColumn(
                        "% Total Infectado", format="%.2f%%", min_value=0, max_value=100
                    ),
                    "porcent_blacklist": st.column_config.NumberColumn("% Blk", format="%.2f"),
                    "porcent_spam": st.column_config.NumberColumn("% Spam", format="%.2f"),
                    "porcent_sshscan": st.column_config.NumberColumn("% SSH", format="%.2f"),
                    "porcent_udpscan": st.column_config.NumberColumn("% UDP", format="%.2f"),
                },
                hide_index=True
            )
        else:
            st.info("No se detectó tráfico malicioso en el archivo cargado.")

    except Exception as e:
        st.error(f"⚠️ **Error Procesando Datos**: {e}")

else:
    st.info("👆 Por favor carga el archivo 'metricas_detalladas.csv' generado para visualizar el análisis.")
    