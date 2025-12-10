import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(
    page_title="Monitor de incidencias",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)


# --- TÍTULO Y HEADER ---
col_logo, col_title = st.columns([1, 10])
with col_logo:
    st.markdown("# 🛡️")
with col_title:
    st.markdown("# Monitor de Anomalías de Red y Detección de Intrusiones")

st.markdown("---")

# 1. CARGA DE DATOS (SIDEBAR)
with st.sidebar:
    st.header("📂 Ingesta de Datos")
    uploaded_file = st.file_uploader("Arrastra tu log CSV aquí", type=["csv"])


if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)

        # --- VALIDACIÓN DE ESTRUCTURA ---
        required_columns = [
            'timestamp_id', 'total_bytes', 'total_packets', 'n_ips_org',
            'n_ips_dst', 'flows_TCP', 'flows_UDP', 'flows_ICMP', 'flows_RST',
            'media_duration_flow', 'media_bytes/flow', 'package_malicious'
        ]

        if not set(required_columns).issubset(df.columns):
            st.error("❌ **Error de Formato de Archivo**")
            st.markdown("El archivo cargado no cumple con el esquema de seguridad requerido.")
            st.markdown("### 📋 Estructura Requerida (Copiar y Pegar)")

            # Código estilizado para copiar
            st.code("""timestamp_id,total_bytes,total_packets,n_ips_org,n_ips_dst,flows_TCP,flows_UDP,flows_ICMP,flows_RST,media_duration_flow,media_bytes/flow,package_malicious
T1,13,40,2,6,4,2,0,0,0.023584821428571427,0.014508928571428572,1""", language="csv")

            st.stop()

        # --- PROCESAMIENTO ---
        with st.spinner('Analizando paquetes y flujos de red...'):
            # Conversión Fechas
            try:
                df['fecha'] = pd.to_datetime(df['timestamp_id'])
            except:
                start_date = pd.Timestamp.now().floor('min')
                def limpiar_y_convertir(x):
                    try:
                        return int(str(x).upper().replace('T', ''))
                    except: return 0
                df['minutos_offset'] = df['timestamp_id'].apply(limpiar_y_convertir)
                df['fecha'] = df['minutos_offset'].apply(lambda x: start_date + pd.Timedelta(minutes=x))

            df = df.sort_values('fecha')

            # Configuración
            st.sidebar.markdown("---")
            st.sidebar.subheader("⚙️ Parámetros de Detección")
            umbral_rst = st.sidebar.slider("Sensibilidad RST (Escaneos)", 0, 100, 50)

            # Lógica de Análisis
            def analizar_fila(row):
                alertas = []
                nivel = "🟢 Normal"

                # Malware
                val_malware = pd.to_numeric(row['package_malicious'], errors='coerce') or 0
                if val_malware > 0:
                    if val_malware == 1:
                        alertas.append(f"Malware ({int(val_malware)})")
                        nivel = "🟡 Media"
                    elif val_malware == 2:
                        alertas.append(f"Malware ({int(val_malware)})")
                        nivel = "🟠 Alta"
                    else:
                        alertas.append(f"MALWARE MASIVO ({int(val_malware)})")
                        nivel = "🔴 Crítica"

                # Escaneo
                val_rst = pd.to_numeric(row['flows_RST'], errors='coerce') or 0
                if val_rst > umbral_rst and nivel == "🟢 Normal":
                    alertas.append("Escaneo de Puertos")
                    if "Crítica" not in nivel: nivel = "🟡 Media"

                str_alertas = " + ".join(alertas) if alertas else "Tráfico Limpio"
                return pd.Series([str_alertas, nivel])

            df[['Detalle Alerta', 'Nivel de Amenaza']] = df.apply(analizar_fila, axis=1)
            amenazas = df[(df['package_malicious'] > 0) | (df['Nivel de Amenaza'] != '🟢 Normal')]

        # --- DASHBOARD VISUAL ---

        # 1. Métricas Clave 
        col1, col2, col3, col4 = st.columns(4)

        total_malware = int(df['package_malicious'].sum())
        total_eventos = len(amenazas)
        pico_max = df['package_malicious'].max() if not df.empty else 0

        with col1:
            st.metric("Total Paquetes", f"{len(df):,}")
        with col2:
            st.metric("Tráfico Analizado", f"{df['total_bytes'].sum()/1024:.2f} KB")
        with col3:
            st.metric("Paquetes Maliciosos", total_malware, delta=f"{total_malware}", delta_color="inverse")
        with col4:
            st.metric("Amenazas Activas", total_eventos, delta="Alerta" if total_eventos > 0 else "Seguro", delta_color="inverse")

        # 2. Gráfica Principal
        st.subheader("📡 Telemetría en Tiempo Real")

        fig = make_subplots(specs=[[{"secondary_y": True}]])

        # Área de tráfico
        fig.add_trace(
            go.Scatter(
                x=df['fecha'], y=df['total_bytes'], name="Tráfico (Bytes)",
                fill='tozeroy', line=dict(color='#00f2ff', width=1), mode='lines'
            ), secondary_y=False
        )

        # Barras de Ataque
        fig.add_trace(
            go.Bar(
                x=df['fecha'], y=df['package_malicious'], name="Intrusión Detectada",
                marker=dict(color='#ff2a2a', line=dict(color='#ff2a2a', width=1)), opacity=0.8
            ), secondary_y=True
        )

        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(family="Roboto, sans-serif"),
            hovermode="x unified",
            legend=dict(orientation="h", y=1.1),
            margin=dict(l=20, r=20, t=40, b=20),
            height=400
        )
        fig.update_yaxes(title_text="Tráfico", showgrid=False, secondary_y=False)
        fig.update_yaxes(title_text="Amenazas", showgrid=False, secondary_y=True)

        st.plotly_chart(fig, use_container_width=True)

        # 3. Tabla de Detalles (Mejorada)
        if not amenazas.empty:
            st.subheader("🚨 Registro de Incidentes")

            # Usamos st.dataframe con configuración de columnas para visuales bonitos
            st.dataframe(
                amenazas[['fecha', 'Detalle Alerta', 'package_malicious', 'flows_RST', 'Nivel de Amenaza']],
                use_container_width=True,
                column_config={
                    "fecha": st.column_config.DatetimeColumn("Timestamp", format="D MMM, HH:mm"),
                    "package_malicious": st.column_config.ProgressColumn(
                        "Magnitud Malware",
                        help="Cantidad de paquetes maliciosos",
                        format="%d",
                        min_value=0,
                        max_value=int(pico_max),
                        width="medium"
                    ),
                    "Nivel de Amenaza": st.column_config.TextColumn(
                        "Severidad",
                        width="small",
                    ),
                    "flows_RST": st.column_config.NumberColumn("Flujos RST")
                },
                hide_index=True
            )
        else:
            st.success("✅ **Sistema Seguro:** No se detectaron anomalías en el periodo analizado.")

    except Exception as e:
        st.error("⚠️ **Error de Procesamiento**")
        st.markdown("No se pudo leer el archivo. Asegúrese de que no esté corrupto.")

else:
    # Pantalla de bienvenida vacía
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 50px;'>
        <h3>Esperando datos...</h3>
        <p>Sube un archivo CSV en la barra lateral para iniciar el monitoreo.</p>
    </div>
    """, unsafe_allow_html=True)
