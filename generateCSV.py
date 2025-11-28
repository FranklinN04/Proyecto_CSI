import pandas as pd

file_csv = "/Users/franciscoruizmontesdeoca/Downloads/uniq/march.week4.csv.uniqblacklistremoved"


# ------------------------------------------------------------
# 1) Filtrar filas de un día concreto
# ------------------------------------------------------------
def filtrar_por_dia(file_csv, dia, chunksize=100_000):

    fecha_objetivo = pd.to_datetime(dia).date()
    filas_dia = []

    for chunk in pd.read_csv(file_csv, header=None, skip_blank_lines=True, chunksize=chunksize):

        # Convertir timestamp
        chunk[0] = pd.to_datetime(chunk[0], errors="coerce")

        # Filtrar día
        filtradas = chunk[chunk[0].dt.date == fecha_objetivo]

        if not filtradas.empty:
            filas_dia.append(filtradas)

    return pd.concat(filas_dia, ignore_index=True) if filas_dia else pd.DataFrame()



# ------------------------------------------------------------
# 2) Función: calcular métricas por minuto
# ------------------------------------------------------------
def metricas_por_minuto(df):

    # Asegurar datetime
    df[0] = pd.to_datetime(df[0], errors='coerce')

    # Crear columna minuto
    df['minute'] = df[0].dt.floor('min')

    # --- CONVERTIR A NUMÉRICO PARA EVITAR CONCATENACIÓN ---
    # AJUSTA ESTOS ÍNDICES A TU CSV
    numeric_cols = [5, 6, 8]    # bytes, packets, duration (suponiendo ese orden)
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    grp = df.groupby('minute')

    resumen = pd.DataFrame({
        "flows": grp.size(),
        "total_bytes": grp[5].sum(),
        "total_packets": grp[6].sum(),
        "src_ips_unicas": grp[1].nunique(),
        "dst_ips_unicas": grp[2].nunique(),
        "dst_ports_unicos": grp[3].nunique(),
        "tcp_flows": grp[4].apply(lambda x: (x == "TCP").sum()),
        "udp_flows": grp[4].apply(lambda x: (x == "UDP").sum()),
        "icmp_flows": grp[4].apply(lambda x: (x == "ICMP").sum()),
        "flows_RST": grp[7].apply(lambda x: x.astype(str).str.contains("R").sum()),
        "duracion_media": grp[8].mean(),
        "media_bytes_por_flow": grp[5].mean(),
    })

    return resumen.reset_index()



# ------------------------------------------------------------
# 3) Ejecutar todo
# ------------------------------------------------------------
df_dia = filtrar_por_dia(file_csv, "2016-03-21")
print("Filas filtradas:", len(df_dia))

df_minutos = metricas_por_minuto(df_dia)
print(df_minutos.head())

df_minutos.to_csv("metricas_2016-03-21.csv", index=False)
print("Guardado metricas_2016-03-21.csv")