import csv
import os
from utils.utils_log import setup_logger
from cryptography.fernet import Fernet
from collections import defaultdict

# =================
# Configuración
# =================
flag_log = True
fecha_limite = "2016-03-23"

# Output
metric_csv = f"Metricas/metricas_{fecha_limite}.csv"
log_file = f"Logs/log_proceso_{fecha_limite}.log"

log = setup_logger("Log", log_file)

# =================
key = os.environ["SECRET_KEY"].encode()
fernet = Fernet(key)

with open("utils/config.enc", "rb") as f:
    encrypted_data = f.read()


base = fernet.decrypt(encrypted_data).decode()

# Rutas de archivos
file_csv = base+"/uniq/march.week4.csv"
malicious_csv = base+"/attack_ts_march_week4.csv"

nombres_malware = ["blacklist", "spam", "sshscan", "udpscan"]
malicious_malware_csv = [
    base+"/blacklist_flows_cut_march_week4.csv",
    base+"/spam_flows_cut_march_week4.csv",
    base+"/sshscan_flows_cut_march_week4.csv",
    base+"/udpscan_flows_cut_march_week4.csv"
]

# =================
# Carga de Diccionario Malicioso
# =================
malware_data = {nombre: defaultdict(int) for nombre in nombres_malware}

flag_log and log.info("Iniciando carga de archivos de malware...")

for nombre, m_file in zip(nombres_malware, malicious_malware_csv):
    try:
        if os.path.exists(m_file):
            with open(m_file, newline='') as f_m:
                reader_m = csv.reader(f_m, delimiter=';') 
                for fila in reader_m:
                    time_key = str(fila[0][:16]) # Clave: YYYY-MM-DD HH:MM
                    try:
                        # Sumamos paquetes al tipo específico
                        malware_data[nombre][time_key] += int(fila[8]) + int(fila[9])
                    except ValueError:
                        continue 
        else:
            flag_log and log.warning(f"Archivo no encontrado: {m_file}")

    except Exception as e:
        flag_log and log.error(f"Error procesando {m_file}: {e}")

flag_log and log.info("Carga de malware completada.")

# ===========
# Parte Principal
# ===========

if not os.path.exists(file_csv):
    flag_log and log.error(f"El archivo no existe: {file_csv}")
    exit()

col_names = [
    "timestamp_id", "total_bytes", "total_packets", "n_ips_org", "n_ips_dst",
    "flows_TCP", "flows_UDP", "flows_ICMP", "flows_RST",
    "media_duration_flow", "media_bytes/flow"
]

for nombre in nombres_malware:
    col_names.append(f"porcent_{nombre}")

# Añadimos la columna del total general
col_names.append("porcent_malware_total")

# =================
# Procesamiento Principal
# =================
try:
    with open(file_csv, newline="") as f, open(metric_csv, mode='w', newline='') as mf:
        reader = csv.reader(f)
        writer = csv.writer(mf)

        # Header
        next(reader, None)
        writer.writerow(col_names)

        # Leemos la primera fila de datos
        fila = next(reader, None)

        #1. BUCLE PARA BUSCAR LA FECHA
        while fila is not None and fila[0][:10] != fecha_limite:
            fila = next(reader, None)

        if fila is None:
            flag_log and log.warning(f"Se terminó el archivo y no se encontró la fecha: {fecha_limite}")
        else:
            flag_log and log.info(f"Fecha encontrada: {fecha_limite}. Iniciando proceso.")

        timestamp_counter = 0

        # 2. BUCLE PRINCIPAL (Mientras sea la fecha indicada)
        while fila is not None and fila[0][:10] == fecha_limite:

            # Capturamos el minuto actual (YYYY-MM-DD HH:MM) usando slicing
            # fila[0] es "2016-03-24 10:00:00", [:16] toma hasta el minuto
            current_datetime_key = fila[0][:16]

            # Inicializar acumuladores
            stats = {
                'flow_count': 0, 'total_bytes': 0, 'total_packets': 0, 'total_duration': 0.0,
                'flows_TCP': 0, 'flows_UDP': 0, 'flows_ICMP': 0, 'flows_RST': 0
            }

            ips_org = set()
            ips_dst = set()

            # 3. BUCLE INTERNO (Mientras sea el mismo minuto)
            while fila is not None and fila[0][:16] == current_datetime_key:
                try:
                    # Acumulamos datos
                    stats['flow_count'] += int(fila[11])
                    stats['total_bytes'] += int(fila[10])
                    stats['total_packets'] += int(fila[9])
                    stats['total_duration'] += float(fila[1])

                    ips_org.add(fila[2])
                    ips_dst.add(fila[3])

                    proto = fila[6]
                    if proto == 'TCP': stats['flows_TCP'] += 1
                    elif proto == 'UDP': stats['flows_UDP'] += 1
                    elif proto == 'ICMP': stats['flows_ICMP'] += 1

                    if 'R' in fila[7]: stats['flows_RST'] += 1

                    # Avanzamos a la siguiente fila
                    fila = next(reader, None)

                except ValueError:
                    # Si hay una fila corrupta, la saltamos pero intentamos seguir
                    fila = next(reader, None)
                    continue

            # --- FIN DEL MINUTO: Escribimos resultados ---
            flow_cnt = stats['flow_count']
            media_duration_flow = stats['total_duration'] / flow_cnt if flow_cnt > 0 else 0
            media_bytes_flow = stats['total_bytes'] / flow_cnt if flow_cnt > 0 else 0

            timestamp_counter += 1
            
            # 2. Creamos la fila base con los datos de tráfico normal
            row_output = [
                f"T{timestamp_counter}", 
                stats['total_bytes'],   
                stats['total_packets'], 
                len(ips_org), len(ips_dst),
                stats['flows_TCP'],     
                stats['flows_UDP'],     
                stats['flows_ICMP'],    
                stats['flows_RST'],     
                media_duration_flow, 
                media_bytes_flow
            ]

            # 3. Calculamos y añadimos los porcentajes de CADA tipo de malware
            total_malware_packets = 0
            total_pkts_minute = stats['total_packets']

            for nombre in nombres_malware:
                # Buscamos en el diccionario 
                pkts_malware = malware_data[nombre].get(current_datetime_key, 0)
                
                # Acumulamos para el total general
                total_malware_packets += pkts_malware

                pct = round(pkts_malware / total_pkts_minute * 100, 4) if total_pkts_minute > 0 else 0
                row_output.append(pct)

            # 4. Calculamos y añadimos el Total General de Malware (última columna)
            pct_total = round(total_malware_packets / total_pkts_minute * 100, 4) if total_pkts_minute > 0 else 0
            row_output.append(pct_total)

            writer.writerow(row_output)



except Exception as e:
    flag_log and log.error(f"Ocurrió un error inesperado: {e}", exc_info=True)

flag_log and log.info("Proceso finalizado.")

