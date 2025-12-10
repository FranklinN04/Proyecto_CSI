import csv
import os
from utils.utils_log import setup_logger

# =================
# Configuración
# =================
flag_log = True
fecha_limite = "2016-03-22"

# Rutas de archivos
file_csv = "/Users/franciscoruizmontesdeoca/Documents/Data_Set/TFG_Dataset/uniq/march.week4.csv"
malicious_csv = "/Users/franciscoruizmontesdeoca/Documents/Data_Set/TFG_Dataset/attack_ts_march_week4.csv"

# Output
metric_csv = f"Metricas/metricas_{fecha_limite}.csv"
log_file = f"Logs/log_proceso_{fecha_limite}.log"

log = setup_logger("Log", log_file)

# =================
# Carga de Diccionario Malicioso
# =================
malicious_dict = {}
try:
    if os.path.exists(malicious_csv):
        with open(malicious_csv, newline='') as f_m:
            reader_m = csv.reader(f_m)
            header_m = next(reader_m, None)
            for row in reader_m:
                if row:
                    time_key = str(row[0][:16])
                    maliciosos = sum(int(x) for x in row[2:])
                    malicious_dict[time_key] = maliciosos
except Exception as e:
    flag_log and log.error(f"Error cargando CSV malicioso: {e}")
    exit()

if not os.path.exists(file_csv):
    flag_log and log.error(f"El archivo no existe: {file_csv}")
    exit()

col_names = [
    "timestamp_id", "total_bytes", "total_packets", "n_ips_org", "n_ips_dst",
    "flows_TCP", "flows_UDP", "flows_ICMP", "flows_RST",
    "media_duration_flow", "media_bytes/flow", "package_malicious"
]

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

        # 1. BUCLE PARA SALTAR LO QUE NO SEA LA FECHA
        # Usamos fila[0][:10] en vez de split() para ahorrar memoria y tiempo
        while fila is not None and fila[0][:10] != fecha_limite:
            fila = next(reader, None)
            # Quitamos el log por fila para no saturar la consola/disco

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
            flow_count = 0
            total_bytes = 0
            total_packets = 0
            total_duration = 0.0
            ips_org = set()
            ips_dst = set()
            flows_TCP = 0
            flows_UDP = 0
            flows_ICMP = 0
            flows_RST = 0

            # 3. BUCLE INTERNO (Mientras sea el mismo minuto)
            # Comparamos la clave de tiempo actual con la de la fila
            while fila is not None and fila[0][:16] == current_datetime_key:
                try:
                    # Acumulamos datos
                    flow_count += int(fila[11])
                    total_bytes += int(fila[10])
                    total_packets += int(fila[9])
                    total_duration += float(fila[1])

                    ips_org.add(fila[2])
                    ips_dst.add(fila[3])

                    proto = fila[6]
                    if proto == 'TCP': flows_TCP += 1
                    elif proto == 'UDP': flows_UDP += 1
                    elif proto == 'ICMP': flows_ICMP += 1

                    if 'R' in fila[7]: flows_RST += 1

                    # Avanzamos a la siguiente fila
                    fila = next(reader, None)

                except ValueError:
                    # Si hay una fila corrupta, la saltamos pero intentamos seguir
                    fila = next(reader, None)
                    continue

            # --- FIN DEL MINUTO: Escribimos resultados ---
            media_duration_flow = total_duration / flow_count if flow_count > 0 else 0
            media_bytes_flow = total_bytes / flow_count if flow_count > 0 else 0

            package_malicious = malicious_dict.get(current_datetime_key, 0)

            timestamp_counter += 1
            row_output = [
                f"T{timestamp_counter}", total_bytes, total_packets, len(ips_org), len(ips_dst),
                flows_TCP, flows_UDP, flows_ICMP, flows_RST,
                media_duration_flow, media_bytes_flow, package_malicious
            ]
            writer.writerow(row_output)

            # El bucle externo se encargará de verificar si seguimos en la fecha correcta
            # o si el archivo (fila) se ha terminado (None).

except Exception as e:
    flag_log and log.error(f"Ocurrió un error inesperado: {e}", exc_info=True)

flag_log and log.info("Proceso finalizado.")
