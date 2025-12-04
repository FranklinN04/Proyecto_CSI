import csv
import os

from utils.utils_log import setup_logger

# =================
# Configuración
# =================
flag_log = True
fecha_limite = "2016-03-21"

# Rutas de archivos
file_csv = "/Users/franciscoruizmontesdeoca/Documents/Bases_de_datos/TFG_Dataset/uniq/march.week4.csv"
malicious_csv = "/Users/franciscoruizmontesdeoca/Documents/Bases_de_datos/TFG_Dataset/attack_ts_march_week4.csv"

# Output
metric_csv = f"metricas_{fecha_limite}.csv"
log_file = f"log_proceso_{fecha_limite}.log"

# =================
# Inicializar Logger
# =================
# Esto crea el archivo .log y prepara la consola
log = setup_logger("Log", log_file)

# =================
# Carga de Diccionario Malicioso
# =================
malicious_dict = {}
try:
    with open(malicious_csv, newline='') as f_m:
        reader_m = csv.reader(f_m)
        header_m = next(reader_m)
        for row in reader_m:
            time_key = str(row[0][:16])
            maliciosos = sum(int(x) for x in row[2:])
            malicious_dict[time_key] = maliciosos
except Exception as e:
    flag_log and log.error(f"Error cargando CSV malicioso: {e}")
    exit()

# Verificación de archivo principal
if not os.path.exists(file_csv):
    flag_log and log.error(f"El archivo no existe en la ruta especificada: {file_csv}")
    exit()

# Columnas Output
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
        next(reader)
        writer.writerow(col_names)

        fila = next(reader)
        timestamp_counter = 0

        # Bucle principal por fecha
        while fila[0].split()[0] == fecha_limite:

            # Capturamos el minuto actual que vamos a procesar
            current_time_str = fila[0].split()[1]
            current_datetime_key = fila[0][:16] # YYYY-MM-DD HH:MM para buscar en dict

            # Inicializar acumuladores para ESTE minuto
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

            # Procesar todas las filas que pertenezcan al mismo minuto (HH:MM)
            while fila[0].split()[1] == current_time_str:
                flow_count += int(fila[11])
                total_bytes += int(fila[10])
                total_packets += int(fila[9])
                total_duration += float(fila[1])

                ips_org.add(fila[2])
                ips_dst.add(fila[3])

                # Optimizacion de booleanos a int
                flows_TCP += (1 if fila[6] == 'TCP' else 0)
                flows_UDP += (1 if fila[6] == 'UDP' else 0)
                flows_ICMP += (1 if fila[6] == 'ICMP' else 0)
                flows_RST += (1 if 'R' in fila[7] else 0)

                try:
                    fila = next(reader)
                except StopIteration:
                    # Se acabó el archivo CSV
                    break

            # Calculamos métricas del minuto que ACABA de terminar
            media_duration_flow = total_duration / flow_count if flow_count > 0 else 0
            media_bytes_flow = total_bytes / flow_count if flow_count > 0 else 0

            # Usamos la key del tiempo que procesamos, no de la fila actual (que ya es el siguiente minuto)
            package_malicious = malicious_dict.get(current_datetime_key, 0)

            timestamp_counter += 1
            row_output = [
                f"T{timestamp_counter}", total_bytes, total_packets, len(ips_org), len(ips_dst),
                flows_TCP, flows_UDP, flows_ICMP, flows_RST,
                media_duration_flow, media_bytes_flow, package_malicious
            ]

            writer.writerow(row_output)


            # Si se acabó el archivo en el bucle interno, salir del externo también
            if fila[0].split()[1] == current_time_str:
                 break

except StopIteration:
    flag_log and log.info("Fin del archivo CSV alcanzado.")
except Exception as e:
    flag_log and log.error(f"Ocurrió un error inesperado: {e}", exc_info=True)

flag_log and log.info("Csv generado completamente")
