import csv

flag_ruta = False

ruta_Ataques = "/Users/franciscoruizmontesdeoca/Documents/Bases_de_datos/TFG_Dataset/attack_ts_march_week4.csv"
ruta_Dataset = "/Users/franciscoruizmontesdeoca/Documents/Bases_de_datos/TFG_Dataset/uniq/march.week4.csv"

if flag_ruta:
    ruta_uso = ruta_Ataques
else:
    ruta_uso = ruta_Dataset

with open(ruta_uso, newline="") as f:
    reader = csv.reader(f)
    fila = [next(reader) for _ in range(200)]  # primeras 2 líneas
    for row in fila:
        print(row)
