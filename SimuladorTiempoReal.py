import pandas as pd
import time
import os
import sys

# === CONFIGURACIÓN DE RUTAS ===

ORIGEN = "Metricas/metricas_2016-03-21.csv" 
VELOCIDAD_AUTO = 0.1
DESTINO = "Metricas/metricas_live.csv"       

# ===============
def simulador_controlado(ruta_origen, ruta_destino, delay_automatico=0.5):
    
    # 1. Cargar datos
    if not os.path.exists(ruta_origen):
        print(f"❌ Error: No encuentro '{ruta_origen}'")
        return

    print(f"📂 Cargando archivo maestro: {ruta_origen}...")
    df_total = pd.read_csv(ruta_origen)
    total_filas = len(df_total)
    
    # 2. Preparar destino (Borrar datos previos y poner cabeceras)
    print(f"🧹 Limpiando archivo destino: {ruta_destino}")
    df_total.iloc[0:0].to_csv(ruta_destino, index=False)

    print("-------------------------------------------------------")
    print("🎮 MODO CONTROL MANUAL ACTIVADO")
    print("👉 Presiona [ENTER] para enviar 1 fila.")
    print("👉 Escribe 'a' y [ENTER] para liberar el modo AUTOMÁTICO.")
    print("-------------------------------------------------------")

    modo_automatico = False

    try:
        for i in range(total_filas):
            # --- LÓGICA DE CONTROL ---
            if not modo_automatico:
                # Esperar input del usuario
                comando = input(f"waiting... (Fila {i+1}/{total_filas}) > ")
                
                # Si el usuario escribe 'a', 'auto' o 'go', activamos el automático
                if comando.lower() in ['a', 'auto', 'go']:
                    modo_automatico = True
                    print(f"\n🚀 ¡MODO AUTOMÁTICO ACTIVADO! Enviando datos restantes...\n")
            
            # --- ENVIAR DATOS ---
            fila_actual = df_total.iloc[[i]]
            fila_actual.to_csv(ruta_destino, mode='a', header=False, index=False)
            
            # --- FEEDBACK VISUAL ---
            if modo_automatico:
                # Barra de progreso simple para modo automático
                sys.stdout.write(f"\r📡 Auto-Stream: Fila {i+1}/{total_filas} enviada.")
                sys.stdout.flush()
                time.sleep(delay_automatico)
            else:
                # Confirmación clara en modo manual
                print(f"✅ Fila {i+1} inyectada al sistema.")

    except KeyboardInterrupt:
        print("\n🛑 Detenido por el usuario.")

    print("\n\n🏁 Simulación finalizada. Todos los datos han sido transmitidos.")

# --- CONFIGURACIÓN ---
if __name__ == "__main__":
    
    simulador_controlado(ORIGEN, DESTINO, VELOCIDAD_AUTO)