# 🛡️ Sistema SOC de Defensa Activa y Visualización de Amenazas

> **Trabajo Fin de Asignatura: Calidad de los Sistemas Informáticos (2025-2026)** > **Autor:** Francisco Ruiz Montes de Oca  
> **Grado en Ingeniería Informática - UCA**

Este proyecto implementa un prototipo de **Centro de Operaciones de Seguridad (SOC)** ligero. Permite la **ingesta** de datos de tráfico de red (basado en el dataset UGR'16), la **visualización** en tiempo real de amenazas y la **mitigación activa** (bloqueo de IPs) mediante una interfaz web reactiva.

---

## 📋 Requisitos Previos

Para ejecutar este sistema necesitas:

* **Python 3.10** o superior.
* Sistema Operativo: **Linux/macOS** (Recomendado para la funcionalidad de bloqueo real) o **Windows** (funciona en modo simulación).
* Permisos de administrador (solo si deseas ejecutar el bloqueo real de `iptables` en Linux).

---

## 🚀 Instalación y Configuración

Sigue estos pasos para preparar el entorno. Se recomienda encarecidamente el uso de un entorno virtual para mantener limpias las dependencias.

### 1. Clonar el repositorio
Descarga el código fuente a tu máquina local:
```bash
git clone [https://github.com/TU_USUARIO/TU_REPOSITORIO.git](https://github.com/TU_USUARIO/TU_REPOSITORIO.git)
cd TU_REPOSITORIO
```

### 2. Crear un Entorno Virtual

**En macOS/Linux:**

Bash

```
python3 -m venv .venv
source .venv/bin/activate
```

**En Windows:**

Bash

```
python -m venv .venv
.venv\Scripts\activate
```

### 3. Instalar Dependencias

Instala las librerías necesarias (Streamlit, Pandas, Plotly, Cryptography) ejecutando:

Bash

```
pip install -r requirements.txt
```

---

## ⚙️ Cómo Ejecutar el Sistema (Orden Correcto)

El sistema consta de dos módulos principales que deben funcionar en paralelo (en dos terminales distintas).

### Paso 1: Iniciar el Motor de Datos (ETL)

Este script actúa como el "backend". Lee los datos crudos del dataset, identifica a los atacantes reales (Ground Truth) y genera el flujo de datos para la interfaz.

1. Abre una terminal.
    
2. Asegúrate de tener el entorno virtual activado.
    
3. Ejecuta:
    
    Bash
    
    ```
    python generateCSV.py
    ```    
    _Verás mensajes indicando que se están procesando ventanas de tiempo (ej: "⚠️ DETECTADO: 147.32.84.165..."). Déjalo corriendo en segundo plano._
    

### Paso 2: Lanzar el Dashboard (SOC)

Este script levanta la interfaz gráfica web donde visualizarás las alertas y ejecutarás las mitigaciones.

1. Abre **otra** terminal (nueva pestaña).
    
2. Activa el entorno virtual de nuevo (`source .venv/bin/activate` o `.venv\Scripts\activate`).
    
3. Ejecuta:
    
    Bash
    
    ```
    streamlit run interfaz.py
    ```
    
    _Automáticamente se abrirá una pestaña en tu navegador (usualmente en `http://localhost:8501`) con el Centro de Comando._
    

---

## 🕹️ Manual de Uso

Una vez dentro de la interfaz web:

### 1. Pestaña "Monitorización Global"

- **KPIs en tiempo real:** Observa el volumen de tráfico, paquetes maliciosos y nivel de infección actual.
    
- **Gráfica Interactiva:** Visualiza la línea de tráfico normal frente a las barras de ataques detectados (SSH Scan, Botnet, Spam, etc.).
    

### 2. Pestaña "Gestión de Incidentes"

- Aquí aparecerán las tarjetas de las IPs atacantes detectadas en el instante actual.
    
- **Tarjeta de Incidente:** Muestra la IP de origen, la IP de destino atacada y el tipo de malware.
    
- **Botón "MITIGAR":**
    
    - Si pulsas el botón, el sistema simulará (o ejecutará, si tienes permisos) una orden de bloqueo en el firewall.
        
    - La tarjeta cambiará a estado "🔒 Bloqueado" y la IP se añadirá a la lista negra de la sesión.
        
    - Se generará un registro de auditoría en `Logs/mitigacion_log.csv`.

### 3. Tiempo real

Ejecuta ``SimuladorTiempoReal.py`` 
no dará la opción de ir linea por linea o hacerlo automáticamente y observa como la pagina web se actualiza
