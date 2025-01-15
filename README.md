## Sistema de Detección de Intrusos (IDS) con Visualización en Tiempo Real

### Descripción
Este sistema IDS monitorea el tráfico de red, detectando actividad sospechosa como:
- Alta tasa de paquetes enviados desde una dirección IP (indicativo de posibles ataques DoS o tráfico anómalo).
- Intentos repetidos de conexión a puertos cerrados.
Además, incluye una **visualización gráfica en tiempo real** que muestra las direcciones IP origen y el número de paquetes enviados.

---

### Características
#### **Detección de Actividad Sospechosa**
- **Alta Tasa de Paquetes por Segundo**:
  - Detecta direcciones IP que envían más paquetes por segundo de lo permitido.
  - Genera alertas automáticas si se excede un umbral configurable.
- **Intentos Repetidos a Puertos Cerrados**:
  - Identifica múltiples intentos de conexión hacia puertos cerrados desde una misma IP.
  - Genera alertas cuando una IP supera un límite de intentos en un intervalo de tiempo.

#### **Visualización del Tráfico**
- **Gráficos de Barras en Tiempo Real**:
  - Muestra las direcciones IP origen y el número de paquetes enviados.
  - El gráfico se actualiza dinámicamente a medida que se capturan nuevos paquetes.

---

### Cómo Funciona
#### **Captura de Paquetes**
- Utiliza la biblioteca `Scapy` para capturar paquetes de red en tiempo real.
- Extrae la dirección IP origen y otros datos relevantes de los paquetes.

#### **Reglas de Detección**
1. **Alta Tasa de Paquetes**:
   - Se calcula la cantidad de paquetes enviados por segundo desde cada IP.
   - Si una IP excede el umbral configurado (por ejemplo, 50 paquetes/seg), se genera una alerta.

2. **Conexiones a Puertos Cerrados**:
   - Rastrea los intentos de conexión a una lista de puertos cerrados.
   - Si una IP intenta conectarse más de 5 veces a un puerto cerrado en un intervalo de 10 segundos, se genera una alerta.

#### **Visualización en Tiempo Real**
- Los datos capturados se muestran en un gráfico de barras creado con `Matplotlib`.
- El gráfico se actualiza automáticamente con cada paquete capturado, proporcionando una representación visual clara del tráfico.

---

### Ejemplo de Uso
#### **1. Ejecutar el Script**
Ejecuta el script desde la terminal:
```bash
python ids.py
