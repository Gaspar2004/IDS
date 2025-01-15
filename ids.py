from scapy.all import sniff, TCP, IP, ICMP
from collections import Counter
import logging
import time
import os
import logging
from scapy.all import sniff, TCP, IP, ICMP
from collections import Counter
import time

# Crear el directorio logs si no existe
if not os.path.exists("logs"):
    os.makedirs("logs")

# Configuración de logging
logging.basicConfig(
    filename="logs/alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Configuración de umbrales
THRESHOLD_PACKET_RATE = 50
THRESHOLD_PORT_ATTEMPTS = 5
MONITOR_INTERVAL = 5

# Rastreadores
packet_rate_tracker = Counter()
time_tracker = {}
closed_port_attempts = Counter()
closed_ports = [22, 23, 8080, 3306]

def packet_handler(packet):
    current_time = time.time()

    # Detección de alta tasa de paquetes
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_rate_tracker[src_ip] += 1

        if src_ip not in time_tracker:
            time_tracker[src_ip] = current_time

        elapsed_time = current_time - time_tracker[src_ip]
        if elapsed_time > MONITOR_INTERVAL:
            packet_rate = packet_rate_tracker[src_ip] / elapsed_time
            if packet_rate > THRESHOLD_PACKET_RATE:
                alert_msg = f"[ALERTA] Alta tasa de paquetes desde {src_ip}: {packet_rate:.2f} paquetes/seg"
                print(alert_msg)
                logging.info(alert_msg)
            packet_rate_tracker[src_ip] = 0
            time_tracker[src_ip] = current_time

    # Detección de intentos hacia puertos cerrados
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if dst_port in closed_ports:
            closed_port_attempts[(src_ip, dst_port)] += 1
            if closed_port_attempts[(src_ip, dst_port)] > THRESHOLD_PORT_ATTEMPTS:
                alert_msg = f"[ALERTA] Intentos hacia puerto cerrado {dst_port} desde {src_ip}"
                print(alert_msg)
                logging.info(alert_msg)
                closed_port_attempts[(src_ip, dst_port)] = 0

# Iniciar captura de paquetes
print("Iniciando IDS...")
sniff(prn=packet_handler, store=0)
