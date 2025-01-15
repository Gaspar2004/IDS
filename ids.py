from scapy.all import sniff, TCP, IP, ICMP
from collections import Counter
import time

# Diccionario para rastrear actividad sospechosa
connection_tracker = Counter()

# Función para manejar los paquetes capturados
def packet_handler(packet):
    # Escaneo de puertos
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        connection_tracker[(src_ip, dst_port)] += 1

        # Detecta más de 10 conexiones hacia el mismo puerto en 5 segundos
        if connection_tracker[(src_ip, dst_port)] > 10:
            print(f"[ALERTA] Escaneo de puertos detectado desde {src_ip} hacia el puerto {dst_port}")
    
    # Tráfico ICMP excesivo
    elif packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        print(f"[ALERTA] Actividad ICMP sospechosa detectada desde {src_ip}")

# Capturar tráfico
print("Iniciando el IDS...")
sniff(prn=packet_handler, store=0, timeout=60)
