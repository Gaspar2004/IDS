import matplotlib.pyplot as plt
from collections import defaultdict
from scapy.all import sniff, IP
import time

# Diccionario para rastrear tráfico por IP
traffic_data = defaultdict(int)

# Configurar la ventana gráfica
plt.ion()  # Habilitar modo interactivo
fig, ax = plt.subplots()

def update_graph():
    """Actualizar el gráfico con los datos actuales."""
    ax.clear()
    ax.bar(traffic_data.keys(), traffic_data.values(), color='blue')
    ax.set_xlabel("Direcciones IP")
    ax.set_ylabel("Número de Paquetes")
    ax.set_title("Tráfico por Dirección IP")
    plt.xticks(rotation=45) #configuracion del teto
    plt.pause(0.01)

def packet_handler(packet):
    """Procesar paquetes capturados."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        traffic_data[src_ip] += 1

        # actualizar gráfico cada vez que se captura un paquete
        update_graph()

# Iniciar captura de paquetes
print("Capturando tráfico... Cierra la ventana del gráfico para detener.")
sniff(prn=packet_handler, store=0)
