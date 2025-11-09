import pyshark
import binascii

PCAP_FILE = "/home/kali/Desktop/python_hacking/seccion3/3_1_sniffer_tshark/3._3_sockets_learning/captura.pcapng"
PUERTO_APP = 12345

def extraer_payload(packet):
    """
    Devuelve el payload TCP del paquete como bytes, o None si no hay.
    """
    try:
        # Algunos paquetes no tienen campo 'data', así que lo hacemos con cuidado
        if hasattr(packet, 'data'):
            # packet.data.data suele venir como hex string, ej: '686f6c61'
            hex_str = packet.data.data.replace(':', '')  # por si viene con dos puntos
            return binascii.unhexlify(hex_str)
    except Exception as e:
        # Por si algún paquete raro rompe el parseo
        print(f"Error extrayendo payload: {e}")
    return None

def main():
    # Carga el pcap filtrando por TCP en tu puerto
    cap = pyshark.FileCapture(
        PCAP_FILE,
        display_filter=f"tcp.port == {PUERTO_APP}"
    )

    for i, pkt in enumerate(cap, start =1):
        payload_bytes = extraer_payload(pkt)
        if payload_bytes:
                # Solo printeo los que tienen  payload(mensajes)
                print(f"\n--- Paquete #{i} ---")
                print("Resumen:", pkt.highest_layer, pkt.ip.src, "->", pkt.ip.dst)
                print("Puertos:", pkt.tcp.srcport, "->", pkt.tcp.dstport)
                print("Payload (bytes):", payload_bytes)
                try:
                    texto = payload_bytes.decode('utf-8', errors='replace')
                    print("Payload (texto):", repr(texto))
                except UnicodeDecodeError:
                    print("No se pudo decodificar como UTF-8.")
    


    cap.close()

if __name__ == "__main__":
    main()
