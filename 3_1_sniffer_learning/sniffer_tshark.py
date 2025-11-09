import pyshark
from scapy.all import wrpcap, Ether

class SnifferTshark:

    def __init__(self):
        self.capture = None
        self.captured_packets = []

    def start_capture(self, interface="any", display_filter=""):
        """
        Inicia la captura de paquetes usando pyshark.LiveCapture.
        display_filter usa la sintaxis de filtros de Wireshark, no BPF.
        """
        self.capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter,
            # use_json=True,  # déjalo comentado si te da error de parámetro
            include_raw=True
        )
        try:
            print("[+] Captura de paquetes iniciada (Ctrl+C para detener)")
            for packet in self.capture.sniff_continuously():
                self.captured_packets.append(packet)
        except (KeyboardInterrupt, EOFError):
            print(f"[+] Captura finaliza. Paquetes capturados: {len(self.captured_packets)}")
        finally:
            if self.capture is not None:
                try:
                    self.capture.close()
                except Exception:
                    pass

    def read_capture(self, pcapfile, display_filter=""):
        try:
            self.capture = pyshark.FileCapture(
                input_file =pcapfile,
                display_filter = display_filter,
                keep_packets=False,
                use_json=True,
                include_raw=True
            )
            self.captured_packets = [pkt for pkt in self.capture]
            print(f"Lectura de {pcapfile} realizada")
        except Exception as e:
            print(f"Error al leer {pcapfile}")



    def filtrar_por_protocolo(self, protocol):
        """
        Devuelve los paquetes que contienen una capa con el nombre indicado.
        Ejemplo: protocol="TCP", "IP", "HTTP"
        """
        return [pkt for pkt in self.captured_packets if protocol in pkt]

    def filtrar_por_texto(self, text):
        """
        Filtra los paquetes capturados buscando una coincidencia de texto en cualquier capa.
        """
        filtered_packet_text = []

        for pkt in self.captured_packets:
            encontrado = False
            for layer in pkt.layers:
                try:
                    for field_line in layer._get_all_field_lines():
                        if text in field_line:
                            filtered_packet_text.append(pkt)
                            encontrado = True
                            break
                except AttributeError:
                    continue
                if encontrado:
                    break

        return filtered_packet_text

    def exportar_a_pcap(self, packets, filename='capture.pcap'):
        """
        Exporta los paquetes a un archivo PCAP usando Scapy.
        """
        scapy_packets = []
        for pkt in packets:
            raw = pkt.get_raw_packet()
            if isinstance(raw, bytes):
                scapy_packets.append(Ether(raw))

        wrpcap(filename, scapy_packets)
        print(f"[+] Packets guardados en {filename}")

    def print_packet_detail(self, packets=None):
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            print(packet)
            print("---" * 20)
