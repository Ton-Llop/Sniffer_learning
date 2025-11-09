from scapy.all import sniff, PcapReader, wrpcap

class SnifferScapy:
    def __init__(self):
        self.captured_packets = []
    
    def start_capture(self, interface="any", filter=""):
        print("Captura de paquetes inicializada")
        try:
            self.captured_packets = sniff(iface=interface,
                                          filter=filter,
                                          prn=lambda x: x.summary(),
                                          store= True
                                        )
        except KeyboardInterrupt:
            print(f"Captura finalizada. Número de paquetes capturados: {len(self.captured_packets)}")

    def read_capture(self, pcapfile):
        try:
            self.captured_packets = [pkt for pkt in PcapReader(pcapfile)]
            print(f"Lectura del fichero {pcapfile} realizada correctamente")
        except Exception as e:
            print(f"Error al leer {pcapfile}")
    
    def filter_por_protocol(self, protocol):
        filtered_packets = [pkt for pkt in self.captured_packets if pkt.haslayer(protocol)]
        return filtered_packets
    
    def filter_por_text(self, text):
        """
        Filtra los paquetes buscando 'text' en el nombre de cualquier campo
        o en el valor de cualquier campo de cualquier capa.
        """
        filtered_packets = []

        for pkt in self.captured_packets:
            encontrado = False

            # Empezamos por la primera capa del paquete
            layer = pkt

            # Recorremos todas las capas del paquete: Ether / IP / TCP / etc.
            while layer:
                # Recorremos la descripción de los campos de esa capa
                for campo in layer.fields_desc:
                    nombre_campo = campo.name

                    # El valor del campo se obtiene del *packet/layer*, no del objeto Field ( mi fallo anterior)
                    valor_campo = layer.getfieldval(nombre_campo)

                    # Convertimos el valor a str para poder buscar texto dentro
                    valor_campo_str = str(valor_campo)

                    # Búsqueda: que el texto esté en el nombre del campo
                    # o en el valor del campo.
                    if text in nombre_campo or text in valor_campo_str:
                        filtered_packets.append(pkt)
                        encontrado = True
                        break  # salimos del for de campos

                if encontrado:
                    break  # salimos del while de capas para no duplicar el paquete

                # Pasamos a la siguiente capa (payload)
                layer = layer.payload

        return filtered_packets

    
    def print_packet_details(self, packets=None):
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            packet.show()
            print("---"*20)

    def export_to_pcap(self, packets, filename ="capture.pcap"):
        wrpcap(filename, packets)
        print("Paquetes guardados")