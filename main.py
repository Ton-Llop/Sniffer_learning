from sniffer_tshark import SnifferTshark

if __name__ == "__main__":
    sniffer = SnifferTshark()
    sniffer.read_capture('/home/kali/Desktop/python_hacking/seccion3/3_1_sniffer_tshark/captura.pcapng')
    packets = sniffer.filtrar_por_protocolo("TCP")
    #packets = sniffer.filtrar_por_texto("phrack")
    #sniffer.exportar_a_pcap(packets)
    sniffer.print_packet_detail(packets)