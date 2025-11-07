from sniffer_scapy import SnifferScapy

if __name__ == "__main__":
    sniffer = SnifferScapy()
    sniffer.start_capture(interface ="eth0")

    #sniffer.read_capture("/home/kali/Desktop/python_hacking/seccion3/3_1_sniffer_tshark/3._2_scapy_learning/captura.pcapng")
    packets = sniffer.filter_por_text("phrack")
    sniffer.print_packet_details(packets)

    sniffer.export_to_pcap(packets, "phrack_packets.pcap")
