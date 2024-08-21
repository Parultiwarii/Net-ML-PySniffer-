import scapy.all as scapy
from scapy.layers import http

class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.sniffing = False

    def start_sniffing(self):
        self.sniffing = True
        self.packets = []
        scapy.sniff(prn=self.process_packet)

    def stop_sniffing(self):
        self.sniffing = False

    def process_packet(self, packet):
        if self.sniffing:
            if packet.haslayer(http.HTTPRequest):
                host = packet[http.HTTPRequest].Host.decode('utf-8')
                path = packet[http.HTTPRequest].Path.decode('utf-8')
                sport = packet.sport
                source_ip = packet[scapy.IP].src
                dport = packet.dport
                dest_ip = packet[scapy.IP].dst
                payloads = packet.payload
                raw = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else None
                length = len(packet)
                proto = packet[scapy.IP].proto
                ttl = packet[scapy.IP].ttl
                flags = packet[scapy.IP].flags
                window = packet[scapy.IP].window
                options = packet[scapy.IP].options

                self.packets.append({
                    "host": host,
                    "path": path,
                    "sport": sport,
                    "source_ip": source_ip,
                    "dport": dport,
                    "dest_ip": dest_ip,
                    "payloads": payloads,
                    "raw": raw,
                    "length": length,
                    "proto": proto,
                    "ttl": ttl,
                    "flags": flags,
                    "window": window,
                    "options": options
                })

    def extract_features(self):
        return self.packets
