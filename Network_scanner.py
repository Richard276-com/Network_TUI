from scapy.all import ARP, Ether, srp
from scapy.all import wrpcap, rdpcap
from datetime import datetime

target_ip = "10.192.3.24/24" #Change this to your target IP range

packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip)
answered, _=srp(packet, timeout=5, verbose=0)

print(f"Scanning for devices on the network: {target_ip}")
print("=" * 50)

for sent, received in answered:
    print(f"[IP]: {received.psrc} - [MAC]: {received.hwsrc}")

class PacketSaver:
    def __init__(self):
        self.packets = []
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.filename = f"capture_{timestamp}.pcap"


    def add_packet(self, packet):
        self.packets.append(packet)

    def save_packets(self, filename=None):
        if filename is None:
            filename = self.filename
        wrpcap(filename, self.packets)
        return filename
    
    def load(self, filename):
        self.packets = rdpcap(filename)
        return self.packets