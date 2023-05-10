'''
Finds the connected users
'''
import os
from scapy.all import Dot11,sniff


def find_users(input_interface,bssid):
    interface = input_interface 

    ### deired ap bssid
    ap_bssid = bssid
    clients = set()

    def handle_packet(packet):
        if(packet.addr1 == ap_bssid):
            if packet.addr2 not in clients:
                    clients.add(packet.addr2)
                    print("client connected : ", packet.addr2)

    sniff(iface = interface, prn = handle_packet)

# Monitor mod Interface and bssid of desired wlan 
if __name__ == "__main__":
    find_users("wlx08beac0a1057","a2:b5:3c:89:b8:d6")
