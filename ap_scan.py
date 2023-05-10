'''
Scans for networks around you
'''

from scapy.all import Dot11, Dot11Beacon, Dot11Elt,sniff
from threading import Thread
import pandas
import time
import os

ap_list = []
# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

# def change_channel():

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
        tup = (ssid,bssid)
        if tup not in ap_list:
            ap_list.append(tup)

def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.5)




def scanner(interface):
    os.system("ifconfig " + str(interface) + " down")
    os.system("iwconfig " + str(interface) + " mode monitor")
    os.system("ifconfig " + str(interface) + " up")
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start sniffing
    sniff(prn=callback, iface=interface, timeout = 10)
    return ap_list

if __name__ == "__main__":
    scanner("wlx000e2ea2551d")
