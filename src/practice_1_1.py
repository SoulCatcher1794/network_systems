#We need to import the scapy library, in this case everything (*)
from scapy.all import *

#Read in a trace of packets from a file
pkts = rdpcap("intro-wireshark-trace1.pcap")