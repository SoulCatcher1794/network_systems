from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

#packet = Ether()/IP(dst='8.8.8.8')/TCP(dport=53,flags='S')

pktlist = []


srcIP = "192.168.10.10"
destIP = "192.168.10.20"

srcEth='12:12:12:12:12:12'
destEth='22:22:22:22:22:22'

ipE=Ether(src=srcEth, dst=destEth)/IP(src=srcIP,dst=destIP)
ipI=Ether(src=destEth, dst=srcEth)/IP(src=destIP,dst=srcIP)

srcPort = 55555
destPort = 80

srcSeq = 1000
destSeq = 9000

time = 100.0

# SYN
p = ipE/ TCP(sport=srcPort,dport=destPort,flags='S',seq=srcSeq)
p.time = time
time = time + 1.0
pktlist.append(p)


srcSeq = srcSeq + 1

# SYNACK
p = ipI / TCP(sport=destPort, dport=srcPort, flags='SA', seq=destSeq,  ack=srcSeq)
p.time = time
time = time + 1.0
pktlist.append(p)

destSeq = destSeq + 1


# ACK 
p = ipE/ TCP(sport=srcPort, dport=destPort, flags='A', seq=srcSeq,  ack=destSeq) 
p.time = time
time = time + 1.0
pktlist.append(p)


# Connection established - now send data from dest to source 


for inflight in [1, 2, 4, 8]:
    ackSeq = destSeq
    for i in range(0,inflight):
        p = ipI / TCP(sport=destPort, dport=srcPort, flags='', seq=destSeq,  ack=srcSeq) / Raw("ABCDE") 
        p.time = time
        time = time + 1.0
        pktlist.append(p)
        destSeq = destSeq + 5

    for i in range(0,inflight):
        ackSeq = ackSeq + 5
        p = ipE / TCP(sport=srcPort, dport=destPort, flags='A', seq=srcSeq,  ack=ackSeq)
        p.time = time
        time = time + 1.0
        pktlist.append(p)


# Src to Dest FIN


# Dest to Src Fin Ack 
# Src to Dest Ack


# Fin
p = ipE/ TCP(sport=srcPort,dport=destPort,flags='F',seq=srcSeq)
p.time = time
time = time + 1.0
pktlist.append(p)
srcSeq = srcSeq + 1

# fin ACK
p = ipI / TCP(sport=destPort, dport=srcPort, flags='FA', seq=destSeq,  ack=srcSeq)
p.time = time
time = time + 1.0
pktlist.append(p)
destSeq = destSeq + 1


# ACK 
p = ipE/ TCP(sport=srcPort, dport=destPort, flags='A', seq=srcSeq,  ack=destSeq) 
p.time = time
time = time + 1.0
pktlist.append(p)



wrpcap("simple-tcp-session.pcap",pktlist)
