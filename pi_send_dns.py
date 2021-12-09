from scapy.all import DNS, DNSQR, IP, sr1, UDP, hexdump

example_com_query = b'\x43\xf0\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x41\x00\x01'

# dns_pkt = IP(dst="localhost")/UDP(dport=5555)/"test"
dns_pkt = IP(dst="192.168.178.52")/UDP(dport=53)/DNS(id=2, rd=1, qd=DNSQR(qname='analytics.163.com'))

print("Sending:")
dns_pkt.show()
print("Hexdump:")
hexdump(dns_pkt)

sr1(dns_pkt)
