from scapy.all import PcapReader, IP, TCP, UDP, ICMP


class NetworkPacket:
    def __init__(
        self,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        length,
        timestamp_us,
        tcp_flags=0,
        ip_header_len=0,
        tcp_header_len=0
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.timestamp_us = timestamp_us
        self.tcp_flags = tcp_flags
        self.ip_header_len = ip_header_len
        self.tcp_header_len = tcp_header_len


def read_pcap(pcap_path):
    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            if IP not in pkt:
                continue

            ip = pkt[IP]
            proto = ip.proto
            src_ip = ip.src
            dst_ip = ip.dst
            length = len(pkt)
            timestamp_us = int(pkt.time * 1_000_000)

            src_port = 0
            dst_port = 0
            tcp_flags = 0
            tcp_hlen = 0

            if TCP in pkt:
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = int(tcp.flags)
                tcp_hlen = tcp.dataofs * 4

            elif UDP in pkt:
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport

            elif ICMP in pkt:
                proto = 1

            yield NetworkPacket(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                length=length,
                timestamp_us=timestamp_us,
                tcp_flags=tcp_flags,
                ip_header_len=ip.ihl * 4,
                tcp_header_len=tcp_hlen
            )
