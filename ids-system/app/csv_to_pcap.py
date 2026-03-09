import csv
from scapy.all import IP, TCP, UDP, wrpcap
'''
def csv_to_pcap(input_csv, output_pcap):
    packets = []

    with open(input_csv, mode='r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # 1. Extract fields from CSV row
                sip = row['src_ip']
                dip = row['dst_ip']
                sport = int(row['src_port'])
                dport = int(row['dst_port'])
                proto = row['protocol'].upper()

                # 2. Build the IP layer
                pkt = IP(src=sip, dst=dip)

                # 3. Add transport layer based on protocol
                if proto == 'TCP':
                    pkt = pkt / TCP(sport=sport, dport=dport)
                elif proto == 'UDP':
                    pkt = pkt / UDP(sport=sport, dport=dport)
                else:
                    # Skip or handle other protocols (e.g., ICMP)
                    continue

                packets.append(pkt)
            except Exception as e:
                print(f"Skipping row due to error: {e}")

    # 4. Save all packets to a PCAP file
    if packets:
        wrpcap(output_pcap, packets)
        print(f"Successfully converted {len(packets)} packets to {output_pcap}")
    else:
        print("No valid packets found to convert.")

#Usage,
csv_to_pcap('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', 'output.pcap')'''

with open('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', mode='r', encoding='utf-8-sig') as f: # utf-8-sig handles BOM automatically
    reader = csv.DictReader(f)
    print("Found headers:", reader.fieldnames)