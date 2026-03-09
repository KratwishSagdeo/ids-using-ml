from pcap_processing.realtime_engine import start_realtime_ids

# Loopback (testing)
# start_realtime_ids(interface=r"\Device\NPF_Loopback")

# Real interface (production / real demo)
start_realtime_ids(
    interface=r"\Device\NPF_{6B5FD7A6-4DE2-4800-8F76-D2761FCE7441}"
)
