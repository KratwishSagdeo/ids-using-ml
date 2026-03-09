INACTIVE_TIMEOUT_US = 60 * 1_000_000
ACTIVE_TIMEOUT_US = 300 * 1_000_000


class Flow:
    def __init__(self, key, start_us):
        self.key = key
        self.start_us = start_us
        self.last_us = start_us
        self.forward = []
        self.backward = []

    def add_packet(self, packet, forward=True):
        self.last_us = packet.timestamp_us
        if forward:
            self.forward.append(packet)
        else:
            self.backward.append(packet)

    def is_expired(self, now_us):
        if now_us - self.last_us > INACTIVE_TIMEOUT_US:
            return True
        if self.last_us - self.start_us > ACTIVE_TIMEOUT_US:
            return True
        return False


class FlowAggregator:
    def __init__(self):
        self.flows = {}

    def _make_key(self, packet):
        a = (packet.src_ip, packet.src_port)
        b = (packet.dst_ip, packet.dst_port)
        return tuple(sorted([a, b])) + (packet.protocol,)

    def add_packet(self, packet):
        key = self._make_key(packet)

        if key not in self.flows:
            self.flows[key] = Flow(key, packet.timestamp_us)

        flow = self.flows[key]
        forward = (packet.src_ip, packet.src_port) == key[0]
        flow.add_packet(packet, forward)

    def expire(self, now_us):
        expired = []
        for key in list(self.flows.keys()):
            if self.flows[key].is_expired(now_us):
                expired.append(self.flows.pop(key))
        return expired
