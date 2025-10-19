import dpkt
import socket
import struct
from collections import defaultdict

SENDER_IP = '130.245.145.12'
RECEIVER_IP = '128.208.2.198'

def inet_to_str(inet):
    return socket.inet_ntop(socket.AF_INET, inet)

def canonical_flow_id(srcip, srcport, dstip, dstport):
    a, b = (srcip, srcport), (dstip, dstport)
    return (a, b) if a <= b else (b, a)

def parse_pcap(filename):
    flows = {}
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            # --- Ethernet header ---
            if len(buf) < 14:
                continue
            eth_header = struct.unpack('!6s6sH', buf[:14])
            eth_type = eth_header[2]
            if eth_type != 0x0800:  # not IPv4
                continue

            # --- IP header ---
            ip_header_start = 14
            if len(buf) < ip_header_start + 20:
                continue
            ip_header = buf[ip_header_start:]
            ver_ihl = ip_header[0]
            version = ver_ihl >> 4
            ihl = (ver_ihl & 0xF) * 4
            if version != 4:
                continue
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header[:20])
            total_len = iph[2]
            proto = iph[6]
            srcip = inet_to_str(iph[8])
            dstip = inet_to_str(iph[9])
            if proto != 6:  # TCP
                continue

            # --- TCP header ---
            tcp_start = ip_header_start + ihl
            tcp_seg = buf[tcp_start:]
            if len(tcp_seg) < 20:
                continue
            tcph = struct.unpack('!HHLLHHHH', tcp_seg[:20])
            srcport, dstport = tcph[0], tcph[1]
            seq, ack = tcph[2], tcph[3]
            data_offset = ((tcph[4] >> 12) & 0xF) * 4
            flags = tcph[4] & 0x3F  # lower 6 bits
            win = tcph[5]

            # --- TCP payload ---
            tcp_data = tcp_seg[data_offset:]
            
            fid = canonical_flow_id(srcip, srcport, dstip, dstport)
            flows.setdefault(fid, {'packets': []})['packets'].append({
                'ts': ts,
                'srcip': srcip,
                'dstip': dstip,
                'srcport': srcport,
                'dstport': dstport,
                'seq': seq,
                'ack': ack,
                'flags': flags,
                'win': win,
                'data': tcp_data
            })

    return flows


def detect_sender_flows(all_flows):
    sender_flows = {}
    for fid, flow in all_flows.items():
        for p in flow['packets']:
            if p['srcip'] == SENDER_IP and (p['flags'] & 0x02) and not (p['flags'] & 0x10):  # SYN only
                sender_flows[fid] = flow
                break
    return sender_flows


def analyze_flow(flow):
    pkts = sorted(flow['packets'], key=lambda x: x['ts'])
    snd = [p for p in pkts if p['srcip'] == SENDER_IP]
    rcv = [p for p in pkts if p['srcip'] == RECEIVER_IP]
    f = snd[0]

    print("\n" + "=" * 60)
    print(f"Flow: {f['srcip']}:{f['srcport']} → {f['dstip']}:{f['dstport']}  |  Packets: {len(pkts)}")
    print("-" * 60)

    # (b) First two sender→receiver transmissions
    print("First 2 Transmissions (sender → receiver):")
    for i, p in enumerate(snd[:2], 1):
        print(f"   [{i}] seq={p['seq']:<12} ack={p['ack']:<12} win={p['win']}")
    print("-" * 60)

    # (c) Throughput
    data_bytes = sum(len(p['data']) for p in snd if len(p['data']))
    dur = snd[-1]['ts'] - snd[0]['ts']
    thr = (data_bytes * 8) / (dur * 1e6) if dur > 0 else 0
    print(f"Throughput: {data_bytes} bytes in {dur:.3f}s  →  {thr:.3f} Mbps")
    print("-" * 60)

    # (d) Congestion Window Estimation
    events = []
    for p in snd:
        if len(p['data']):
            events.append(('send', p['seq'], len(p['data']), p['ts']))
    for p in rcv:
        events.append(('ack', p['ack'], 0, p['ts']))
    events.sort(key=lambda x: x[3])

    inflight, cwnd = {}, []
    for ev, seq, size, ts in events:
        if ev == 'send':
            inflight[seq] = size
        else:
            inflight = {k: v for k, v in inflight.items() if k + v > seq}
            cwnd.append(sum(inflight.values()))

    print("Estimated cwnd growth (bytes per RTT):")
    if cwnd:
        for i, c in enumerate(cwnd[:3], 1):
            print(f"   cwnd[{i}] ≈ {c:>6} bytes  ({c/1460:.2f} MSS)")
    else:
        print("   No ACK-based cwnd samples observed.")
    print("-" * 60)

    # (e) Retransmissions
    ack_counts = defaultdict(int)
    for p in rcv:
        ack_counts[p['ack']] += 1

    seq_seen, ret_dup, ret_to, ret_other = {}, 0, 0, 0
    for p in snd:
        if not len(p['data']):
            continue
        if p['seq'] in seq_seen:
            dupacks = sum(1 for a, c in ack_counts.items() if a < p['seq'] and c >= 3)
            if dupacks:
                ret_dup += 1
            elif p['ts'] - seq_seen[p['seq']] > 1.0:
                ret_to += 1
            else:
                ret_other += 1
        seq_seen[p['seq']] = p['ts']

    print("Retransmission Summary:")
    print(f"   • Triple-duplicate ACKs : {ret_dup}")
    print(f"   • Timeout Retransmits   : {ret_to}")
    print(f"   • Other Retransmits     : {ret_other}")


def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python analysis_pcap_tcp_manual.py <pcap file>")
        sys.exit(1)

    flows = parse_pcap(sys.argv[1])
    sender_flows = detect_sender_flows(flows)
    for f in sender_flows.values():
        analyze_flow(f)


if __name__ == "__main__":
    main()
