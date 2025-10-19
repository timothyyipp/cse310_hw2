import dpkt
import socket
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
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data
            except Exception:
                continue
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(tcp, dpkt.tcp.TCP):
                continue
            srcip, dstip = inet_to_str(ip.src), inet_to_str(ip.dst)
            fid = canonical_flow_id(srcip, tcp.sport, dstip, tcp.dport)
            flows.setdefault(fid, {'packets': []})['packets'].append({
                'ts': ts, 'ip': ip, 'tcp': tcp,
                'srcip': srcip, 'dstip': dstip,
                'srcport': tcp.sport, 'dstport': tcp.dport
            })
    return flows

def detect_sender_flows(all_flows):
    sender_flows = {}
    for fid, flow in all_flows.items():
        for p in flow['packets']:
            t = p['tcp']
            if p['srcip'] == SENDER_IP and (t.flags & dpkt.tcp.TH_SYN) and not (t.flags & dpkt.tcp.TH_ACK):
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

    # (b) First two sender→receiver transactions
    print("First 2 Transmissions (sender → receiver):")
    for i, p in enumerate(snd[:2], 1):
        t = p['tcp']
        print(f"   [{i}] seq={t.seq:<12} ack={t.ack:<12} win={t.win}")
    print("-" * 60)

    # (c) Throughput
    data_bytes = sum(len(p['tcp'].data) for p in snd if len(p['tcp'].data))
    dur = snd[-1]['ts'] - snd[0]['ts']
    thr = (data_bytes * 8) / (dur * 1e6) if dur > 0 else 0
    print(f"Throughput: {data_bytes} bytes in {dur:.3f}s  →  {thr:.3f} Mbps")
    print("-" * 60)

    # (d) Congestion Window Estimation
    events = []
    for p in snd:
        if len(p['tcp'].data):
            events.append(('send', p['tcp'].seq, len(p['tcp'].data), p['ts']))
    for p in rcv:
        events.append(('ack', p['tcp'].ack, 0, p['ts']))
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
    for p in rcv: ack_counts[p['tcp'].ack] += 1
    seq_seen, ret_dup, ret_to, ret_other = {}, 0, 0, 0
    for p in snd:
        t = p['tcp']
        if not len(t.data): continue
        if t.seq in seq_seen:
            dupacks = sum(1 for a, c in ack_counts.items() if a < t.seq and c >= 3)
            if dupacks: ret_dup += 1
            elif p['ts'] - seq_seen[t.seq] > 1.0: ret_to += 1
            else: ret_other += 1
        seq_seen[t.seq] = p['ts']

    print("Retransmission Summary:")
    print(f"   • Triple-duplicate ACKs : {ret_dup}")
    print(f"   • Timeout Retransmits   : {ret_to}")
    print(f"   • Other Retransmits     : {ret_other}")

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python analysis_pcap_tcp.py <pcap file>")
        sys.exit(1)
    flows = parse_pcap(sys.argv[1])
    sender_flows = detect_sender_flows(flows)
    for f in sender_flows.values():
        analyze_flow(f)

if __name__ == "__main__":
    main()
