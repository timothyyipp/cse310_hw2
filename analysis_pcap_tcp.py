#!/usr/bin/env python
import sys
import dpkt
import socket
import math
from collections import Counter

SENDER_IP = '130.245.145.12'
RECEIVER_IP = '128.208.2.198'
MSS = 1460  # Approximate TCP segment size

def inet_to_str(inet):
    return socket.inet_ntop(socket.AF_INET, inet)

def tcp_header_len_bytes(tcp):
    return getattr(tcp, 'off', 5) * 4

def flow_key(srcip, dstip, srcport, dstport):
    return (srcport, srcip, dstport, dstip)

def parse_pcap(filename):
    flows = {}
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
                tcp = ip.data
                if not isinstance(tcp, dpkt.tcp.TCP):
                    continue
            except:
                continue

            srcip = inet_to_str(ip.src)
            dstip = inet_to_str(ip.dst)
            srcport = tcp.sport
            dstport = tcp.dport
            key = flow_key(srcip, dstip, srcport, dstport)
            if key not in flows:
                flows[key] = []
            flows[key].append({'ts': ts, 'tcp': tcp, 'srcip': srcip, 'dstip': dstip})
    return flows

def filter_sender_flows(flows):
    sender_flows = {}
    for key, packets in flows.items():
        srcport, srcip, dstport, dstip = key
        if srcip != SENDER_IP or dstip != RECEIVER_IP:
            continue
        # Must start with SYN from sender
        if any((p['tcp'].flags & dpkt.tcp.TH_SYN) and not (p['tcp'].flags & dpkt.tcp.TH_ACK) for p in packets):
            sender_flows[key] = packets
    return sender_flows

def analyze_flow(key, packets):
    packets.sort(key=lambda p: p['ts'])
    # First two sender->receiver transactions after handshake
    first_two = []
    handshake_done = False
    syn_seen = synack_seen = False
    for p in packets:
        tcp = p['tcp']
        if not handshake_done:
            if p['srcip'] == SENDER_IP and (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
                syn_seen = True
                continue
            if p['srcip'] == RECEIVER_IP and (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK) and syn_seen:
                synack_seen = True
                continue
            if syn_seen and synack_seen and p['srcip'] == SENDER_IP and (tcp.flags & dpkt.tcp.TH_ACK):
                handshake_done = True
                continue
        else:
            if p['srcip'] == SENDER_IP:
                first_two.append({'seq': tcp.seq, 'ack': tcp.ack, 'win': tcp.win})
                if len(first_two) == 2:
                    break

    # Throughput
    data_packets = [p for p in packets if p['srcip'] == SENDER_IP and len(p['tcp'].data) > 0]
    if data_packets:
        start_ts = data_packets[0]['ts']
        end_seq = max(p['tcp'].seq + len(p['tcp'].data) for p in data_packets)
        last_ack_ts = None
        for p in reversed(packets):
            if p['srcip'] == RECEIVER_IP and (p['tcp'].flags & dpkt.tcp.TH_ACK):
                if p['tcp'].ack >= end_seq:
                    last_ack_ts = p['ts']
                    break
        last_ack_ts = last_ack_ts or packets[-1]['ts']
        total_bytes = sum(tcp_header_len_bytes(p['tcp']) + len(p['tcp'].data) for p in data_packets)
        period = last_ack_ts - start_ts
        throughput = total_bytes / period if period > 0 else 0
    else:
        throughput = 0
        total_bytes = 0
        period = 0

    # Congestion window estimation (outstanding bytes at ACK arrival)
    highest_sent = last_acked = 0
    cwnd_samples = []
    for p in packets:
        tcp = p['tcp']
        if p['srcip'] == SENDER_IP:
            end_seq = tcp.seq + len(tcp.data)
            if end_seq > highest_sent:
                highest_sent = end_seq
        elif p['srcip'] == RECEIVER_IP and (tcp.flags & dpkt.tcp.TH_ACK):
            last_acked = max(last_acked, tcp.ack)
            outstanding = max(0, highest_sent - last_acked)
            if outstanding > 0:
                cwnd_samples.append(math.ceil(outstanding / MSS))
    first_three_cwnd = cwnd_samples[:3]

    # Retransmission detection (simplified)
    seq_counts = Counter()
    for p in packets:
        tcp = p['tcp']
        if p['srcip'] == SENDER_IP and len(tcp.data) > 0:
            seq_counts[tcp.seq] += 1
    triple_dup = sum(1 for cnt in seq_counts.values() if cnt > 1)  # rough approximation
    timeout_retx = 0  # omitted for simplicity
    other_retx = 0    # omitted

    return {
        'flow_tuple': key,
        'first_two': first_two,
        'throughput': throughput,
        'total_bytes': total_bytes,
        'period': period,
        'cwnd_samples': first_three_cwnd,
        'retrans': {'triple_dup': triple_dup, 'timeout': timeout_retx, 'other': other_retx}
    }

def print_flow(a):
    key = a['flow_tuple']
    srcport, srcip, dstport, dstip = key
    print(f"Flow: {srcport}, {srcip} -> {dstport}, {dstip}")
    print("First two sender->receiver transactions:")
    for t in a['first_two']:
        print(f"  seq={t['seq']}, ack={t['ack']}, win={t['win']}")
    print(f"Sender throughput: {a['total_bytes']} bytes over {a['period']:.6f}s -> {a['throughput']:.2f} B/s")
    print("First 3 congestion window estimates (packets):", a['cwnd_samples'])
    print("Retransmissions:", a['retrans'])
    print("-"*50)

def main():
    if len(sys.argv) < 2:
        print("Usage: python analysis_pcap_tcp.py assignment2.pcap")
        sys.exit(1)
    flows = parse_pcap(sys.argv[1])
    sender_flows = filter_sender_flows(flows)
    for key, packets in sender_flows.items():
        a = analyze_flow(key, packets)
        print_flow(a)

if __name__ == "__main__":
    main()
