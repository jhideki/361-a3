import struct
import socket
from collections import defaultdict
import statistics


def parse_pcap(file_path):
    with open(file_path, "rb") as f:
        pcap_global_header = f.read(24)  # Skip global header

        packets = []
        while True:
            packet_header = f.read(16)  # Read the packet header
            if not packet_header:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("=IIII", packet_header)
            packet_data = f.read(incl_len)
            packets.append((ts_sec, ts_usec, packet_data))

    return packets


def parse_ip_header(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # Header length in bytes
    total_length = ip_header[2]
    flags_offset = ip_header[4]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    frag_offset = (flags_offset & 0x1FFF) * 8
    mf_flag = (flags_offset & 0x2000) >> 13

    return {
        "ihl": ihl,
        "total_length": total_length,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "frag_offset": frag_offset,
        "mf_flag": mf_flag,
    }


def parse_udp_packet(data):
    UDP_HEADER_LENGTH = 8  # UDP header is always 8 bytes long

    if len(data) < UDP_HEADER_LENGTH:
        raise ValueError("Data is too short to contain a valid UDP header")

    # Unpack UDP header fields
    udp_header = struct.unpack("!HHHH", data[:UDP_HEADER_LENGTH])
    src_port = udp_header[0]
    dst_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]

    # Extract UDP payload
    udp_payload = data[UDP_HEADER_LENGTH:]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "udp_payload": udp_payload,
    }


def analyze_traceroute(pcap_file):
    packets = parse_pcap(pcap_file)

    source_ip = None
    dest_ip = None
    intermediate_ips = set()
    protocol_set = set()
    fragment_offsets = []
    rtt_data = defaultdict(list)

    for ts_sec, ts_usec, packet_data in packets:
        # Ethernet header is 14 bytes; skip it
        ip_data = packet_data[14:]
        ip_header = parse_ip_header(ip_data)
        proto = ip_header["protocol"]
        if proto == 17:
            udp_start = 14 + ip_header["ihl"]
            udp_data = parse_udp_packet(packet_data[udp_start:])

            if udp_data["dst_port"] == 53:
                continue
            else:
                if source_ip is None:
                    source_ip = ip_header["src_ip"]
                if dest_ip is None:
                    dest_ip = ip_header["dst_ip"]
        elif proto == 1:
            if (
                ip_header["src_ip"] not in intermediate_ips
                and ip_header["src_ip"] != source_ip
                and ip_header["src_ip"] != dest_ip
            ):
                intermediate_ips.add(ip_header["src_ip"])
        else:
            continue

        if source_ip is None:
            source_ip = ip_header["src_ip"]
        if dest_ip is None:
            ultimate_destination_ip = ip_header["dst_ip"]

        protocol_set.add(ip_header["protocol"])

        if ip_header["frag_offset"] > 0 or ip_header["mf_flag"] == 1:
            fragment_offsets.append(ip_header["frag_offset"])

        # Simulate RTT using timestamps
        rtt_key = (
            "ultimate"
            if ip_header["dst_ip"] == dest_ip
            else f"router-{ip_header['dst_ip']}"
        )
        rtt_data[rtt_key].append(ts_sec + ts_usec / 1e6)

    print(f"The IP address of the source node: {source_ip}")
    print(f"The IP address of ultimate destination node: {dest_ip}")
    print("The IP addresses of the intermediate destination nodes:")
    for i, ip in enumerate(intermediate_ips):
        print(f"router {i}: {ip}")

    print("\nThe values in the protocol field of IP headers:")
    for proto in sorted(protocol_set):
        print(f"{proto}: {'ICMP' if proto == 1 else 'UDP' if proto == 17 else 'Other'}")

    num_fragments = len(fragment_offsets)
    last_fragment_offset = max(fragment_offsets) if fragment_offsets else 0
    print(
        f"\nThe number of fragments created from the original datagram is: {num_fragments}"
    )
    print(f"The offset of the last fragment is: {last_fragment_offset}")

    print("\nRTT statistics:")
    for key, times in rtt_data.items():
        if len(times) > 1:
            diffs = [times[i + 1] - times[i] for i in range(len(times) - 1)]
            avg_rtt = statistics.mean(diffs)
            std_rtt = statistics.stdev(diffs)
            print(
                f"The avg RTT to {key} is: {avg_rtt:.2f} ms, the s.d. is: {std_rtt:.2f} ms"
            )
        else:
            print(f"The avg RTT to {key} is: N/A, the s.d. is: N/A")


# Run the program
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python analyze_traceroute.py <pcap_file>")
    else:
        pcap_file = sys.argv[1]
        analyze_traceroute(pcap_file)
