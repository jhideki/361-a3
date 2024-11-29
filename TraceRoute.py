import struct
import socket
import statistics

def analyze_group_trace_files(group1):
    for trace_file in group1:
        packets, pcap_start, ts_factor = parse_pcap(trace_file)
        packets = sorted(packets, key=lambda pkt: (pkt[0]))
        ttl_probe_counts = dict()

        for ts, packet_data in packets:
            ip_data = packet_data[14:]
            ip_header = parse_ip_header(ip_data)
            proto = ip_header["protocol"]

            if proto != 17:  
                continue

            udp_start = 14 + ip_header["ihl"]
            udp_data = parse_udp_packet(packet_data[udp_start:])

            if not 33434 <= udp_data["dst_port"] <= 33529:
                continue

            if udp_data["src_port"] == 53 or udp_data["dst_port"] == 53:
                continue
            else:
                ttl = ip_header["ttl"]
                if ttl in ttl_probe_counts:
                    ttl_probe_counts[ttl] += 1
                else:
                    ttl_probe_counts[ttl] = 1

        ttl_probe_counts = dict(sorted(ttl_probe_counts.items()))
        print(f"\nTrace file: {trace_file}")
        print("{:<5} {:<10} {:<15}".format("TTL", "Probes", "Avg RTT (ms)"))
        for ttl,count in ttl_probe_counts.items():
            print(f"{ttl:<5} {count:<10} ")


def parse_pcap(file_path):
    pcap_start = None
    packets = []

    with open(file_path, "rb") as f:
        pcap_global_header = f.read(24)
        magic_number = pcap_global_header[:4]

        if magic_number == b'\xa1\xb2\xc3\xd4':  
            endian = ">"
            ts_factor = 1_000_000  
        elif magic_number == b'\xd4\xc3\xb2\xa1':  
            endian = "<"
            ts_factor = 1_000_000  
        elif magic_number == b'\xa1\xb2\x3c\x4d':  
            endian = ">"
            ts_factor = 1_000_000_000  
        elif magic_number == b'\x4d\x3c\xb2\xa1':  
            endian = "<"
            ts_factor = 1_000_000 
        else:
            raise ValueError("Unknown magic number in pcap file")

        while True:
            packet_header = f.read(16)
            if not packet_header:
                break  

            try:
                ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                    f"{endian}IIII", packet_header
                )
            except struct.error:
                raise ValueError("Malformed packet header")

            packet_data = f.read(incl_len)
            if len(packet_data) != incl_len:
                raise ValueError("Packet data length mismatch")

            if pcap_start is None:
                pcap_start = ts_sec + ts_frac / ts_factor
                print(f"PCAP start time: {round(pcap_start, 9)}")

            packet_time = ts_sec + ts_frac / ts_factor
            packets.append((packet_time, packet_data))

    return packets, pcap_start, ts_factor

def parse_ip_header(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    total_length = ip_header[2]
    flags_offset = ip_header[4]
    protocol = ip_header[6]
    ttl = ip_header[5]  
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    frag_offset = (flags_offset & 0x1FFF) * 8
    mf_flag = (flags_offset & 0x2000) >> 13
    identification = ip_header[3]

    return {
        "ihl": ihl,
        "total_length": total_length,
        "protocol": protocol,
        "ttl": ttl,  
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "frag_offset": frag_offset,
        "mf_flag": mf_flag,
        "id": identification,
    }


def parse_udp_packet(data):
    UDP_HEADER_LENGTH = 8

    if len(data) < UDP_HEADER_LENGTH:
        raise ValueError("Data is too short to contain a valid UDP header")

    udp_header = struct.unpack("!HHHH", data[:UDP_HEADER_LENGTH])
    src_port = udp_header[0]
    dst_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]

    udp_payload = data[UDP_HEADER_LENGTH:]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": checksum,
        "udp_payload": udp_payload,
    }



def parse_icmp(data):
    # Unpack the ICMP header
    icmp_header = struct.unpack("!BBHHH", data[:8])
    icmp_type = icmp_header[0]
    icmp_code = icmp_header[1]
    icmp_checksum = icmp_header[2]
    identifier = icmp_header[3]
    seq_number = icmp_header[4]
    print("----", seq_number)

    rest_of_icmp = data[8:]
    embedded_seq = None

    # Return early if there's not enough data for the embedded IP header
    if len(rest_of_icmp) < 20:
        return {
            "type": icmp_type,
            "code": icmp_code,
            "checksum": icmp_checksum,
            "identifier": identifier,
            "seq": seq_number,
            "embedded_seq": embedded_seq,
            "embedded_ip_header": None,
            "udp_data": None,
        }

    # Parse the embedded IP header
    embedded_ip_header = struct.unpack("!BBHHHBBH4s4s", rest_of_icmp[:20])
    embedded_ip_id = embedded_ip_header[3]
    embedded_ip_src = socket.inet_ntoa(embedded_ip_header[8])
    embedded_ip_dst = socket.inet_ntoa(embedded_ip_header[9])

    # Check for embedded sequence number
    if len(rest_of_icmp) >= 22:
        embedded_seq = struct.unpack("!H", rest_of_icmp[20:22])[0]

    print("----", embedded_seq)
    udp_data_offset = 20
    # Check if there is enough data for the UDP header
    if len(rest_of_icmp) < udp_data_offset + 8:
        return {
            "type": icmp_type,
            "code": icmp_code,
            "checksum": icmp_checksum,
            "identifier": identifier,
            "seq": seq_number,
            "embedded_seq": embedded_seq,
            "id": embedded_ip_id,
            "src_ip": embedded_ip_src,
            "dst_ip": embedded_ip_dst,
            "udp_data": None,
            "src_port": None,
        }

    # Parse the UDP header
    udp_header = struct.unpack(
        "!HHHH", rest_of_icmp[udp_data_offset:udp_data_offset + 8]
    )
    udp_src_port = udp_header[0]
    udp_dst_port = udp_header[1]
    udp_length = udp_header[2]
    udp_checksum = udp_header[3]

    return {
        "type": icmp_type,
        "code": icmp_code,
        "checksum": icmp_checksum,
        "identifier": identifier,
        "seq": seq_number,
        "embedded_seq": embedded_seq,
        "id": embedded_ip_id,
        "src_ip": embedded_ip_src,
        "dst_ip": embedded_ip_dst,
        "src_port": udp_src_port,
        "dst_port": udp_dst_port,
        "length": udp_length,
        "checksum": udp_checksum,
    }


def analyze_traceroute(pcap_file):
    packets, pcap_start, ts_factor = parse_pcap(pcap_file)

    source_ip = None
    dest_ip = None
    intermediate_ips = set()
    protocol_set = set()
    fragment_offsets = dict()
    udp_packets = []
    icmp_packets = []
    icmp_echo_packets = []
    routers = dict()

    packets = sorted(packets, key=lambda pkt: (pkt[0]))

    for ts, packet_data in packets:
        ip_data = packet_data[14:]
        ip_header = parse_ip_header(ip_data)
        proto = ip_header["protocol"]

        if ip_header["frag_offset"] > 0 or ip_header["mf_flag"] == 1:
            if ip_header["id"] in fragment_offsets:
                fragment_offsets[ip_header["id"]].append(ip_header["frag_offset"])
            else:
                fragment_offsets[ip_header["id"]] = [ip_header["frag_offset"]]

        if proto != 17 and proto != 1:
            continue

        if proto == 17:
            udp_start = 14 + ip_header["ihl"]
            udp_data = parse_udp_packet(packet_data[udp_start:])

            if not 33434 <= udp_data["dst_port"] <= 33529:
                continue

            if udp_data["src_port"] == 53 or udp_data["dst_port"] == 53:
                continue
            else:
                if source_ip is None:
                    source_ip = ip_header["src_ip"]
                if dest_ip is None:
                    dest_ip = ip_header["dst_ip"]
                if ip_header["frag_offset"] == 0:
                    udp_packets.append(
                        {
                            "ip": ip_header["src_ip"],
                            "src_port": udp_data["src_port"],
                            "id": ip_header["id"],
                            "time": ts,
                            "ttl": ip_header["ttl"],
                        }
                    )
        elif proto == 1:
            icmp_data = parse_icmp(packet_data[14 + ip_header["ihl"] :])
            if icmp_data["type"] == 8:
                icmp_echo_packets.append(
                    {
                        "ip": ip_header["src_ip"],
                        "src_port": icmp_data["src_port"],
                        "id": icmp_data["id"],
                        "time": ts,
                        "seq": icmp_data["seq"],
                    }
                )
                if source_ip is None:
                    source_ip = ip_header["src_ip"]
                if dest_ip is None:
                    dest_ip = ip_header["dst_ip"]
            elif icmp_data["type"] == 11:
                if ( ip_header["src_ip"] not in intermediate_ips
                    and ip_header["src_ip"] != source_ip
                    and ip_header["src_ip"] != dest_ip
                ):
                    intermediate_ips.add(ip_header["src_ip"])


                icmp_packets.append(
                    {
                        "ip": ip_header["src_ip"],
                        "src_port": icmp_data["src_port"],
                        "id": icmp_data["id"],
                        "time": ts,
                        "seq": icmp_data["embedded_seq"],
                    }
                )

            routers[ip_header["src_ip"]] = {
                "rtt": [],
                "avg": 0,
                "std": 0,
            }

        protocol_set.add(ip_header["protocol"])

    ttl_rtt = dict()

    print("-----", len(icmp_echo_packets))
    print("-----", len(icmp_packets))

    if len(icmp_echo_packets) > 0:
        for echo in icmp_echo_packets:
            for icmp in icmp_packets:
                if echo["seq"] == icmp["seq"]:
                    icmp_ip = icmp["ip"]
                    print("---", icmp_ip)
                    if icmp_ip in routers:
                        diff = max(0, icmp["time"] - echo["time"])
                        routers[icmp_ip]["rtt"].append(diff)

    else:
        for udp in udp_packets:
            for icmp in icmp_packets:
                if (udp["id"] == icmp["id"] and udp["id"] != 0) or (
                    udp["src_port"] == icmp["src_port"] and udp["src_port"] != 0
                ):
                    icmp_ip = icmp["ip"]
                    if icmp_ip in routers:
                        diff = max(icmp["time"] - udp["time"],0)
                        routers[icmp_ip]["rtt"].append(diff)
                        if udp["ttl"] in ttl_rtt:
                            ttl_rtt[udp["ttl"]].append(diff)
                        else:
                            ttl_rtt[udp["ttl"]] = [diff]


    print(f"The IP address of the source node: {source_ip}")
    print(f"The IP address of ultimate destination node: {dest_ip}")
    print("The IP addresses of the intermediate destination nodes:")
    for i, ip in enumerate(intermediate_ips):
        print(f"router {i}: {ip}")

    print("\nThe values in the protocol field of IP headers:")
    for proto in sorted(protocol_set):
        print(f"{proto}: {'ICMP' if proto == 1 else 'UDP' if proto == 17 else 'Other'}")

    i = 0
    for id, frag_off in fragment_offsets.items():
        print(
            f"\nThe number of fragments created from the original datagram D{i} is: {len(frag_off)}"
        )
        print(f"The offset of the last fragment is: {max(frag_off)}")
        i += 1

    print("\nRTT statistics:")
    for key, router in routers.items():
        if len(router["rtt"]) > 0:
            router["avg"] = statistics.mean(router["rtt"])
        if len(router["rtt"]) > 1:
            router["std"] = statistics.pstdev(router["rtt"])
        else:
            router["std"] = 0

    print("Ultimate Destination:")
    print(
        f"The avg RTT to {dest_ip} is: {routers[dest_ip]["avg"]:.2f} ms, the s.d. is: {routers[dest_ip]["std"]:.2f} ms"
    )

    print("Intermediate Routers:")
    for key, router in routers.items():
        if key != dest_ip:
            print(
                f"The avg RTT to {key} is: {router["avg"]:.2f} ms, the s.d. is: {router["std"]:.2f} ms"
            )
    return ttl_rtt


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python analyze_traceroute.py <pcap_file>")
    else:
        pcap_file = sys.argv[1]
        ttl_rtt = analyze_traceroute(pcap_file)

        group1_trace_files = [f"PcapTracesAssignment3/group1-trace{i}.pcap" for i in range(1, 6)]  
        group2_trace_files = [f"PcapTracesAssignment3/group2-trace{i}.pcap" for i in range(1, 6)]  
        #Part 2
        '''
        analyze_group_trace_files(group1_trace_files)
        for file in group1_trace_files:
            print(file)
            ttl_rtt = analyze_traceroute(file)
            print(f"\nTrace file: {file}")
            print("{:<5} {:<10}".format("TTL", "Avg RTT (ms)"))
            for ttl, rtt in ttl_rtt.items():
                print(f"{ttl:<5} {statistics.mean(rtt):<10} ")
        '''
