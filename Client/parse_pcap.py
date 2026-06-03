import sys

def parse_pcap(filename):
    with open(filename, 'rb') as f:
        pcap_data = f.read()

    # Extremely rudimentary search for ServerHello (0x02) in TLS 1.2 (0x03 0x03)
    # The pattern for ServerHello is:
    # 0x16 (Handshake) 0x03 0x03 (TLS 1.2) [Length: 2 bytes]
    # 0x02 (Server Hello) [Length: 3 bytes] 0x03 0x03 (Version)
    idx = pcap_data.find(b'\x16\x03\x03')
    while idx != -1:
        # Check if it's a ServerHello
        if idx + 9 < len(pcap_data) and pcap_data[idx+5] == 0x02 and pcap_data[idx+9:idx+11] == b'\x03\x03':
            # Offset to Cipher Suite:
            # 5 (Record header) + 4 (Handshake header) + 2 (Version) + 32 (Random) + 1 (Session ID length)
            session_id_len = pcap_data[idx + 5 + 4 + 2 + 32]
            cipher_suite_offset = idx + 5 + 4 + 2 + 32 + 1 + session_id_len
            cipher_suite = pcap_data[cipher_suite_offset:cipher_suite_offset+2]
            print(f"ServerHello found at offset {idx}")
            print(f"Selected Cipher Suite: 0x{cipher_suite.hex()}")
            return
        idx = pcap_data.find(b'\x16\x03\x03', idx + 1)
    
    print("ServerHello not found")

parse_pcap('eapol_capture.pcap')
