import socket
import struct
import time
import argparse
import threading

# DRTP Config
TIMEOUT = 0.5  # seconds
MAX_PACKET_SIZE = 1024
HEADER_FORMAT = '!I I'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# Global for discard mode
DISCARD_PACKET = False

def make_packet(seq_num, is_last, data):
    header = struct.pack(HEADER_FORMAT, seq_num, is_last)
    return header + data

def parse_packet(packet):
    header = packet[:HEADER_SIZE]
    seq_num, is_last = struct.unpack(HEADER_FORMAT, header)
    data = packet[HEADER_SIZE:]
    return seq_num, is_last, data

def server_mode(ip, port, file_name, discard):
    global DISCARD_PACKET
    DISCARD_PACKET = discard

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print("[SERVER] Listening on {}:{}".format(ip, port))

    expected_seq = 0
    with open(file_name, 'wb') as f:
        while True:
            packet, addr = sock.recvfrom(MAX_PACKET_SIZE)
            seq_num, is_last, data = parse_packet(packet)

            if DISCARD_PACKET:
                print(f"[SERVER] Discarding packet {seq_num}")
                DISCARD_PACKET = False
                continue

            if seq_num == expected_seq:
                f.write(data)
                ack = struct.pack('!I', seq_num)
                sock.sendto(ack, addr)
                print(f"[SERVER] Received and ACK'd: {seq_num}")
                expected_seq += 1
            else:
                # Resend ACK for last correct packet
                ack = struct.pack('!I', expected_seq - 1)
                sock.sendto(ack, addr)

            if is_last:
                print("[SERVER] Last packet received.")
                break

    sock.close()

def client_mode(ip, port, file_name, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    server_addr = (ip, port)

    with open(file_name, 'rb') as f:
        data_chunks = []
        while True:
            chunk = f.read(MAX_PACKET_SIZE - HEADER_SIZE)
            if not chunk:
                break
            data_chunks.append(chunk)

    base = 0
    next_seq = 0
    total_packets = len(data_chunks)
    acked = [False] * total_packets

    def recv_acks():
        nonlocal base
        while base < total_packets:
            try:
                ack_packet, _ = sock.recvfrom(4)
                ack_seq = struct.unpack('!I', ack_packet)[0]
                print(f"[CLIENT] Received ACK: {ack_seq}")
                acked[ack_seq] = True
                while base < total_packets and acked[base]:
                    base += 1
            except socket.timeout:
                continue

    ack_thread = threading.Thread(target=recv_acks)
    ack_thread.start()

    start_time = time.time()
    while base < total_packets:
        while next_seq < base + window_size and next_seq < total_packets:
            is_last = (next_seq == total_packets - 1)
            pkt = make_packet(next_seq, is_last, data_chunks[next_seq])
            sock.sendto(pkt, server_addr)
            print(f"[CLIENT] Sent packet: {next_seq}")
            next_seq += 1

        time.sleep(TIMEOUT)
        # Retransmit unacked packets
        for i in range(base, min(base + window_size, total_packets)):
            if not acked[i]:
                is_last = (i == total_packets - 1)
                pkt = make_packet(i, is_last, data_chunks[i])
                sock.sendto(pkt, server_addr)
                print(f"[CLIENT] Retransmitted packet: {i}")

    ack_thread.join()
    duration = time.time() - start_time
    print(f"[CLIENT] File transfer completed in {duration:.2f} seconds")

    sock.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['server', 'client'], required=True)
    parser.add_argument('--ip', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--file', required=True)
    parser.add_argument('--window', type=int, default=5)
    parser.add_argument('--discard', action='store_true')
    args = parser.parse_args()

    if args.mode == 'server':
        server_mode(args.ip, args.port, args.file, args.discard)
    else:
        client_mode(args.ip, args.port, args.file, args.window)
