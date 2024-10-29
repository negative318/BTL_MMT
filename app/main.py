import json
import sys
import hashlib
import bencode
import requests
import struct
import socket
import bencodepy
import math
import os

def decode_bencode(bencoded_value):
    return bencode.decode(bencoded_value)


def get_info(torrent_file):
    with open(torrent_file, "rb") as f:
        torrent_data = bencode.decode(f.read())
    
    tracker_url = torrent_data["announce"]
    length = torrent_data["info"]["length"]
    info_hash = hashlib.sha1(bencode.bencode(torrent_data['info'])).digest()
    piece_length = torrent_data['info']["piece length"]
    pieces = torrent_data["info"]["pieces"]
    return tracker_url, length, info_hash, pieces, piece_length

def get_list_piece_hashs(pieces):
    list_pieces = []
    for i in range(0, len(pieces), 20):
        list_pieces.append(pieces[i:i+20].hex())
    return list_pieces

def get_list_peers(tracker_url, info_hash, peer_id, port, uploaded, downloaded, left, compact):

    list_peers = []

    params = {
        "info_hash": info_hash,
        "peer_id": peer_id,
        "port": port,
        "uploaded": uploaded,
        "downloaded": downloaded,
        "left": left,
        "compact": compact
    }

    response = requests.get(tracker_url, params = params)
    response_decode = decode_bencode(response.content)
    peers = response_decode["peers"]
    for i in range(0, len(peers), 6):
        ip = ".".join(str(b) for b in peers[i: i+ 4])
        port = struct.unpack("!H", peers[i+4: i+6])[0]
        list_peers.append((ip, port))
    return list_peers


def handshake(info_hash, Ssocket, peer_id, ip, port):
    payload = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + peer_id.encode()
    )
    Ssocket.connect((ip, int(port)))
    Ssocket.send(payload)
    respon = Ssocket.recv(68)
    return respon


def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message



def download_piece(tracker_url, length, info_hash, pieces, piece_length, peer_id, peer_index, output):

    list_peers = get_list_peers(tracker_url, info_hash, peer_id, 6881, 0, 0, length, 1)

    ip, port = list_peers[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    

    payload = (
        b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
        + info_hash
        + peer_id.encode()
    )


    try:
        sock.connect((ip, port))
        sock.sendall(payload)
        response = sock.recv(68)

        # response = handshake(info_hash, sock, peer_id, ip, port)
        message = receive_message(sock)
        
        while int(message[4]) != 5:
            print("aaaa")
            message = receive_message(sock)
        

        interested_payload = struct.pack(">IB", 1, 2)
        sock.sendall(interested_payload)
        
        # sock.settimeout(3)
        
        message = receive_message(sock)

        while int(message[4]) != 1:
            print("bbb")
            message =receive_message(sock)

        list_piece_hashs = get_list_piece_hashs(pieces)
        num_peers = len(list_piece_hashs)

        if peer_index == num_peers - 1:
            piece_length = length - piece_length * peer_index
        
        num_blocks = math.ceil(piece_length / (16*1024))

        data = bytearray()

        for i in range(num_blocks):
            block_start = 16 * 1024 * i
            block_length = min(piece_length - block_start, 16*1024)
            print(f"request block {i+1} of {num_blocks} with len {block_length}")

            request_payload = struct.pack(">IBIII", 13, 6, peer_index, block_start, block_length)
            # print("Requesting block, with payload:")
            # print(request_payload)
            # print(struct.unpack(">IBIII", request_payload))
            # print(int.from_bytes(request_payload[:4]))
            # print(int.from_bytes(request_payload[4:5]))
            # print(int.from_bytes(request_payload[5:9]))
            # print(int.from_bytes(request_payload[9:13]))
            # print(int.from_bytes(request_payload[13:17]))

            sock.sendall(request_payload)
            message = receive_message(sock)
            data.extend(message[13:])
        
        with open(output, "ab") as f:
            f.write(data)
        print("end file")
        data.clear()

    finally:
        print("close socket")
        sock.close()

    return True


def download(torrent_file, output):

    tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
    num_piece = len(get_list_piece_hashs(pieces))
    for i in range(num_piece):
        download_piece(tracker_url, length, info_hash, pieces, piece_length, "01234567899876543210", i, output)
    return True


def main():
    command = sys.argv[1]



    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))

    elif command == "info":
        torrent_file = sys.argv[2]
        
        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
        piece_hashs = get_list_piece_hashs(pieces)
        print("Tracker URL:", tracker_url)
        print("Length:", length)
        print("Info Hash:", info_hash.hex())
        print("Piece Length:", piece_length)
        print("Piece Hashes:")
        for i in range(len(piece_hashs)):
            print(piece_hashs[i])

    elif command == "peers":
        torrent_file = sys.argv[2]
        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)
        list_peers = get_list_peers(tracker_url, info_hash, "01234567899876543210", 6881, 0, 0, length, 1)


        for i in range(0, len(list_peers)):
            print(f"Peers: {list_peers[i][0]}:{list_peers[i][1]}")



    elif command == "handshake":
        torrent_file = sys.argv[2]
        (ip, port) = sys.argv[3].split(":")

        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)

        Ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        respon = handshake(info_hash, Ssocket, "01234567899876543210", ip, port)
        print(f"Peer ID: {respon[48:].hex()}")


    elif command == "download_piece":
        output = sys.argv[3]
        torrent_file = sys.argv[4]
        peer_index = int(sys.argv[5])
        tracker_url, length, info_hash, pieces, piece_length = get_info(torrent_file)

        if download_piece(tracker_url, length, info_hash, pieces, piece_length, "01234567899876543210", peer_index, output):
            print(f"Piece {peer_index} downloaded to {output}")
        
        else:
            raise RuntimeError("Failed to download piece")


    elif command == "download":
        output = sys.argv[3]
        torrent_file = sys.argv[4]

        if download(torrent_file, output):
            print(f"download {torrent_file} to {output}")


    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
