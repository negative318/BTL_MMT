# server.py
import socket
import threading
import bencodepy
from urllib.parse import unquote
from urllib.parse import unquote_to_bytes
import urllib.parse
import bencodepy
import bencode
import os

class server:
    def __init__(self):
        self.peers = {}

    def create_torrent(self, file_path, tracker_url, folder_out = "torrent", piece_length=512*1024):
    
        os.makedirs(folder_out, exist_ok=True)

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        piece_hashes = self.get_piece_hashes(file_path, piece_length)
        print(tracker_url, file_name, file_size, piece_length, piece_hashes)
        torrent_info = {
            "announce": tracker_url,
            "info": {
                "name": file_name,
                "length": file_size,
                "piece length": piece_length,
                "pieces": piece_hashes,
            }
        }

        torrent_file_path = os.path.join(folder_out, f"{file_name}.torrent")
        with open(torrent_file_path, "wb") as torrent_file:
            torrent_file.write(bencodepy.encode(torrent_info))


        print(f"Torrent file created: {torrent_file_path}")
        return torrent_file_path



    def handle_client(self, client_socket, addr):
        try:
            request = client_socket.recv(1024).decode()
            print(f"Received request: {request}, {addr}")
            first_line = request.splitlines()[0]
            path = first_line.split(" ")[1]
            query_params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)

            info_hash_encoded = query_params.get("info_hash", [""])[0]
            info_hash_bytes = urllib.parse.unquote_to_bytes(info_hash_encoded)
            info_hash = info_hash_bytes.hex()

            ip = addr[0]
            port = addr[1]
            peer_id = query_params.get("peer_id", [""])[0]

            print(info_hash, ip, port, peer_id)

            if info_hash not in self.peers:
                self.peers[info_hash] = []
            self.peers[info_hash].append((ip, port, peer_id))
            print(f"Peer list for {info_hash}: {self.peers[info_hash]}")

            response_peers = bytearray()
            for peer_ip, peer_port, _ in self.peers[info_hash]:
                packed_ip = b"".join(int(x).to_bytes(1, "big") for x in peer_ip.split("."))
                packed_port = peer_port.to_bytes(2, "big")
                response_peers.extend(packed_ip + packed_port)

            complete_count = len(self.peers[info_hash])
            incomplete_count = 0
            interval = 60

            response = (
                b"d" 
                b"8:completei" + str(complete_count).encode() + b"e"
                b"10:incompletei" + str(incomplete_count).encode() + b"e"
                b"8:intervali" + str(interval).encode() + b"e"
                b"5:peers" + str(len(response_peers)).encode() + b":" + response_peers + b"e"
            )
            client_socket.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(response)).encode() + b"\r\n\r\n" + response
            )

        except Exception as e:
            print(f"Error handling client {addr}: {e}")

        finally:
            client_socket.close()

    def start_tracker_server(self, port=6881):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Lấy địa chỉ IP của máy hiện tại
        hostname = socket.gethostname()
        server_ip = socket.gethostbyname(hostname)

        server_socket.bind((server_ip, port))
        server_socket.listen(5)
        print(f"Tracker is running on IP {server_ip} and port {port}...")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"New connection from {addr}")
            client_handler = threading.Thread(target= self.handle_client, args=(client_socket, addr))
            client_handler.start()


if __name__ == "__main__":
    tracker = server()
    tracker.start_tracker_server(6881)