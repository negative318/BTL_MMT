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
from tabulate import tabulate

class server:
    def __init__(self):
        self.peers = {}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            self.server_ip = s.getsockname()[0]
        self.server_port = 6881
        
    def get_server_info(self):
        return {"ip": self.server_ip, "port": self.server_port}

    def print_peers_table(self):
        headers = ["Info Hash", "IP", "Port", "Peer ID"]
        data = []

        for info_hash, peers_list in self.peers.items():
            for ip, port, peer_id in peers_list:
                data.append([info_hash, ip, port, peer_id])

        print(tabulate(data, headers=headers, tablefmt="grid"))

    def handle_inform(self, first_line):

        print("event=started")
        path = first_line.split(" ")[1]
        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        ip = query_params.get("ip", [""])[0]
        port = int(query_params.get("port", [0])[0])
        peer_id = query_params.get("peer_id", [""])[0]
        info_hash_encoded = query_params.get("info_hash", [""])[0]
        info_hash_bytes = urllib.parse.unquote_to_bytes(info_hash_encoded)
        info_hash = info_hash_bytes.hex()
        print(ip, port, peer_id, info_hash)

        if info_hash not in self.peers:
            self.peers[info_hash] = []

        if (ip, port, peer_id) not in self.peers[info_hash]:
            self.peers[info_hash].append((ip, port, peer_id))

        print(f"Peer list for {info_hash}: {self.peers[info_hash]}")

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 2\r\n\r\n"
            b"OK"
        )
        return response
    
    
    def handle_end(self,first_line):
        print("event=end")
        path = first_line.split(" ")[1]
        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)

        ip = query_params.get("ip", [""])[0]
        port = int(query_params.get("port", [0])[0])
        peer_id = query_params.get("peer_id", [""])[0]

        info_hash_encoded = query_params.get("info_hash", [""])[0]
        info_hash_bytes = urllib.parse.unquote_to_bytes(info_hash_encoded)
        info_hash = info_hash_bytes.hex()

        if info_hash in self.peers:
            peer_info = (ip, port, peer_id)
            if peer_info in self.peers[info_hash]:
                self.peers[info_hash].remove(peer_info)
                print(f"Peer {peer_info} removed for info_hash {info_hash}")
                if not self.peers[info_hash]:
                    del self.peers[info_hash]
                    print(f"Info hash {info_hash} has no more peers and was removed.")
            else:
                print(f"Peer {peer_info} not found for info_hash {info_hash}")
        else:
            print(f"Info hash {info_hash} not found.")

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 2\r\n\r\n"
            b"OK"
        )
        return response

    def handle_get_peer(self, first_line):
        path = first_line.split(" ")[1]

        query_params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)

        info_hash_encoded = query_params.get("info_hash", [""])[0]
        info_hash_bytes = urllib.parse.unquote_to_bytes(info_hash_encoded)
        info_hash = info_hash_bytes.hex()

        requesting_peer_id = query_params.get("peer_id", [""])[0]

        response_peers = bytearray()
        for peer_ip, peer_port, peer_id in self.peers[info_hash]:
            if(requesting_peer_id == peer_id):
                continue
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
        return response


    def handle_client(self, client_socket, addr):
        try:
            request = client_socket.recv(1024).decode()
            first_line = request.splitlines()[0]
            if 'event=started' in first_line:
                response = self.handle_inform(first_line)
                self.print_peers_table()
                client_socket.sendall(response)

            elif 'event=end' in first_line:
                response = self.handle_end(first_line)
                self.print_peers_table()
                client_socket.sendall(response)
            else:
                response = self.handle_get_peer(first_line)

                print("response", response)
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
        
        
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            server_ip = s.getsockname()[0]


        server_socket.bind(("0.0.0.0", port))
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