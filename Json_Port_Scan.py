import socket
import struct
import json
import argparse
from concurrent.futures import ThreadPoolExecutor


class PortScanner:
    def __init__(self, ip_address, scan_option, ports=None, hostname=False):
        self.ip_address = ip_address
        self.scan_option = scan_option.lower()
        self.ports = ports
        self.hostname = hostname
        self.results = []

    def get_hostname(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = "Unknown"
        return hostname

    def banner_grabbing(self, ip_address, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip_address, port))
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "not found"
                response = None  # Initialize response here
                if service == "http":
                    s.send(str.encode(f"GET / HTTP/1.1\r\nHost:{ip_address}:{port}\r\n\r\n"))
                    response = s.recv(1024).decode().strip()
                    total_communication = response.split("\r\n")
                    total_communication = next((line.split(": ")[1] for line in total_communication if line.startswith("Server: ")), "")
                elif service in ["ftp", "pop3"]:
                    s.send(b"USER anonymous\r\n")
                    user = s.recv(1024).decode().strip()
                    s.send(b"PASS anonymous\r\n")
                    password = s.recv(1024).decode().strip()
                    total_communication = f"{response}\r\n{user}\r\n{password}"
                elif service in ["smtp", "ssh"]:
                    total_communication = response
                else:
                    s.send(str.encode(f"GET / HTTP/1.1\r\nHost:{ip_address}:{port}\r\n\r\n"))
                    response = s.recv(1024).decode()
                    total_communication = next((line.split(": ")[1] for line in response.split("\r\n") if line.startswith("Server: ")), "")
        except (socket.timeout, OSError, TimeoutError) as e:
            total_communication = str(e)
        except UnicodeDecodeError:
            total_communication = "Couldn't decode."

        return {"service": service, "version": total_communication}

    def ping_ip(self):
        try:
            icmp = socket.getprotobyname("icmp")
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

            s.settimeout(2)

            packet_id = 12345
            packet_header = struct.pack("!BBHHH", 8, 0, 0, packet_id, 1)
            packet_data = b"Hello, World!"
            packet_checksum = self.checksum(packet_header + packet_data)
            packet_header = struct.pack("!BBHHH", 8, 0, socket.htons(packet_checksum), packet_id, 1)
            packet = packet_header + packet_data

            s.sendto(packet, (self.ip_address, 0))
            response, _ = s.recvfrom(1024)
            ttl = struct.unpack("!B", response[8:9])[0]

            s.close()

            return "Linux/Unix" if ttl <= 64 else "Windows"
        except (socket.timeout, OSError):
            return "Unknown"

    def checksum(self, data):
        checksum = 0
        count = len(data)
        index = 0

        while count > 1:
            checksum += (data[index + 1] * 256 + data[index])
            index += 2
            count -= 2

        if count:
            checksum += (data[index])

        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += (checksum >> 16)

        return ~checksum & 0xffff

    def scan_port(self, ip_address, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    banner_info = self.banner_grabbing(ip_address, port)
                    hostname = self.get_hostname(ip_address) if self.hostname else None
                    self.results.append({"port": port, "status": "open", "service": banner_info["service"], "version": banner_info["version"]})
                else:
                    if self.scan_option == "p":
                        self.results.append({"port": port, "status": "closed", "service": None, "version": None, "hostname": None})

        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
        except socket.gaierror:
            print("Hostname could not be resolved. Exiting.")
        except socket.error as e:
            print(f"Couldn't connect to server: {e}")

    def start_scan(self):
        if self.scan_option == 'a':
            start_port, end_port = 1, 65535
        elif self.scan_option == 'kn':
            start_port, end_port = 1, 1024
        elif self.scan_option == "p":
            ports = map(int, self.ports.split(","))
            for port in ports:
                self.scan_port(self.ip_address, port)
            return self.results
        else:
            print("Invalid option. Exiting.")
            return

        with ThreadPoolExecutor(max_workers=500) as executor:
            for port in range(start_port, end_port + 1):
                executor.submit(self.scan_port, self.ip_address, port)

        return self.results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("ip_address", type=str, help="IP address to scan")
    parser.add_argument("scan_option", type=str, choices=["a", "kn", "p"], help="Scan option: 'a' for all ports, 'kn' "
                                                                                "for known ports, 'p' for individual "
                                                                                "ports")
    parser.add_argument("--ports", type=str, help="Individual ports separated by commas (only for '-p' option)")
    parser.add_argument("-Hn", action="store_true", help="Include hostname in the output")

    args = parser.parse_args()
    print(args)
    scanner = PortScanner(args.ip_address, args.scan_option, args.ports)
    port_results = scanner.start_scan()
    os_type = scanner.ping_ip()

    hostname = scanner.get_hostname(args.ip_address) if args.Hn else ""

    result = {
        "ip_address": args.ip_address,
        "hostname": hostname,
        "os_type": os_type,
        "port_results": port_results
    }

    print(json.dumps(result, indent=4))

