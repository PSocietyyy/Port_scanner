import socket
from datetime import datetime
from config import settings
import struct
import time


class PortScanner:
    def __init__(
        self,
        target: str,
        start_port: int = settings.DEFAULT_START_PORT,
        end_port: int = settings.DEFAULT_END_PORT,
        port_scanning_list: list = None,
        scan_type: str = settings.DEFAULT_SCAN_TYPE,
        tcp_scan_type: str = settings.DEFAULT_TCP_SCAN_TYPE,
        output_file: str = settings.DEFAULT_OUTPUT_FILE,
    ):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.port_scanning_list = port_scanning_list or []
        self.scan_type = scan_type.upper()
        self.tcp_scan_type = tcp_scan_type.upper()
        self.output_file = output_file

        # Warna untuk logging
        self.info = "\033[34m[INFO]\033[0m"
        self.error = "\033[31m[ERROR]\033[0m"
        self.open = "\033[32m[OPEN]\033[0m"
        self.close = "\033[31m[CLOSED]\033[0m"
        self.filter = "\033[33m[FILTERED]\033[0m"

    def scan_port(self):
        """
        Memindai port TCP atau UDP pada target.
        """
        print(f"\n{self.info} Memulai pemindaian pada {self.target}")
        if self.port_scanning_list:
            print(f"{self.info} Pemindaian berdasarkan daftar port: {self.port_scanning_list}")
        else:
            print(f"{self.info} Pemindaian dari port {self.start_port} hingga port {self.end_port}")

        print(f"\nDimulai: {datetime.now()}\n")

        ports_to_scan = (
            self.port_scanning_list
            if self.port_scanning_list
            else range(self.start_port, self.end_port + 1)
        )

        for port in ports_to_scan:
            try:
                if self.scan_type == "TCP":
                    if self.tcp_scan_type == "SYN":
                        self._scan_syn(port)
                    else:
                        self._scan_tcp(port)
                elif self.scan_type == "UDP":
                    self._scan_udp(port)
                else:
                    print(f"{self.error} Jenis pemindaian tidak valid.")
            except Exception as e:
                print(f"{self.error} Gagal memindai port {port}: {e}")

        print(f"\n{self.info} Pemindaian selesai pada {datetime.now()}\n")

    def _scan_tcp(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            try:
                result = s.connect_ex((self.target, port))
                if result == 0:
                    message = f"{self.open} Port {port} terbuka (TCP)"
                    print(message)
                    self._save_to_txt(message)
                else:
                    print(f"{self.close} Port {port} tertutup (TCP)")
            except socket.timeout:
                print(f"{self.filter} Port {port} terfilter (TCP)")
            except Exception as e:
                print(f"{self.error} Error: {e}")

    def _scan_udp(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            try:
                s.sendto(b"", (self.target, port))
                print(f"{self.open} Port {port} terbuka (UDP)")
            except Exception as e:
                print(f"{self.close} Port {port} tertutup (UDP) atau error: {e}")

    def _scan_syn(self, port):
        """
        Melakukan pemindaian SYN dengan menggunakan socket mentah.
        Membutuhkan izin root.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
                s.settimeout(1)
                src_ip = socket.gethostbyname(socket.gethostname())
                tcp_header = self._create_tcp_syn_packet(src_ip, self.target, port)
                s.sendto(tcp_header, (self.target, port))

                try:
                    data = s.recv(1024)
                    if data:
                        # Cek apakah respon adalah SYN-ACK (Port terbuka)
                        if b"SYN+ACK" in data:
                            print(f"{self.open} Port {port} terbuka (SYN)")
                        # Cek jika respon adalah RST (Port tertutup)
                        elif b"RST" in data:
                            print(f"{self.close} Port {port} tertutup (SYN)")
                        else:
                            print(f"{self.filter} Port {port} terfilter atau tidak merespons dengan benar.")
                    else:
                        print(f"{self.close} Port {port} tidak merespon.")
                except socket.timeout:
                    print(f"{self.close} Port {port} tidak merespon.")
        except PermissionError:
            print(f"{self.error} Izin root diperlukan untuk pemindaian SYN.")


    def _create_tcp_syn_packet(self, src_ip, dest_ip, dest_port):
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            12345,
            dest_port,
            0,
            0,
            (5 << 4) + 2,
            0,
            socket.htons(5840),
            0,
            0,
        )
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            69,
            0,
            40,
            54321,
            0,
            255,
            socket.IPPROTO_TCP,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dest_ip),
        )
        return ip_header + tcp_header

    def _save_to_txt(self, text):
        if self.output_file:
            with open(self.output_file, "a") as f:
                f.write(text + "\n")
