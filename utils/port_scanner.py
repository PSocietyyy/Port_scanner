import socket
from datetime import datetime
from config import settings

class PortScanner:
    def __init__(self, target: str, start_port: int = settings.DEFAULT_START_PORT, end_port: int = settings.DEFAULT_END_PORT, port_scanning_list: list = None, scan_type: str = settings.DEFAULT_SCAN_TYPE):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.port_scanning_list = port_scanning_list or []
        self.scan_type = scan_type.upper()

        # color variabel
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
            print(f"\n{self.info} Pemindaian berdasarkan daftar port: {self.port_scanning_list}")
        else:
            print(f"\n{self.info} Pemindaian dari port {self.start_port} hingga port {self.end_port}")

        print(f"\nDimulai: {datetime.now()}\n")

        ports_to_scan = (
            self.port_scanning_list
            if self.port_scanning_list
            else range(self.start_port, self.end_port + 1)
        )

        for port in ports_to_scan:
            try:
                if self.scan_type == "TCP":
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
            s.settimeout(2)  # TimeOut 2 detik
            try:
                result = s.connect_ex((self.target, port))  # 0 = Berhasil, lainnya = Gagal
                if result == 0:
                    print(f"{self.open} Port {port} terbuka (TCP)")
                else:
                    print(f"{self.close} Port {port} tertutup (TCP)")
            except socket.timeout:
                print(f"{self.filter} Port {port} filter (TCP)")
            except Exception as e:
                print(f"{self.error} Error: {e}")

    def _scan_udp(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)  # TimeOut 2 detik
            try:
                result = s.sendto(b'', (self.target, port))
                print(f"{self.open} Port {port} terbuka (UDP)")
            except Exception as e:
                print(f"{self.close} Port {port} tertutup (UDP) atau terjadi kesalahan: {e}")

