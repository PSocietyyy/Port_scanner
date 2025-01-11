import socket
from datetime import datetime
from config import settings
import struct
import time


class PortScanner:
    # Constructor untuk inisialisasi objek PortScanner
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
        # Menyimpan parameter yang diberikan saat inisialisasi
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.port_scanning_list = port_scanning_list or []  # Jika tidak ada port yang ditentukan, maka gunakan list kosong
        self.scan_type = scan_type.upper()  # Memastikan jenis pemindaian ditulis dalam huruf besar
        self.tcp_scan_type = tcp_scan_type.upper()  # Memastikan jenis pemindaian TCP ditulis dalam huruf besar
        self.output_file = output_file

        # Warna untuk logging output
        self.info = "\033[34m[INFO]\033[0m"
        self.error = "\033[31m[ERROR]\033[0m"
        self.open = "\033[32m[OPEN]\033[0m"
        self.close = "\033[31m[CLOSED]\033[0m"
        self.filter = "\033[33m[FILTERED]\033[0m"

    def scan_port(self):
        """
        Fungsi utama untuk memindai port TCP atau UDP pada target yang diberikan.
        """
        print(f"\n{self.info} Memulai pemindaian pada {self.target}")  # Menampilkan informasi target
        if self.port_scanning_list:
            print(f"{self.info} Pemindaian berdasarkan daftar port: {self.port_scanning_list}")  # Menampilkan daftar port yang dipindai
        else:
            print(f"{self.info} Pemindaian dari port {self.start_port} hingga port {self.end_port}")  # Menampilkan rentang port yang dipindai

        print(f"\nDimulai: {datetime.now()}\n")  # Menampilkan waktu mulai pemindaian

        # Mengecek apakah menggunakan rentang port atau menggunakan port tertentu saja
        ports_to_scan = (
            self.port_scanning_list
            if self.port_scanning_list  # Jika ada port yang ditentukan, maka gunakan daftar tersebut
            else range(self.start_port, self.end_port + 1)  # Jika tidak, gunakan rentang port
        )

        # Loop untuk memindai setiap port dalam daftar atau rentang
        for port in ports_to_scan:
            try:
                if self.scan_type == "TCP":  # Jika pemindaian TCP
                    if self.tcp_scan_type == "SYN":  # Jika pemindaian menggunakan SYN scan
                        self._scan_syn(port)
                    else:
                        self._scan_tcp(port)
                elif self.scan_type == "UDP":  # Jika pemindaian UDP
                    self._scan_udp(port)
                else:
                    print(f"{self.error} Jenis pemindaian tidak valid.")  # Jika jenis pemindaian tidak valid
            except Exception as e:
                print(f"{self.error} Gagal memindai port {port}: {e}")  # Menampilkan error jika pemindaian gagal

        print(f"\n{self.info} Pemindaian selesai pada {datetime.now()}\n")  # Menampilkan waktu selesai pemindaian

    def _scan_tcp(self, port):
        """
        Fungsi untuk memindai port TCP menggunakan koneksi standar.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Menetapkan waktu tunggu 2 detik untuk koneksi
            try:
                result = s.connect_ex((self.target, port))  # Mencoba koneksi ke port
                if result == 0:  # Jika koneksi berhasil
                    message = f"{self.open} Port {port} terbuka (TCP)"  # Menampilkan port terbuka
                    print(message)
                    self._save_to_txt(message)  # Menyimpan hasil ke file
                else:  # Jika koneksi gagal
                    print(f"{self.close} Port {port} tertutup (TCP)")  # Menampilkan port tertutup
            except socket.timeout:  # Jika terjadi timeout
                print(f"{self.filter} Port {port} terfilter (TCP)")  # Menampilkan port terfilter
            except Exception as e:  # Menangani exception lain
                print(f"{self.error} Error: {e}")

    def _scan_udp(self, port):
        """
        Fungsi untuk memindai port UDP.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)  # Menetapkan waktu tunggu 2 detik untuk koneksi
            try:
                s.sendto(b"", (self.target, port))  # Mengirimkan paket kosong ke port
                print(f"{self.open} Port {port} terbuka (UDP)")  # Menampilkan port terbuka
            except Exception as e:  # Menangani error lain
                print(f"{self.close} Port {port} tertutup (UDP) atau error: {e}")  # Menampilkan port tertutup atau error

    def _scan_syn(self, port):
        """
        Melakukan pemindaian SYN menggunakan socket mentah.
        Membutuhkan izin root untuk melakukan pemindaian ini.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
                s.settimeout(1)  # Menetapkan waktu tunggu 1 detik
                src_ip = socket.gethostbyname(socket.gethostname())  # Mendapatkan alamat IP lokal
                tcp_header = self._create_tcp_syn_packet(src_ip, self.target, port)  # Membuat paket SYN
                s.sendto(tcp_header, (self.target, port))  # Mengirimkan paket SYN ke target

                try:
                    data = s.recv(1024)  # Menerima respons dari port
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
                except socket.timeout:  # Jika timeout
                    print(f"{self.close} Port {port} tidak merespon.")
        except PermissionError:  # Jika tidak memiliki izin root
            print(f"{self.error} Izin root diperlukan untuk pemindaian SYN.")

    def _create_tcp_syn_packet(self, src_ip, dest_ip, dest_port):
        """
        Fungsi untuk membuat paket TCP SYN mentah.
        """
        tcp_header = struct.pack(
            "!HHLLBBHHH",  # Struktur paket TCP
            12345,  # Nomor port sumber (random)
            dest_port,  # Port tujuan
            0,  # Nomor urut (0 untuk SYN)
            0,  # Nomor pengakuan (0 untuk SYN)
            (5 << 4) + 2,  # Ukuran header dan jenis flag (SYN)
            0,  # Data offset
            socket.htons(5840),  # Nomor window
            0,  # Checksum
            0,  # Urutan data
        )
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",  # Struktur header IP
            69,  # Versi IP
            0,  # Tipe layanan
            40,  # Panjang header IP
            54321,  # ID
            0,  # Frag offset
            255,  # TTL
            socket.IPPROTO_TCP,  # Protokol TCP
            0,  # Checksum
            socket.inet_aton(src_ip),  # IP sumber
            socket.inet_aton(dest_ip),  # IP tujuan
        )
        return ip_header + tcp_header  # Gabungkan header IP dan TCP untuk membentuk paket SYN

    def _save_to_txt(self, text):
        """
        Menyimpan hasil pemindaian ke file jika output file diset.
        """
        if self.output_file:
            with open(self.output_file, "a") as f:  # Membuka file dalam mode append
                f.write(text + "\n")  # Menulis hasil ke file
