import argparse
from utils.port_scanner import PortScanner

logo = """
d8888b. .d8888.  .d88b.   .o88b. d888888b d88888b d888888b db    db db    db db    db 
88  `8D 88'  YP .8P  Y8. d8P  Y8   `88'   88'     `~~88~~' `8b  d8' `8b  d8' `8b  d8' 
88oodD' `8bo.   88    88 8P         88    88ooooo    88     `8bd8'   `8bd8'   `8bd8'  
88~~~     `Y8b. 88    88 8b         88    88~~~~~    88       88       88       88    
88      db   8D `8b  d8' Y8b  d8   .88.   88.        88       88       88       88    
88      `8888Y'  `Y88P'   `Y88P' Y888888P Y88888P    YP       YP       YP       YP    
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        print(logo),
        description="Port Scanner sederhana by PSocietyyy",
        epilog="contoh penggunaan: python3 main.py -t 192.168.1.1 -sP 1 -eP 1000 -st TCP -sS\natau\npython3 main.py -t 192.168.1.1 -p 22,80,443 -st UDP"
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP atau hostname")
    parser.add_argument("-sP", "--start_port", type=int, default=1, help="Port awal untuk dipindai")
    parser.add_argument("-eP", "--end_port", type=int, default=9999, help="Port akhir yang dipindai")
    parser.add_argument("-p", "--ports", help="Daftar port spesifik (22,80,443)")
    parser.add_argument("-st", "--scan_type", choices=["TCP", "UDP"], default="TCP", help="Jenis pemindaian")
    parser.add_argument("-sS", "--syn_scan", action="store_true", help="Gunakan SYN scan untuk TCP (harus sebagai sudo[linux] atau administrator[windows])")
    parser.add_argument("-o", "--output", help="Simpan output ke file")

    args = parser.parse_args()

    ports = list(map(int, args.ports.split(","))) if args.ports else None
    tcp_scan_type = "SYN" if args.syn_scan else "CONNECT"

    scanner = PortScanner(
        target=args.target,
        start_port=args.start_port,
        end_port=args.end_port,
        port_scanning_list=ports,
        scan_type=args.scan_type,
        tcp_scan_type=tcp_scan_type,
        output_file=args.output,
    )

    
    scanner.scan_port()
