Tentu! Berikut adalah file README.md dalam format markdown yang dapat Anda gunakan:

# Port Scanner oleh PSocietyyy

Port Scanner ini adalah alat sederhana untuk memindai port TCP, UDP, dan melakukan pemindaian SYN pada alamat IP atau nama host. Pengguna dapat melakukan pemindaian port dalam rentang yang ditentukan atau dengan memilih port tertentu. Alat ini memungkinkan pemilihan jenis pemindaian (TCP/UDP/SYN) dan pengaturan lainnya.

## Fitur

- Pemindaian untuk port TCP, UDP, dan SYN.
- Pilih rentang port yang ingin dipindai.
- Pilih port spesifik dengan format daftar.
- Menyediakan pemindaian dengan waktu tunggu (timeout) 2 detik.
- Menampilkan hasil pemindaian, seperti port yang terbuka, tertutup, atau terfilter.
- Menggunakan argparse untuk menangani input dari baris perintah.
- Mendukung pemindaian SYN menggunakan opsi `-sS`.

## Cara Instalasi

1. Clone repository ini:

   ```bash
   git clone https://github.com/PSocietyyy/Port_scanner.git
   cd port_scanner
   ```

2. Install dependensi yang diperlukan (jika ada).

## Cara Penggunaan

### Format Perintah Dasar

```bash
python main.py -t <target> -sP <start_port> -eP <end_port> -st <scan_type> [-sS]
```

- `-t` : IP atau hostname target untuk dipindai (Wajib).
- `-sP` : Port awal untuk pemindaian (opsional, default: 1).
- `-eP` : Port akhir untuk pemindaian (opsional, default: 9999).
- `-p` : Daftar port spesifik yang dipisahkan koma, contohnya: `22,80,443` (opsional).
- `-st` : Jenis pemindaian: pilih `TCP`, `UDP`, atau `SYN` (opsional, default: `TCP`).
- `-sS` : Menyediakan pemindaian SYN (suitable untuk testing port terbuka melalui paket SYN).

### Contoh Penggunaan

#### Memindai Port TCP dalam Rentang 1-1000:

```bash
python main.py -t 192.168.1.1 -sP 1 -eP 1000
```

#### Memindai Port UDP dalam Rentang 1-1000:

```bash
python main.py -t 192.168.1.1 -sP 1 -eP 1000 -st UDP
```

#### Memindai Port Spesifik (misalnya port 22, 80, 443):

```bash
python main.py -t 192.168.1.1 -p 22,80,443
```

#### Memindai Port UDP Spesifik:

```bash
python main.py -t 192.168.1.1 -p 53,161 -st UDP
```

#### Pemindaian dengan Rentang Semua Port (1-9999):

```bash
python main.py -t 192.168.1.1 -sP 1 -eP 9999
```

#### Pemindaian SYN untuk Port Spesifik (misalnya 22, 80):

```bash
python main.py -t 192.168.1.1 -p 22,80 -st TCP -sS
```

### Penjelasan

- **`-t` / `--target`** : Masukkan alamat IP atau nama host untuk pemindaian.
- **`-sP` / `--start_port`** : Tentukan port awal (misalnya `1`).
- **`-eP` / `--end_port`** : Tentukan port akhir (misalnya `1000`).
- **`-p` / `--ports`** : Tentukan port-port tertentu yang dipisahkan oleh koma, misalnya `22,80,443`.
- **`-st` / `--scan_type`** : Tentukan jenis pemindaian, pilih antara `TCP`, `UDP`, atau `SYN`.
- **`-sS`** : Melakukan pemindaian SYN untuk port yang lebih cepat dan akurat.

### Hasil Pemindaian

Setelah pemindaian selesai, hasil akan ditampilkan dengan format berikut:

- **[OPEN] Port <nomor_port> terbuka (TCP/UDP/SYN)**
- **[CLOSED] Port <nomor_port> tertutup (TCP/UDP/SYN)**
- **[FILTERED] Port <nomor_port> terfilter (TCP)**

### Pengaturan Default

Pemindaian dilakukan dengan pengaturan default berikut:

- **Rentang Port** : 1-9999.
- **Jenis Pemindaian** : TCP (secara default).

Pengaturan ini dapat diubah di file `config/settings.py`.

## Lisensi

Port Scanner ini dirilis di bawah **MIT License**.

```

Silakan simpan konten di atas ke dalam file `README.md` pada project Anda. Ini sudah mencakup berbagai penggunaan, opsi pemindaian, dan penjelasan singkat mengenai fungsionalitas port scanner Anda.
```
