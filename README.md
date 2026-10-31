# Zero Trust Academic Microservices

Implementasi arsitektur Zero Trust Security (berdasarkan prinsip NIST SP 800-207: never trust, always verify, least privilege, dan assume breach) pada sistem akademik berbasis mikrolayanan menggunakan Node.js dan Express.js.

---

## Arsitektur Sistem & Port
Sistem ini terdistribusi ke dalam beberapa komponen utama:
1. **API Gateway (Port 3000)**: Berperan sebagai *Policy Enforcement Point* (PEP) dan *Policy Engine*. Pintu masuk tunggal yang memvalidasi token JWT, pemeriksaan *Device ID*, pembatasan jam akses, pencatatan audit log, serta proxy request.
2. **Service Nilai (Port 3001)**: Mengelola data nilai dan kelas. Dilindungi oleh verifikasi *Gateway Secret* (`X-Gateway-Secret`) dan token internal service.
3. **Service Transkrip (Port 3002)**: Mengelola transkrip mahasiswa, menerima sinkronisasi data otomatis saat finalisasi kelas.
4. **Database Bersama**: Menggunakan SQLite (`academic.db`) dengan pustaka `better-sqlite3`.

---

## Prasyarat
* [Node.js](https://nodejs.org/) (Versi 18 atau lebih baru)
* Git

---

## Cara Menjalankan Proyek

Jalankan setiap layanan di terminal/command prompt yang terpisah dengan perintah berikut:

```bash
# 1. Jalankan Service Transkrip (Port 3002)
cd service-transkrip
npm install
npm start

# 2. Jalankan Service Nilai (Port 3001)
cd service-nilai
npm install
npm start

# 3. Jalankan API Gateway (Port 3000)
cd api-gateway
npm install
npm start

## DAFTAR AKUN DAN DEVICE ID DATA AWAL

| Role | NIM / NIDN | Password | Nama / Keterangan | Device ID Terdaftar |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin01` | `password123` | Admin | `device-admin-01` |
| **Dosen** | `dosen01` | `password123` | Dosen | `device-dosen-01` |
| **Dosen** | `dosen02` | `password123` | Dosen | `device-dosen-02` |
| **Mahasiswa** | `mhs01` | `password123` | Mahasiswa | `device-mhs-01` |
| **Mahasiswa** | `mhs02` | `password123` | Mahasiswa | `device-mhs-02` |
| **Mahasiswa** | `mhs03` | `password123` | Mahasiswa | `device-mhs-03` |