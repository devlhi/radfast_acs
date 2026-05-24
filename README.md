# RadFast ACS

**GenieACS v1.2.16 — Multi-Instance ACS Manager**  
Support Ubuntu 20.04 / 22.04 / 24.04 | Node.js 18 | MongoDB 7.0  
By RadFast Bill

---

## Cara Install di VPS

### 1. Clone repo

```bash
git clone https://github.com/devlhi/radfast_acs.git
cd radfast_acs
```

### 2. Setup sistem (jalankan SEKALI saja)

Perintah ini akan install Node.js 18, MongoDB 7.0, dan deploy app GenieACS.

```bash
sudo bash setup-system.sh
```

---

## Tambah Instance / User Baru

Setiap user mendapat folder sendiri, database sendiri, dan port sendiri (otomatis).

```bash
sudo bash add-instance.sh
```

Atau langsung dengan nama:

```bash
sudo bash add-instance.sh namauser
```

Contoh output:
```
  User     : alice
  UI Port  : 3001   → http://1.2.3.4:3001
  CWMP Port: 7548
  NBI Port : 7558
  FS Port  : 7568
  Database : genieacs_alice
```

---

## Lihat Semua Instance

```bash
bash list-instances.sh
```

Menampilkan semua instance beserta port, status service, dan URL akses.

---

## Hapus Instance

```bash
sudo bash remove-instance.sh namauser
```

> ⚠️ Database MongoDB instance tersebut akan ikut dihapus permanen.

---

## Update ke Versi Terbaru

```bash
cd radfast_acs
git pull
sudo bash setup-system.sh
```

> Instance yang sudah berjalan tidak terganggu. App baru akan di-deploy ke `/opt/genieacs-app`.  
> Restart service untuk pakai versi terbaru:
> ```bash
> sudo systemctl restart genieacs-NAMAUSER-cwmp
> sudo systemctl restart genieacs-NAMAUSER-ui
> ```

---

## Struktur di VPS Setelah Install

```
/opt/genieacs-app/              ← App GenieACS (shared, 1 copy)
/opt/genieacs-instances/
├── .registry                   ← Daftar semua instance
├── alice/
│   └── .env                    ← Config port & database alice
├── bob/
│   └── .env
└── ...
```

Systemd services per instance:
```
genieacs-alice-cwmp.service
genieacs-alice-fs.service
genieacs-alice-nbi.service
genieacs-alice-ui.service
```

---

## Port Default (auto-increment jika sudah dipakai)

| Service | Port Awal |
|---------|-----------|
| UI      | 3001, 3002, 3003... |
| CWMP    | 7548, 7549, 7550... |
| NBI     | 7558, 7559, 7560... |
| FS      | 7568, 7569, 7570... |

---

## Manage Instance

```bash
# Cek status
systemctl status genieacs-alice-ui

# Lihat log realtime
journalctl -u genieacs-alice-ui -f

# Restart
systemctl restart genieacs-alice-cwmp
systemctl restart genieacs-alice-ui

# Stop semua service 1 instance
systemctl stop genieacs-alice-cwmp genieacs-alice-fs genieacs-alice-nbi genieacs-alice-ui
```

---

## Persyaratan VPS

- OS: Ubuntu 20.04 / 22.04 / 24.04 (atau RHEL/CentOS)
- RAM: minimal 1 GB per instance
- Akses root / sudo

---

## Support OS

| OS | Status |
|----|--------|
| Ubuntu 20.04 (Focal)  | ✅ |
| Ubuntu 22.04 (Jammy)  | ✅ |
| Ubuntu 24.04 (Noble)  | ✅ |
| RHEL / CentOS         | ✅ |
