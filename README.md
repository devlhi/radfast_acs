# RadFast ACS

**GenieACS v1.2.16 — Multi-Instance ACS Manager**  
Support Ubuntu 20.04 / 22.04 / 24.04 | Node.js 20 LTS | MongoDB 7.0/8.0  
By RadFast Bill

[![Release](https://img.shields.io/github/v/release/devlhi/radfast_acs?style=flat-square)](https://github.com/devlhi/radfast_acs/releases/latest)
[![License](https://img.shields.io/github/license/devlhi/radfast_acs?style=flat-square)](LICENSE)

---

## ⚡ Install (Cara Tercepat)

Cukup jalankan **satu perintah** di VPS:

**Pakai curl:**
```bash
curl -fsSL https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | sudo bash
```

**Pakai wget:**
```bash
wget -qO- https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | sudo bash
```

> Script otomatis mendeteksi jika dijalankan via pipe dan menanganinya  
> sendiri — prompt interaktif tetap tampil normal di semua sistem  
> (bare metal, VM, LXC container).

> Script otomatis:
> 1. Install Node.js 20 LTS, MongoDB 7.0/8.0, Git
> 2. Clone repo ke `/opt/radfast_acs`
> 3. Deploy GenieACS ke `/opt/genieacs-app`
> 4. Tanya apakah langsung tambah instance/user

---

## 📦 Download Releases

Setiap versi stabil tersedia di halaman **[Releases](https://github.com/devlhi/radfast_acs/releases)**.

### Install dari versi spesifik (bukan main/latest)

```bash
# Ganti v1.0.0 dengan versi yang diinginkan
VER=v1.0.0
wget -O /tmp/radfast_acs.tar.gz https://github.com/devlhi/radfast_acs/archive/refs/tags/${VER}.tar.gz
tar -xzf /tmp/radfast_acs.tar.gz -C /tmp
sudo bash /tmp/radfast_acs-${VER#v}/setup-system.sh
```

### Install versi terbaru dari Releases (bukan dari main)

```bash
# Ambil tag versi terbaru otomatis
VER=$(curl -fsSL https://api.github.com/repos/devlhi/radfast_acs/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
wget -O /tmp/radfast_acs.tar.gz https://github.com/devlhi/radfast_acs/archive/refs/tags/${VER}.tar.gz
tar -xzf /tmp/radfast_acs.tar.gz -C /tmp
sudo bash /tmp/radfast_acs-${VER#v}/setup-system.sh
```

> **Kapan pakai Releases vs main?**
> | | Releases | main (default) |
> |--|----------|---------------|
> | Stabilitas | ✅ Sudah diuji & tagged | ⚠️ Development aktif |
> | Cocok untuk | Production VPS | Test / dev |
> | Auto update | Manual pilih versi | `git pull` ambil terbaru |

---

## 🔄 Update ke Versi Terbaru

Jalankan ulang installer — script otomatis `git pull` jika repo sudah ada:

```bash
wget -O /tmp/r.sh https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh && sudo bash /tmp/r.sh
```

Atau manual:

```bash
cd /opt/radfast_acs && git pull
sudo bash setup-system.sh
```

> Instance yang sudah berjalan **tidak terganggu**.  
> Restart service untuk pakai versi terbaru:
> ```bash
> sudo systemctl restart genieacs-NAMAUSER-proxy
> sudo systemctl restart genieacs-NAMAUSER-ui
> ```

---

## 👤 Tambah User/Instance Baru

Setiap user mendapat port sendiri, database sendiri, folder sendiri — otomatis.

```bash
sudo radfast-add
# atau
sudo bash /opt/radfast_acs/add-instance.sh
```

Contoh hasil:
```
  User     : alice
  UI       : http://1.2.3.4:3001   ← Dashboard Web
  CWMP     : 7548                  ← ACS URL device TR-069
  NBI      : 7558                  ← REST API
  FS       : 7568                  ← File Server
  Database : genieacs_alice
```

---

## 🖼 Upload Logo (tanpa terminal)

Setiap instance punya tombol **"Ganti Logo Klik"** (merah) di navbar dashboard.

1. Buka dashboard: `http://IP:PORT`
2. Klik tombol **Ganti Logo Klik** di pojok kiri navbar
3. Pilih file logo (SVG / PNG / JPG / GIF / WebP — maks 2 MB)
4. Preview muncul otomatis → klik **Upload Logo**

> Logo langsung berubah tanpa restart.

---

## 📋 Shortcut Commands

```bash
radfast-add      # tambah instance/user baru
radfast-list     # lihat semua instance + port
radfast-status   # monitor CPU/RAM/disk + status service
radfast-remove   # hapus instance (termasuk database)
radfast-multi    # jalankan multi-proxy mode (semua instance dalam 1 proses Node.js)
```

---

## 🗂 Struktur di VPS Setelah Install

```
/opt/radfast_acs/               ← Script installer (dari repo ini)
├── logo-proxy.js               ← Proxy instance tunggal
├── multi-proxy.js              ← Proxy multi-instance (1 proses Node.js)
├── add-instance.sh             ← Tambah instance baru
└── remove-instance.sh          ← Hapus instance
/opt/genieacs-app/              ← App GenieACS (shared, 1 copy)
/opt/genieacs-instances/
├── .registry                   ← Daftar semua instance
├── alice/
│   ├── .env                    ← Config port & database alice
│   └── logo/                   ← Custom logo alice
├── bob/
│   └── .env
└── ...
```

### Mode Standar (per-instance proxy)

Setiap instance punya Node.js proxy sendiri:
```
genieacs-alice-cwmp.service    ← TR-069 device
genieacs-alice-fs.service      ← File server
genieacs-alice-nbi.service     ← REST API
genieacs-alice-ui.service      ← UI internal
genieacs-alice-proxy.service   ← Proxy publik + logo manager
```

### Mode Multi-Proxy ⭐ (recommended)

Semua instance proxy digabung dalam **1 proses Node.js** → hemat RAM:
```
genieacs-alice-cwmp.service    ← TR-069 device
genieacs-alice-fs.service      ← File server
genieacs-alice-nbi.service     ← REST API
genieacs-alice-ui.service      ← UI internal
                                ← proxy TIDAK per-instance

genieacs-multi-proxy.service   ← Semua proxy dalam 1 proses Node.js
```

> `radfast-add` otomatis mendeteksi mode multi-proxy.
> Instance baru langsung aktif tanpa restart manual.

---

## 🔌 Port & Fungsi Tiap Service

| Service | Port Mulai | Fungsi |
|---------|------------|--------|
| **UI (proxy)** | 3001, 3002... | Dashboard web publik — buka di browser |
| **CWMP** | 7548, 7549... | Port device/CPE TR-069 (ONU, router) |
| **NBI**  | 7558, 7559... | REST API untuk integrasi billing/monitoring |
| **FS**   | 7568, 7569... | File server firmware & config device |

---

## 🛠 Manage Instance

```bash
# Status semua instance
radfast-status

# Status instance tertentu
radfast-status alice

# Log realtime (_mode standar_)
journalctl -u genieacs-alice-proxy -f
journalctl -u genieacs-alice-ui -f

# Log realtime (mode multi-proxy)
journalctl -u genieacs-multi-proxy -f

# Restart
systemctl restart genieacs-alice-proxy      # mode standar
systemctl restart genieacs-multi-proxy       # mode multi-proxy
systemctl restart genieacs-alice-cwmp

# Stop semua service 1 instance
systemctl stop genieacs-alice-{cwmp,fs,nbi,ui,proxy}
```

### Mode Multi-Proxy

```bash
# Jalankan multi-proxy (semua instance dalam 1 proses)
sudo radfast-multi
# atau
sudo node /opt/radfast_acs/multi-proxy.js

# Restart multi-proxy (setelah tambah instance baru)
sudo systemctl restart genieacs-multi-proxy

# Cek status multi-proxy
sudo systemctl status genieacs-multi-proxy

# Log multi-proxy realtime
journalctl -u genieacs-multi-proxy -f
```

> **Keuntungan multi-proxy:** hemat RAM karena hanya 1 proses Node.js
> untuk semua instance logo/proxy. Perubahan logo instance tetap langsung tanpa restart.

---

## 🖥️ Support OS

| OS | MongoDB | Status |
|----|---------|--------|
| Ubuntu 20.04 (Focal) | 7.0 | ✅ |
| Ubuntu 22.04 (Jammy) | 7.0 | ✅ |
| Ubuntu 24.04 (Noble) | 8.0 | ✅ |
| RHEL / CentOS        | 7.0 | ✅ |

---

## 📋 Persyaratan VPS

- RAM minimal 512 MB (rekomendasi 1 GB per instance)
- Akses root / sudo
- Port tidak diblokir firewall
- Koneksi internet (untuk download Node.js & MongoDB)

---

## 🧠 Multi-Proxy Mode — Arsitektur

Untuk **hemat RAM**, semua instance logo/proxy bisa digabung dalam **satu proses Node.js**
menggunakan `multi-proxy.js`.

### Cara Kerja

```
Browser ──:3001──► genieacs-multi-proxy ──:13001──► GenieACS UI alice
            ──:3002──► genieacs-multi-proxy ──:13002──► GenieACS UI bob
            ──:3003──► genieacs-multi-proxy ──:13003──► GenieACS UI charlie
```

- 1 proses Node.js melayani **semua instance**
- Port publik → port internal dipetakan dari `.registry`
- Setiap instance login dengan `RADFAST_ADMIN_TOKEN` sendiri
- Logo per-instance dibaca dari `/opt/genieacs-instances/{user}/logo/`
- CSRF, rate limiter, IP blocker berjalan terisolasi per-instance

### Aktifkan Mode Multi-Proxy

```bash
# 1. Buat file .registry (otomatis jika sudah pakai radfast-add)
ls -la /opt/genieacs-instances/.registry

# 2. Install service systemd
sudo tee /etc/systemd/system/genieacs-multi-proxy.service << 'EOF'
[Unit]
Description=RadFast ACS Multi-Instance Logo Proxy
After=network.target

[Service]
Type=simple
Environment=NODE_ENV=production
ExecStart=/usr/bin/node /opt/radfast_acs/multi-proxy.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=genieacs-multi-proxy
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 3. Reload & start
sudo systemctl daemon-reload
sudo systemctl enable genieacs-multi-proxy
sudo systemctl start genieacs-multi-proxy

# 4. Verifikasi
sudo systemctl status genieacs-multi-proxy
journalctl -u genieacs-multi-proxy -f
```

### Migrasi dari Mode Standar ke Multi-Proxy

```bash
# 1. Stop semua proxy per-instance
for USER in $(awk '{print $1}' /opt/genieacs-instances/.registry); do
    sudo systemctl stop genieacs-${USER}-proxy 2>/dev/null
    sudo systemctl disable genieacs-${USER}-proxy 2>/dev/null
done

# 2. Jalankan multi-proxy
sudo systemctl start genieacs-multi-proxy

# 3. Verifikasi semua instance aktif
sudo systemctl status genieacs-multi-proxy
# Contoh output:
# [logo-proxy] :3001 → GenieACS UI :13001
# [logo-proxy] :3002 → GenieACS UI :13002
```

### Format .registry

```
USERNAME UI=3001 CWMP=7548 NBI=7558 FS=7568 DB=genieacs_alice IP=1.2.3.4 DATE=2026-05-29
bob UI=3002 CWMP=7549 NBI=7559 FS=7569 DB=genieacs_bob IP=1.2.3.4 DATE=2026-05-29
```
