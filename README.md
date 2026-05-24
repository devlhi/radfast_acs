# RadFast ACS

**GenieACS v1.2.16 — Multi-Instance ACS Manager**  
Support Ubuntu 20.04 / 22.04 / 24.04 | Node.js 18 | MongoDB 7.0  
By RadFast Bill

---

## ⚡ Install (Cara Tercepat)

Cukup jalankan **dua perintah** di VPS:

**Pakai wget:**
```bash
wget -O /tmp/r.sh https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh && sudo bash /tmp/r.sh
```

**Pakai curl:**
```bash
curl -fsSL https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh -o /tmp/r.sh && sudo bash /tmp/r.sh
```

> ℹ️ **Kenapa download dulu?**  
> Cara `curl | bash` (pipe langsung) menyebabkan layar blank karena bash menunggu  
> koneksi ke GitHub. Download ke `/tmp/r.sh` dulu lebih aman dan tampil progress.

> Script akan otomatis:
> 1. Install Node.js 18, MongoDB 7.0, Git
> 2. Clone repo ke `/opt/radfast_acs`
> 3. Deploy GenieACS ke `/opt/genieacs-app`
> 4. Tanya apakah langsung tambah instance/user

---

## Tambah User/Instance Baru

Setiap user mendapat port sendiri, database sendiri, folder sendiri — otomatis.

```bash
sudo bash /opt/radfast_acs/add-instance.sh
```

Contoh hasil:
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
bash /opt/radfast_acs/list-instances.sh
```

---

## Hapus Instance

```bash
sudo bash /opt/radfast_acs/remove-instance.sh namauser
```

> ⚠️ Database MongoDB instance tersebut ikut dihapus permanen.

---

## Update ke Versi Terbaru

Cukup jalankan ulang perintah install — script otomatis `git pull` jika repo sudah ada:

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
> sudo systemctl restart genieacs-NAMAUSER-cwmp
> sudo systemctl restart genieacs-NAMAUSER-ui
> ```

---

## Struktur di VPS Setelah Install

```
/opt/radfast_acs/               ← Script installer (dari repo ini)
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

## Port & Fungsi Tiap Service

| Service | Port Mulai | Fungsi |
|---------|------------|--------|
| **UI**   | 3001, 3002... | Dashboard web — login, kelola device, lihat status |
| **CWMP** | 7548, 7549... | Port untuk device/CPE TR-069 (ONU, router) daftar & kirim data |
| **NBI**  | 7558, 7559... | Northbound Interface — REST API untuk integrasi sistem lain (billing, monitoring, automation) |
| **FS**   | 7568, 7569... | File Server — tempat device download firmware, config, atau script |

> **Singkatnya:**
> - **UI** = buka di browser, buat operator/admin
> - **CWMP** = arahkan TR-069 device ke port ini
> - **NBI** = pakai untuk hit API dari aplikasi lain
> - **FS** = otomatis dipakai GenieACS saat push firmware/file ke device

---

## Manage Instance

```bash
# Status
systemctl status genieacs-alice-ui

# Log realtime
journalctl -u genieacs-alice-ui -f

# Restart
systemctl restart genieacs-alice-cwmp
systemctl restart genieacs-alice-ui

# Stop semua service 1 instance
systemctl stop genieacs-alice-{cwmp,fs,nbi,ui}
```

---

## Support OS

| OS | Status |
|----|--------|
| Ubuntu 20.04 (Focal) | ✅ |
| Ubuntu 22.04 (Jammy) | ✅ |
| Ubuntu 24.04 (Noble) | ✅ |
| RHEL / CentOS        | ✅ |

---

## Persyaratan VPS

- RAM minimal 512 MB (rekomendasi 1 GB per instance)
- Akses root / sudo
- Port tidak diblokir firewall
