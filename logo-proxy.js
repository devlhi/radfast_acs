#!/usr/bin/env node
// ============================================================
//  logo-proxy.js — Reverse proxy + Logo Upload untuk GenieACS
//  By RadFast Bill
//  Tidak butuh npm install — pakai built-in Node.js saja
// ============================================================
'use strict';

const http  = require('http');
const fs    = require('fs');
const path  = require('path');

const PUBLIC_PORT   = parseInt(process.env.RADFAST_PROXY_PORT   || 3001);
const GENIE_PORT    = parseInt(process.env.RADFAST_UI_INTERNAL  || 13001);
const LOGO_BASE     = process.env.RADFAST_LOGO_FILE || '/tmp/radfast-logo';
const ADMIN_TOKEN   = process.env.RADFAST_ADMIN_TOKEN || 'changeme';
const MAX_SIZE      = 2 * 1024 * 1024; // 2 MB

// ── Cari logo custom yg tersimpan ────────────────────────────
function findCustomLogo() {
    for (const ext of ['.svg', '.png', '.jpg', '.jpeg']) {
        const f = LOGO_BASE + ext;
        if (fs.existsSync(f)) return f;
    }
    return null;
}

// ── Content-Type dari ekstensi ────────────────────────────────
const MIME = {
    '.svg'  : 'image/svg+xml',
    '.png'  : 'image/png',
    '.jpg'  : 'image/jpeg',
    '.jpeg' : 'image/jpeg'
};

// ── Parse multipart/form-data (no libs) ──────────────────────
function parseMultipart(body, boundary) {
    const sep    = Buffer.from('\r\n--' + boundary);
    const result = {};
    let pos = body.indexOf('--' + boundary);
    if (pos < 0) return result;
    pos += ('--' + boundary).length + 2;

    while (pos < body.length) {
        // Find header end
        const hEnd = body.indexOf(Buffer.from('\r\n\r\n'), pos);
        if (hEnd < 0) break;
        const headers = body.slice(pos, hEnd).toString();

        const nameM     = headers.match(/name="([^"]+)"/);
        const fileM     = headers.match(/filename="([^"]*)"/);
        const ctM       = headers.match(/Content-Type:\s*(\S+)/i);
        const dataStart = hEnd + 4;
        const dataEnd   = body.indexOf(sep, dataStart);

        if (nameM) {
            const data = body.slice(dataStart, dataEnd < 0 ? undefined : dataEnd);
            result[nameM[1]] = {
                value    : fileM ? null : data.toString(),
                data     : data,
                filename : fileM ? fileM[1] : null,
                mime     : ctM ? ctM[1] : 'text/plain'
            };
        }
        if (dataEnd < 0) break;
        pos = dataEnd + sep.length;
        // Check final boundary (--)
        if (body.slice(pos, pos + 2).toString() === '--') break;
        pos += 2; // skip \r\n
    }
    return result;
}

// ── Upload Form HTML ─────────────────────────────────────────
function uploadPage(msg = '') {
    const custom = findCustomLogo();
    return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Upload Logo — RadFast ACS</title>
<style>
  *{box-sizing:border-box}
  body{font-family:Arial,sans-serif;background:#f0f2f5;margin:0;padding:30px}
  .card{max-width:480px;margin:0 auto;background:#fff;border-radius:10px;padding:32px;box-shadow:0 2px 12px rgba(0,0,0,.1)}
  h2{margin:0 0 20px;color:#333;font-size:20px}
  label{display:block;font-size:13px;font-weight:bold;color:#555;margin:14px 0 4px}
  input[type=password],input[type=file]{width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px}
  .btn{display:inline-block;padding:10px 24px;border:none;border-radius:6px;font-size:14px;cursor:pointer;margin-top:16px}
  .btn-green{background:#27ae60;color:#fff}.btn-green:hover{background:#219a52}
  .btn-red{background:#e74c3c;color:#fff;font-size:13px;padding:8px 18px}.btn-red:hover{background:#c0392b}
  .msg{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:14px}
  .ok{background:#d4edda;color:#155724;border:1px solid #c3e6cb}
  .err{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}
  .preview{margin:16px 0;text-align:center}
  .preview img{max-height:70px;max-width:260px;border:1px solid #ddd;border-radius:6px;padding:8px;background:#fafafa}
  .preview p{font-size:12px;color:#888;margin:6px 0 0}
  hr{border:none;border-top:1px solid #eee;margin:20px 0}
  .note{font-size:12px;color:#888;margin-top:12px}
  .back{display:inline-block;margin-top:14px;font-size:13px;color:#3498db;text-decoration:none}
  .back:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
  <h2>🖼 Upload Logo GenieACS</h2>
  ${msg}
  ${custom ? `
  <div class="preview">
    <img src="/__admin/logo/preview?t=${Date.now()}" alt="Logo saat ini">
    <p>Logo saat ini</p>
  </div>` : '<p style="color:#999;font-size:13px">Belum ada logo custom — menampilkan logo default.</p>'}

  <form method="POST" action="/__admin/logo/upload" enctype="multipart/form-data">
    <label>🔑 Token Admin</label>
    <input type="password" name="token" placeholder="Masukkan admin token" required autocomplete="off">
    <label>📁 File Logo (SVG / PNG / JPG — maks 2 MB)</label>
    <input type="file" name="logo" accept=".svg,.png,.jpg,.jpeg" required>
    <button type="submit" class="btn btn-green">⬆ Upload Logo</button>
  </form>

  ${custom ? `
  <hr>
  <form method="POST" action="/__admin/logo/reset">
    <input type="hidden" name="token" value="">
    <label>🔑 Token Admin (untuk reset)</label>
    <input type="password" name="token" placeholder="Masukkan admin token" required>
    <button type="submit" class="btn btn-red">🗑 Reset ke Logo Default</button>
  </form>` : ''}

  <p class="note">💡 Logo akan langsung aktif tanpa perlu restart service.</p>
  <a class="back" href="/">← Kembali ke Dashboard</a>
</div>
</body>
</html>`;
}

// ── Proxy ke GenieACS UI ─────────────────────────────────────
function proxyRequest(req, res) {
    const opts = {
        hostname : '127.0.0.1',
        port     : GENIE_PORT,
        path     : req.url,
        method   : req.method,
        headers  : { ...req.headers, host: `127.0.0.1:${GENIE_PORT}` }
    };
    const proxy = http.request(opts, (pRes) => {
        res.writeHead(pRes.statusCode, pRes.headers);
        pRes.pipe(res);
    });
    proxy.on('error', () => {
        res.writeHead(502, { 'Content-Type': 'text/html' });
        res.end('<h3>502 — GenieACS UI sedang tidak berjalan</h3>');
    });
    req.pipe(proxy);
}

// ── Main HTTP Server ─────────────────────────────────────────
const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0];

    // ── Admin: tampilkan form ──────────────────────────────
    if (url === '/__admin/logo' || url === '/__admin/logo/') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(uploadPage());
        return;
    }

    // ── Admin: preview logo ────────────────────────────────
    if (url === '/__admin/logo/preview') {
        const f = findCustomLogo();
        if (f) {
            const ext = path.extname(f).toLowerCase();
            res.writeHead(200, { 'Content-Type': MIME[ext] || 'image/svg+xml', 'Cache-Control': 'no-cache' });
            fs.createReadStream(f).pipe(res);
        } else {
            res.writeHead(404); res.end();
        }
        return;
    }

    // ── Admin: handle upload ───────────────────────────────
    if (url === '/__admin/logo/upload' && req.method === 'POST') {
        const ct = req.headers['content-type'] || '';
        const bm = ct.match(/boundary=([^\s;]+)/);
        if (!bm) { res.writeHead(400); res.end('Bad request'); return; }

        const chunks = [];
        let total = 0;
        req.on('data', c => {
            total += c.length;
            if (total > MAX_SIZE + 8192) { req.destroy(); return; }
            chunks.push(c);
        });
        req.on('end', () => {
            try {
                const body  = Buffer.concat(chunks);
                const parts = parseMultipart(body, bm[1].replace(/^"|"$/g, ''));

                // Cek token
                const tok = (parts.token && parts.token.value) ? parts.token.value.trim() : '';
                if (tok !== ADMIN_TOKEN) {
                    res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(uploadPage('<div class="msg err">❌ Token salah!</div>'));
                    return;
                }

                const file = parts.logo;
                if (!file || !file.data || file.data.length < 10) {
                    res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(uploadPage('<div class="msg err">❌ File tidak valid.</div>'));
                    return;
                }

                // Deteksi ekstensi dari filename & content-type
                const origExt = path.extname(file.filename || '').toLowerCase();
                const mimeExt = { 'image/svg+xml': '.svg', 'image/png': '.png', 'image/jpeg': '.jpg' };
                const useExt  = MIME[origExt] ? origExt : (mimeExt[file.mime] || '.svg');

                if (!MIME[useExt]) {
                    res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(uploadPage('<div class="msg err">❌ Format tidak didukung. Gunakan SVG, PNG, atau JPG.</div>'));
                    return;
                }

                // Hapus logo lama
                for (const e of ['.svg', '.png', '.jpg', '.jpeg']) {
                    try { fs.unlinkSync(LOGO_BASE + e); } catch(_) {}
                }

                // Simpan logo baru
                const savePath = LOGO_BASE + useExt;
                fs.mkdirSync(path.dirname(savePath), { recursive: true });
                fs.writeFileSync(savePath, file.data);

                console.log(`[logo-proxy] Logo diupdate: ${savePath} (${file.data.length} bytes)`);

                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(uploadPage('<div class="msg ok">✅ Logo berhasil diupload!</div>'));

            } catch(e) {
                console.error('[logo-proxy] Upload error:', e.message);
                res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(uploadPage(`<div class="msg err">❌ Error: ${e.message}</div>`));
            }
        });
        return;
    }

    // ── Admin: reset logo ──────────────────────────────────
    if (url === '/__admin/logo/reset' && req.method === 'POST') {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            const body = Buffer.concat(chunks).toString();
            const tok  = (body.match(/token=([^&]*)/) || [])[1] || '';
            if (decodeURIComponent(tok).trim() !== ADMIN_TOKEN) {
                res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(uploadPage('<div class="msg err">❌ Token salah!</div>'));
                return;
            }
            for (const e of ['.svg', '.png', '.jpg', '.jpeg']) {
                try { fs.unlinkSync(LOGO_BASE + e); } catch(_) {}
            }
            console.log('[logo-proxy] Logo direset ke default');
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(uploadPage('<div class="msg ok">✅ Logo direset ke default GenieACS.</div>'));
        });
        return;
    }

    // ── Intercept logo GenieACS (/public/logo-*.svg|png|jpg) ──
    if (/\/public\/logo-[^/]+\.(svg|png|jpg|jpeg)/i.test(req.url)) {
        const custom = findCustomLogo();
        if (custom) {
            const ext = path.extname(custom).toLowerCase();
            res.writeHead(200, {
                'Content-Type'  : MIME[ext] || 'image/svg+xml',
                'Cache-Control' : 'no-cache'
            });
            fs.createReadStream(custom).pipe(res);
            return;
        }
    }

    // ── Semua request lain → proxy ke GenieACS UI ─────────
    proxyRequest(req, res);
});

// Handle upgrade (untuk koneksi WebSocket jika ada)
server.on('upgrade', (req, socket, head) => {
    const conn = http.request({
        hostname : '127.0.0.1',
        port     : GENIE_PORT,
        path     : req.url,
        method   : req.method,
        headers  : req.headers
    });
    conn.on('upgrade', (res, proxySocket, proxyHead) => {
        socket.write('HTTP/1.1 101 Switching Protocols\r\n' +
            Object.keys(res.headers).map(k => `${k}: ${res.headers[k]}`).join('\r\n') +
            '\r\n\r\n');
        proxySocket.pipe(socket).pipe(proxySocket);
    });
    conn.end();
});

server.on('error', err => {
    console.error('[logo-proxy] Error:', err.message);
    process.exit(1);
});

server.listen(PUBLIC_PORT, '::', () => {
    console.log(`[logo-proxy] Port :${PUBLIC_PORT} → GenieACS UI :${GENIE_PORT}`);
    console.log(`[logo-proxy] Upload logo: http://<ip>:${PUBLIC_PORT}/__admin/logo`);
});
