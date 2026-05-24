#!/usr/bin/env node
// ============================================================
//  logo-proxy.js — Secure Reverse Proxy + Logo Upload
//  By RadFast Bill
//
//  Security features:
//  - Rate limiting (5 attempts/menit per IP, lockout 30 menit)
//  - Timing-safe token comparison (anti brute-force timing)
//  - SVG sanitization (hapus <script>, event handlers, JS refs)
//  - Magic bytes validation PNG/JPG (cegah file palsu)
//  - Path traversal protection
//  - Security HTTP headers (CSP, nosniff, X-Frame, dll)
//  - Audit log setiap percobaan upload
//  - Max file size check di level stream
//  - Tidak expose error detail ke client
// ============================================================
'use strict';

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PUBLIC_PORT  = parseInt(process.env.RADFAST_PROXY_PORT   || 3001);
const GENIE_PORT   = parseInt(process.env.RADFAST_UI_INTERNAL  || 13001);
const LOGO_BASE    = process.env.RADFAST_LOGO_FILE || '/tmp/radfast-logo';
const ADMIN_TOKEN  = process.env.RADFAST_ADMIN_TOKEN || '';
const MAX_SIZE     = 2 * 1024 * 1024; // 2 MB hard limit

// ════════════════════════════════════════════════════════════
//  RATE LIMITER
//  - 5 gagal / menit → blokir 30 menit
// ════════════════════════════════════════════════════════════
const RATE_WINDOW   = 60 * 1000;        // 1 menit
const RATE_MAX_FAIL = 5;                 // max gagal sebelum blokir
const LOCKOUT_TIME  = 30 * 60 * 1000;   // lockout 30 menit

const ipData = new Map(); // ip → { fails, windowStart, lockedUntil }

function getIP(req) {
    // Ambil IP asli, tapi jangan percaya X-Forwarded-For sepenuhnya
    return (req.socket && req.socket.remoteAddress) || '0.0.0.0';
}

function checkRate(ip) {
    const now  = Date.now();
    const data = ipData.get(ip) || { fails: 0, windowStart: now, lockedUntil: 0 };

    // Masih dalam lockout?
    if (data.lockedUntil > now) {
        const wait = Math.ceil((data.lockedUntil - now) / 1000 / 60);
        return { ok: false, reason: `Terlalu banyak percobaan. Coba lagi dalam ${wait} menit.` };
    }

    // Reset window jika sudah lewat
    if (now - data.windowStart > RATE_WINDOW) {
        data.fails = 0;
        data.windowStart = now;
    }

    if (data.fails >= RATE_MAX_FAIL) {
        data.lockedUntil = now + LOCKOUT_TIME;
        ipData.set(ip, data);
        auditLog('LOCKOUT', ip, `IP dikunci 30 menit setelah ${data.fails} percobaan`);
        return { ok: false, reason: 'IP dikunci 30 menit karena terlalu banyak percobaan.' };
    }

    return { ok: true };
}

function recordFail(ip, reason) {
    const now  = Date.now();
    const data = ipData.get(ip) || { fails: 0, windowStart: now, lockedUntil: 0 };
    if (now - data.windowStart > RATE_WINDOW) {
        data.fails = 0;
        data.windowStart = now;
    }
    data.fails++;
    ipData.set(ip, data);
    auditLog('FAIL', ip, reason + ` (percobaan ke-${data.fails})`);
}

function recordSuccess(ip) {
    const data = ipData.get(ip);
    if (data) { data.fails = 0; ipData.set(ip, data); }
    auditLog('SUCCESS', ip, 'Logo berhasil diupload');
}

// ── Auto cleanup data lama (tiap 1 jam) ───────────────────
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of ipData.entries()) {
        if (now - data.windowStart > LOCKOUT_TIME * 2) ipData.delete(ip);
    }
}, 3600000);

// ════════════════════════════════════════════════════════════
//  AUDIT LOG
// ════════════════════════════════════════════════════════════
function auditLog(type, ip, msg) {
    const ts = new Date().toISOString();
    console.log(`[AUDIT] ${ts} | ${type.padEnd(8)} | ${ip.padEnd(15)} | ${msg}`);
}

// ════════════════════════════════════════════════════════════
//  TOKEN COMPARISON (timing-safe, anti timing-attack)
// ════════════════════════════════════════════════════════════
function safeTokenCheck(input) {
    if (!ADMIN_TOKEN || !input) return false;
    const a = Buffer.from(input.trim());
    const b = Buffer.from(ADMIN_TOKEN.trim());
    // Pad ke panjang sama agar timingSafeEqual tidak throw
    const len  = Math.max(a.length, b.length);
    const aPad = Buffer.concat([a, Buffer.alloc(len - a.length)]);
    const bPad = Buffer.concat([b, Buffer.alloc(len - b.length)]);
    // Bandingkan isi DAN panjang — keduanya harus sama
    return crypto.timingSafeEqual(aPad, bPad) && a.length === b.length;
}

// ════════════════════════════════════════════════════════════
//  MAGIC BYTES VALIDATION
//  Cegah file palsu (nama .jpg tapi isi SVG/script, dst.)
// ════════════════════════════════════════════════════════════
function validateMagic(buf, ext) {
    if (ext === '.png') {
        return buf.length >= 8 &&
            buf[0] === 0x89 && buf[1] === 0x50 &&
            buf[2] === 0x4E && buf[3] === 0x47 &&
            buf[4] === 0x0D && buf[5] === 0x0A &&
            buf[6] === 0x1A && buf[7] === 0x0A;
    }
    if (ext === '.jpg' || ext === '.jpeg') {
        return buf.length >= 3 &&
            buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF;
    }
    if (ext === '.svg') {
        // SVG harus teks valid, tidak boleh binary
        const head = buf.slice(0, 512).toString('utf-8', 0, 512);
        // Cek ada tag SVG dan tidak ada byte null (binary injection)
        return !buf.slice(0, 512).includes(0x00) &&
               (/<svg[\s>]/i.test(head) || /^<\?xml/i.test(head));
    }
    return false;
}

// ════════════════════════════════════════════════════════════
//  SVG SANITIZER
//  Hapus semua yang bisa jadi XSS / code execution
// ════════════════════════════════════════════════════════════
function sanitizeSVG(buf) {
    let svg = buf.toString('utf-8');

    // Hapus DOCTYPE (bisa load external entity - XXE)
    svg = svg.replace(/<!DOCTYPE[^>]*>/gi, '');

    // Hapus XML processing instructions (bisa load external CSS/DTD)
    svg = svg.replace(/<\?(?!xml\s)[^?]*\?>/g, '');

    // Hapus <script> dan isinya
    svg = svg.replace(/<script[\s\S]*?<\/script\s*>/gi, '');
    svg = svg.replace(/<script[^>]*\/>/gi, '');

    // Hapus <foreignObject> (bisa embed HTML penuh)
    svg = svg.replace(/<foreignObject[\s\S]*?<\/foreignObject\s*>/gi, '');

    // Hapus semua event handler (onclick, onload, onmouseover, dst.)
    svg = svg.replace(/\s+on[a-z]+\s*=\s*"[^"]*"/gi, '');
    svg = svg.replace(/\s+on[a-z]+\s*=\s*'[^']*'/gi, '');
    svg = svg.replace(/\s+on[a-z]+\s*=\s*[^\s>]*/gi, '');

    // Hapus javascript: di href, xlink:href, src, action
    svg = svg.replace(/(href|xlink:href|src|action)\s*=\s*["']\s*javascript:[^"']*["']/gi,
                      (m, attr) => `${attr}="#"`);

    // Hapus data: URI di src/href (bisa embed HTML/JS)
    svg = svg.replace(/(href|xlink:href|src)\s*=\s*["']\s*data:[^"']*["']/gi,
                      (m, attr) => `${attr}="#"`);

    // Hapus url(data:...) di style (CSS injection)
    svg = svg.replace(/url\s*\(\s*["']?\s*data:[^)]*["']?\s*\)/gi, 'url(#)');
    svg = svg.replace(/url\s*\(\s*["']?\s*javascript:[^)]*["']?\s*\)/gi, 'url(#)');

    // Hapus <use> yang referensi eksternal (bisa SSRF)
    svg = svg.replace(/<use[^>]+xlink:href\s*=\s*["'][^#][^"']*["'][^>]*>/gi, '');
    svg = svg.replace(/<use[^>]+href\s*=\s*["'][^#][^"']*["'][^>]*>/gi, '');

    // Hapus style yang punya expression() atau behavior: (IE exploit)
    svg = svg.replace(/expression\s*\([^)]*\)/gi, '');
    svg = svg.replace(/behavior\s*:[^;"']*/gi, '');

    // Hapus -moz-binding (Firefox exploit lama)
    svg = svg.replace(/-moz-binding\s*:[^;"']*/gi, '');

    // Hapus <image> atau <img> yang load dari luar (tracking pixel / SSRF)
    svg = svg.replace(/<image[^>]+href\s*=\s*["']https?:[^"']*["'][^>]*>/gi, '');

    // Verifikasi masih valid SVG setelah sanitasi
    if (!/<svg[\s\S]*>/i.test(svg)) {
        throw new Error('SVG tidak valid setelah sanitasi');
    }

    return Buffer.from(svg, 'utf-8');
}

// ════════════════════════════════════════════════════════════
//  SECURITY HTTP HEADERS
// ════════════════════════════════════════════════════════════
const SEC_HEADERS = {
    'X-Content-Type-Options' : 'nosniff',
    'X-Frame-Options'        : 'DENY',
    'X-XSS-Protection'       : '1; mode=block',
    'Referrer-Policy'        : 'no-referrer',
    'Cache-Control'          : 'no-store, no-cache',
    // Strict CSP: tidak boleh ada script sama sekali
    'Content-Security-Policy': "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none';"
};

function sendSecure(res, status, ct, body) {
    res.writeHead(status, { 'Content-Type': ct, ...SEC_HEADERS });
    res.end(body);
}

// ════════════════════════════════════════════════════════════
//  LOGO HELPERS
// ════════════════════════════════════════════════════════════
const MIME = {
    '.svg'  : 'image/svg+xml',
    '.png'  : 'image/png',
    '.jpg'  : 'image/jpeg',
    '.jpeg' : 'image/jpeg'
};

function findCustomLogo() {
    for (const ext of ['.svg', '.png', '.jpg', '.jpeg']) {
        const f = LOGO_BASE + ext;
        if (fs.existsSync(f)) return f;
    }
    return null;
}

function deleteAllLogo() {
    for (const ext of ['.svg', '.png', '.jpg', '.jpeg']) {
        try { fs.unlinkSync(LOGO_BASE + ext); } catch(_) {}
    }
}

// ════════════════════════════════════════════════════════════
//  UPLOAD PAGE HTML
// ════════════════════════════════════════════════════════════
function uploadPage(msg = '') {
    const custom = findCustomLogo();
    const ts = Date.now();
    return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>Upload Logo — RadFast ACS</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:Arial,sans-serif;background:#f0f2f5;padding:30px 16px}
  .card{max-width:460px;margin:0 auto;background:#fff;border-radius:10px;padding:32px;box-shadow:0 2px 12px rgba(0,0,0,.1)}
  h2{color:#333;font-size:20px;margin-bottom:20px}
  label{display:block;font-size:13px;font-weight:bold;color:#555;margin:14px 0 4px}
  input[type=password]{width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;outline:none}
  input[type=password]:focus{border-color:#3498db}
  input[type=file]{width:100%;padding:6px 0;font-size:14px}
  .btn{display:inline-block;padding:10px 22px;border:none;border-radius:6px;font-size:14px;cursor:pointer;margin-top:14px;font-weight:bold}
  .g{background:#27ae60;color:#fff}.g:hover{background:#1e8449}
  .r{background:#e74c3c;color:#fff;font-size:13px;padding:8px 16px;margin-top:10px}.r:hover{background:#c0392b}
  .msg{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:14px}
  .ok{background:#d4edda;color:#155724;border:1px solid #c3e6cb}
  .er{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}
  .prev{text-align:center;margin:14px 0;padding:12px;border:1px solid #eee;border-radius:6px;background:#fafafa}
  .prev img{max-height:64px;max-width:240px}
  .prev p{font-size:12px;color:#888;margin-top:6px}
  hr{border:none;border-top:1px solid #eee;margin:18px 0}
  .note{font-size:12px;color:#999;margin-top:14px;line-height:1.5}
  .back{display:inline-block;margin-top:16px;font-size:13px;color:#3498db;text-decoration:none}
  .back:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
  <h2>🖼 Upload Logo</h2>
  ${msg}
  ${custom ? `<div class="prev">
    <img src="/__admin/logo/preview?t=${ts}" alt="Logo saat ini">
    <p>Logo aktif saat ini</p>
  </div>` : `<p style="color:#aaa;font-size:13px;margin-bottom:14px">Menampilkan logo default GenieACS.</p>`}

  <form method="POST" action="/__admin/logo/upload" enctype="multipart/form-data" autocomplete="off">
    <label>🔑 Token Admin</label>
    <input type="password" name="token" placeholder="Masukkan token admin" required autocomplete="new-password">
    <label>📁 File Logo</label>
    <small style="color:#888;font-size:12px">SVG / PNG / JPG · maks 2 MB</small>
    <input type="file" name="logo" accept=".svg,.png,.jpg,.jpeg" required style="margin-top:6px">
    <button type="submit" class="btn g">⬆ Upload Logo</button>
  </form>

  ${custom ? `<hr>
  <form method="POST" action="/__admin/logo/reset" autocomplete="off">
    <label>🔑 Token Admin (untuk reset)</label>
    <input type="password" name="token" placeholder="Token admin" required autocomplete="new-password">
    <button type="submit" class="btn r">🗑 Reset ke Logo Default</button>
  </form>` : ''}

  <p class="note">
    ⚡ Logo aktif langsung tanpa restart.<br>
    🔒 5 percobaan gagal = IP diblokir 30 menit.
  </p>
  <a class="back" href="/">← Kembali ke Dashboard</a>
</div>
</body>
</html>`;
}

// ════════════════════════════════════════════════════════════
//  MULTIPART PARSER (simple, size-bounded)
// ════════════════════════════════════════════════════════════
function parseMultipart(body, boundary) {
    const sep    = '\r\n--' + boundary;
    const result = {};
    let   pos    = body.indexOf('--' + boundary);
    if (pos < 0) return result;
    pos += ('--' + boundary).length + 2;

    while (pos < body.length) {
        const hEnd = body.indexOf(Buffer.from('\r\n\r\n'), pos);
        if (hEnd < 0) break;
        const headers = body.slice(pos, hEnd).toString('latin1'); // latin1 = byte-safe
        const nameM   = headers.match(/name="([^"]{1,64})"/);   // max 64 char nama
        const fileM   = headers.match(/filename="([^"]{0,255})"/); // max 255 char filename
        const ctM     = headers.match(/Content-Type:\s*([^\r\n]+)/i);
        const dStart  = hEnd + 4;
        const dEnd    = body.indexOf(Buffer.from('\r\n--' + boundary), dStart);
        if (!nameM) { if (dEnd < 0) break; pos = dEnd + sep.length; continue; }
        const data = body.slice(dStart, dEnd < 0 ? undefined : dEnd);
        result[nameM[1]] = {
            value    : fileM ? null : data.toString('utf-8').trim(),
            data     : data,
            filename : fileM ? path.basename(fileM[1]) : null, // basename: hapus path traversal
            mime     : ctM  ? ctM[1].trim().split(';')[0].trim() : 'text/plain'
        };
        if (dEnd < 0) break;
        pos = dEnd + sep.length;
        if (body.slice(pos, pos + 2).toString() === '--') break;
        pos += 2;
    }
    return result;
}

// ════════════════════════════════════════════════════════════
//  TOMBOL FLOATING — inject ke setiap halaman GenieACS
// ════════════════════════════════════════════════════════════
const FLOATING_BTN = `
<style>
#radfast-logo-btn{
  position:fixed;bottom:18px;right:18px;z-index:99999;
  background:#2980b9;color:#fff;padding:8px 14px 8px 10px;
  border-radius:22px;text-decoration:none;
  font-family:Arial,sans-serif;font-size:13px;font-weight:bold;
  box-shadow:0 3px 10px rgba(0,0,0,.25);
  display:flex;align-items:center;gap:6px;
  transition:background .2s,transform .1s;
  border:2px solid rgba(255,255,255,.3);
}
#radfast-logo-btn:hover{background:#1a6fa3;transform:scale(1.04)}
#radfast-logo-btn span{font-size:16px}
</style>
<a id="radfast-logo-btn" href="/__admin/logo" title="Upload Logo">
  <span>🖼</span> Upload Logo
</a>`;

// ════════════════════════════════════════════════════════════
//  PROXY KE GENIEACS UI
//  - Strip Accept-Encoding supaya response tidak gzip
//    (agar bisa inject tombol ke HTML)
// ════════════════════════════════════════════════════════════
function proxyRequest(req, res) {
    // Hapus Accept-Encoding agar GenieACS kirim HTML plain (bukan gzip)
    const headers = { ...req.headers, host: `127.0.0.1:${GENIE_PORT}` };
    delete headers['accept-encoding'];

    const opts = {
        hostname : '127.0.0.1',
        port     : GENIE_PORT,
        path     : req.url,
        method   : req.method,
        headers
    };

    const proxy = http.request(opts, (pRes) => {
        const ct = (pRes.headers['content-type'] || '');

        // Inject tombol hanya ke halaman HTML
        if (ct.includes('text/html')) {
            const chunks = [];
            pRes.on('data', c => chunks.push(c));
            pRes.on('end', () => {
                let html = Buffer.concat(chunks).toString('utf-8');

                // Inject tombol sebelum </body>
                if (html.includes('</body>')) {
                    html = html.replace('</body>', FLOATING_BTN + '</body>');
                } else {
                    html += FLOATING_BTN; // fallback kalau tidak ada </body>
                }

                // Hapus content-length lama (sudah berubah) & content-encoding
                const respHeaders = { ...pRes.headers };
                delete respHeaders['content-length'];
                delete respHeaders['content-encoding'];
                delete respHeaders['transfer-encoding'];

                const buf = Buffer.from(html, 'utf-8');
                respHeaders['content-length'] = buf.length;

                res.writeHead(pRes.statusCode, respHeaders);
                res.end(buf);
            });
            pRes.on('error', () => res.end());
        } else {
            // Non-HTML (JS, CSS, JSON, dll) — pass-through biasa
            res.writeHead(pRes.statusCode, pRes.headers);
            pRes.pipe(res);
        }
    });

    proxy.on('error', () => {
        res.writeHead(502, { 'Content-Type': 'text/plain' });
        res.end('502 — GenieACS UI tidak berjalan');
    });

    req.pipe(proxy);
}

// ════════════════════════════════════════════════════════════
//  MAIN SERVER
// ════════════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0].replace(/\/+$/, '') || '/';
    const ip  = getIP(req);

    // ── Admin: tampilkan form ──────────────────────────────
    if (url === '/__admin/logo') {
        sendSecure(res, 200, 'text/html; charset=utf-8', uploadPage());
        return;
    }

    // ── Admin: preview logo ────────────────────────────────
    if (url === '/__admin/logo/preview') {
        const f = findCustomLogo();
        if (f) {
            const ext = path.extname(f).toLowerCase();
            res.writeHead(200, {
                'Content-Type'          : MIME[ext] || 'image/svg+xml',
                'Cache-Control'         : 'no-store',
                'X-Content-Type-Options': 'nosniff'
            });
            fs.createReadStream(f).pipe(res);
        } else {
            res.writeHead(404); res.end();
        }
        return;
    }

    // ── Admin: handle upload ───────────────────────────────
    if (url === '/__admin/logo/upload' && req.method === 'POST') {

        // Cek rate limit DULU sebelum terima body
        const rl = checkRate(ip);
        if (!rl.ok) {
            sendSecure(res, 429, 'text/html; charset=utf-8',
                uploadPage(`<div class="msg er">🚫 ${rl.reason}</div>`));
            return;
        }

        const ct  = req.headers['content-type'] || '';
        const bm  = ct.match(/boundary=([^\s;,]+)/);
        if (!bm) {
            sendSecure(res, 400, 'text/html; charset=utf-8',
                uploadPage('<div class="msg er">❌ Request tidak valid.</div>'));
            return;
        }

        const chunks = [];
        let   total  = 0;
        let   aborted = false;

        req.on('data', chunk => {
            if (aborted) return;
            total += chunk.length;
            if (total > MAX_SIZE + 16384) { // 16KB ekstra untuk headers
                aborted = true;
                req.destroy();
                sendSecure(res, 413, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg er">❌ File terlalu besar (maks 2 MB).</div>'));
                return;
            }
            chunks.push(chunk);
        });

        req.on('end', () => {
            if (aborted) return;
            try {
                const body     = Buffer.concat(chunks);
                const boundary = bm[1].replace(/^["']|["']$/g, '');
                const parts    = parseMultipart(body, boundary);

                // ── Cek token (timing-safe) ────────────────
                const tok = (parts.token && parts.token.value) ? parts.token.value : '';
                if (!safeTokenCheck(tok)) {
                    recordFail(ip, 'Token salah');
                    sendSecure(res, 403, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ Token salah!</div>'));
                    return;
                }

                // ── Cek file ada ───────────────────────────
                const file = parts.logo;
                if (!file || !file.data || file.data.length < 16) {
                    sendSecure(res, 400, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ File tidak diterima.</div>'));
                    return;
                }

                // ── Tentukan ekstensi dari nama file ────────
                const origExt = path.extname(file.filename || '').toLowerCase();
                const allowed = ['.svg', '.png', '.jpg', '.jpeg'];
                if (!allowed.includes(origExt)) {
                    recordFail(ip, `Ekstensi tidak diizinkan: ${origExt}`);
                    sendSecure(res, 400, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ Format tidak didukung. Gunakan SVG, PNG, atau JPG.</div>'));
                    return;
                }

                // ── Validasi magic bytes ────────────────────
                if (!validateMagic(file.data, origExt)) {
                    recordFail(ip, `Magic bytes tidak cocok untuk ${origExt}`);
                    sendSecure(res, 400, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ File tidak valid atau formatnya tidak cocok.</div>'));
                    return;
                }

                // ── Sanitasi SVG ────────────────────────────
                let finalData = file.data;
                if (origExt === '.svg') {
                    try {
                        finalData = sanitizeSVG(file.data);
                    } catch(e) {
                        recordFail(ip, `SVG tidak valid: ${e.message}`);
                        sendSecure(res, 400, 'text/html; charset=utf-8',
                            uploadPage('<div class="msg er">❌ SVG tidak valid atau mengandung konten berbahaya.</div>'));
                        return;
                    }
                }

                // ── Hapus logo lama, simpan baru ─────────────
                deleteAllLogo();

                // Path final: LOGO_BASE + ext (tidak ada user-controlled path)
                const savePath = LOGO_BASE + origExt;
                fs.mkdirSync(path.dirname(savePath), { recursive: true });
                fs.writeFileSync(savePath, finalData, { mode: 0o640 });

                recordSuccess(ip);

                sendSecure(res, 200, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg ok">✅ Logo berhasil diupload!</div>'));

            } catch(e) {
                // Jangan expose detail error ke client
                console.error(`[logo-proxy] Upload error dari ${ip}:`, e.message);
                sendSecure(res, 500, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg er">❌ Terjadi kesalahan server. Coba lagi.</div>'));
            }
        });

        req.on('error', () => {});
        return;
    }

    // ── Admin: reset logo ──────────────────────────────────
    if (url === '/__admin/logo/reset' && req.method === 'POST') {
        const rl = checkRate(ip);
        if (!rl.ok) {
            sendSecure(res, 429, 'text/html; charset=utf-8',
                uploadPage(`<div class="msg er">🚫 ${rl.reason}</div>`));
            return;
        }

        const chunks = [];
        req.on('data', c => { if (Buffer.concat(chunks).length < 4096) chunks.push(c); });
        req.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf-8', 0, 4096);
            const tokM = body.match(/(?:^|&)token=([^&]*)/);
            const tok  = tokM ? decodeURIComponent(tokM[1]) : '';

            if (!safeTokenCheck(tok)) {
                recordFail(ip, 'Token salah saat reset');
                sendSecure(res, 403, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg er">❌ Token salah!</div>'));
                return;
            }

            deleteAllLogo();
            auditLog('RESET', ip, 'Logo direset ke default');
            sendSecure(res, 200, 'text/html; charset=utf-8',
                uploadPage('<div class="msg ok">✅ Logo direset ke logo default.</div>'));
        });
        req.on('error', () => {});
        return;
    }

    // ── Blokir akses admin lain ────────────────────────────
    if (url.startsWith('/__admin')) {
        sendSecure(res, 404, 'text/plain', 'Not found');
        return;
    }

    // ── Intercept logo GenieACS → serve custom jika ada ───
    if (/\/public\/logo-[^/]+\.(svg|png|jpe?g)/i.test(req.url)) {
        const custom = findCustomLogo();
        if (custom) {
            const ext = path.extname(custom).toLowerCase();
            res.writeHead(200, {
                'Content-Type'          : MIME[ext] || 'image/svg+xml',
                'Cache-Control'         : 'no-cache',
                'X-Content-Type-Options': 'nosniff'
            });
            fs.createReadStream(custom).pipe(res);
            return;
        }
    }

    // ── Semua request lain → proxy GenieACS ───────────────
    proxyRequest(req, res);
});

// Handle WebSocket / SSE upgrade
server.on('upgrade', (req, socket, head) => {
    const conn = http.request({
        hostname : '127.0.0.1',
        port     : GENIE_PORT,
        path     : req.url,
        method   : req.method,
        headers  : req.headers
    });
    conn.on('upgrade', (res, proxySocket) => {
        socket.write(
            'HTTP/1.1 101 Switching Protocols\r\n' +
            Object.entries(res.headers).map(([k,v]) => `${k}: ${v}`).join('\r\n') +
            '\r\n\r\n'
        );
        proxySocket.pipe(socket).pipe(proxySocket);
    });
    conn.on('error', () => socket.destroy());
    conn.end();
});

server.on('error', err => {
    console.error('[logo-proxy] Fatal:', err.message);
    process.exit(1);
});

if (!ADMIN_TOKEN) {
    console.error('[logo-proxy] PERINGATAN: RADFAST_ADMIN_TOKEN tidak di-set! Upload dinonaktifkan.');
}

server.listen(PUBLIC_PORT, '::', () => {
    console.log(`[logo-proxy] :${PUBLIC_PORT} → GenieACS UI :${GENIE_PORT}`);
    console.log(`[logo-proxy] Upload logo: http://<ip>:${PUBLIC_PORT}/__admin/logo`);
});
