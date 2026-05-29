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

const PUBLIC_PORT  = parseInt(process.env.RADFAST_PROXY_PORT       || 3001);
const GENIE_PORT   = parseInt(process.env.RADFAST_UI_INTERNAL      || 13001);
const NBI_PORT     = parseInt(process.env.GENIEACS_NBI_PORT        || 7558);
// Secret path untuk akses NBI (REST API GenieACS) lewat port UI publik ini.
// Di-set per instance via .env (RADFAST_NBI_GATE_PATH).
// JIKA KOSONG — otomatis di-generate saat startup (tidak pernah nonaktif).
const NBI_GATE_PATH_INIT = (process.env.RADFAST_NBI_GATE_PATH || '').trim().replace(/\/+$/, '')
    || `/_acs-${crypto.randomBytes(20).toString('hex')}`;
const NBI_GATE_AUTO_GENERATED = !(process.env.RADFAST_NBI_GATE_PATH || '').trim();
// Batas maksimum perubahan secret via dashboard (0 = unlimited)
const NBI_GATE_MAX_CHANGES = parseInt(process.env.RADFAST_NBI_GATE_MAX_CHANGES || '3', 10);
// State runtime
let nbiGateCurrentPath = NBI_GATE_PATH_INIT;
let nbiGateOriginalPath = NBI_GATE_PATH_INIT;
let nbiGateChangesLeft = NBI_GATE_MAX_CHANGES;
// Agar route-check (if NBI_GATE_PATH ...) tetap jalan, kita pakai variabel
// yang diupdate saat secret berubah — cukup alias ke current.
let NBI_GATE_PATH = nbiGateCurrentPath;
function refreshNbiGateConst() { NBI_GATE_PATH = nbiGateCurrentPath; }
const LOGO_BASE    = process.env.RADFAST_LOGO_FILE                 || '/tmp/radfast-logo';
const ADMIN_TOKEN  = process.env.RADFAST_ADMIN_TOKEN               || '';
const JWT_SECRET   = process.env.GENIEACS_UI_JWT_SECRET            || '';
const MAX_SIZE     = 2 * 1024 * 1024; // 2 MB hard limit

// Cookie isolation: prefix semua cookie JWT dengan _p<PORT>_
// Supaya tiap instance punya cookie terpisah di browser (tidak saling overwrite)
// Strategi: deteksi JWT dari VALUE (3 bagian base64url), bukan nama cookie
// Ini robust untuk semua nama cookie GenieACS (session, koa:sess, dll)
const PORT_PREFIX = `_p${PUBLIC_PORT}_`;
const JWT_PATTERN = /^[\w-]+\.[\w-]{10,}\.[\w-]+$/; // deteksi JWT: xxx.xxx.xxx

// Response dari GenieACS: prefix SEMUA cookie dengan port prefix
// (bukan hanya JWT — ini mencakup cookie logout/delete juga)
function rewriteSetCookie(val) {
    const eqIdx = val.indexOf('=');
    if (eqIdx < 0) return val;
    const name = val.slice(0, eqIdx).trim();
    // Skip cookie yang sudah punya prefix atau milik proxy
    if (/^_p\d+_/.test(name) || name === '_rfcsrf') return val;
    return `${PORT_PREFIX}${name}${val.slice(eqIdx)}`;
}

// Request ke GenieACS: strip prefix, buang cookie milik instance lain
function rewriteCookieForUpstream(cookieStr) {
    if (!cookieStr) return cookieStr;
    return cookieStr.split(';').map(c => {
        const t = c.trimStart();
        // Cookie milik instance ini → hapus prefix (trimStart agar tidak ada spasi di awal)
        if (t.startsWith(PORT_PREFIX)) {
            return t.slice(PORT_PREFIX.length);
        }
        // Cookie milik instance lain → buang
        if (/^_p\d+_/.test(t)) return null;
        return c;
    }).filter(v => v !== null).join('; ');
}

// Logo setiap instance disimpan di folder instance masing-masing
// (LOGO_BASE = /opt/genieacs-instances/<user>/logo/custom-logo)
// Proxy intercept request logo → serve dari folder instance sendiri
// sehingga tiap instance punya logo terpisah, tidak saling overwrite

// ════════════════════════════════════════════════════════════
//  CSRF TOKEN STORE
//  - Nonce sekali pakai, TTL 10 menit
//  - Wajib ada di setiap POST upload/reset
// ════════════════════════════════════════════════════════════
const csrfStore = new Map(); // nonce → { exp, ip }
const CSRF_TTL  = 10 * 60 * 1000; // 10 menit

function genCSRF(ip) {
    const nonce = crypto.randomBytes(24).toString('hex');
    csrfStore.set(nonce, { exp: Date.now() + CSRF_TTL, ip });
    return nonce;
}
function checkCSRF(nonce, ip) {
    if (!nonce) return false;
    const entry = csrfStore.get(nonce);
    if (!entry) return false;
    csrfStore.delete(nonce); // sekali pakai
    if (Date.now() > entry.exp) return false;
    // IP harus sama (optional strict, bisa dilemahkan jika di-proxy)
    return entry.ip === ip;
}
// Cleanup CSRF kedaluwarsa tiap 5 menit
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of csrfStore.entries()) {
        if (now > v.exp) csrfStore.delete(k);
    }
}, 5 * 60 * 1000);

// ════════════════════════════════════════════════════════════
//  RATE LIMITER
//  - 5 gagal / menit → blokir 30 menit
// ════════════════════════════════════════════════════════════
const RATE_WINDOW   = 60 * 1000;        // 1 menit
const RATE_MAX_FAIL = 5;                 // max gagal sebelum blokir
const LOCKOUT_TIME  = 30 * 60 * 1000;   // lockout 30 menit

const ipData = new Map(); // ip → { fails, windowStart, lockedUntil }

function getIP(req) {
    const raw = (req.socket && req.socket.remoteAddress) || '0.0.0.0';
    // Normalize IPv4-mapped IPv6 (::ffff:192.168.x.x → 192.168.x.x)
    // Server listens on '::' so IPv4 clients arrive as ::ffff:<ipv4>
    // Without normalization CSRF genCSRF/checkCSRF IP comparison can fail
    return raw.replace(/^::ffff:/i, '');
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
    const len  = Math.max(a.length, b.length);
    const aPad = Buffer.concat([a, Buffer.alloc(len - a.length)]);
    const bPad = Buffer.concat([b, Buffer.alloc(len - b.length)]);
    return crypto.timingSafeEqual(aPad, bPad) && a.length === b.length;
}

// ════════════════════════════════════════════════════════════
//  CEK SESSION GENIEACS (JWT HS256)
//  Kalau user sudah login ke GenieACS → langsung boleh upload
//  tanpa perlu input token manual
// ════════════════════════════════════════════════════════════
function verifyGenieJWT(token) {
    if (!token || !JWT_SECRET) return false;
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return false;
        // Decode payload
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
        // Cek expiry
        if (payload.exp && Date.now() / 1000 > payload.exp) return false;
        // Verifikasi signature HS256
        const expected = crypto.createHmac('sha256', JWT_SECRET)
            .update(parts[0] + '.' + parts[1])
            .digest('base64url');
        const a = Buffer.from(expected);
        const b = Buffer.from(parts[2]);
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
    } catch(_) { return false; }
}

function isGenieSession(req) {
    // Cek Authorization: Bearer <token>
    const auth = req.headers['authorization'] || '';
    const bear = auth.match(/^Bearer\s+(\S+)/i);
    if (bear && verifyGenieJWT(bear[1])) return true;

    // Cek semua cookie — coba setiap nilai sebagai JWT
    const cookieStr = req.headers['cookie'] || '';
    if (!cookieStr) {
        console.log('[auth] FAIL: tidak ada cookie header');
        return false;
    }

    const names = [];
    for (const part of cookieStr.split(';')) {
        const eq = part.indexOf('=');
        if (eq < 0) continue;
        const name = part.slice(0, eq).trim();
        const raw  = part.slice(eq + 1).trim();
        names.push(name);
        try {
            const val = decodeURIComponent(raw);
            if (!val) continue;
            const parts = val.split('.');
            if (parts.length === 3) {
                // Terlihat seperti JWT — coba verify
                if (verifyGenieJWT(val)) return true;
                // Gagal — log alasannya
                try {
                    const pl = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
                    if (pl.exp && Date.now() / 1000 > pl.exp) {
                        console.log(`[auth] cookie "${name}" JWT expired (exp=${pl.exp})`);
                    } else if (!JWT_SECRET) {
                        console.log(`[auth] cookie "${name}" JWT_SECRET kosong!`);
                    } else {
                        console.log(`[auth] cookie "${name}" signature tidak cocok`);
                    }
                } catch(_) {
                    console.log(`[auth] cookie "${name}" bukan JWT valid`);
                }
            }
        } catch(e) {
            console.log(`[auth] cookie "${name}" decode error: ${e.message}`);
        }
    }

    console.log(`[auth] FAIL: tidak ada JWT valid. Cookie names: [${names.join(', ')}]`);
    return false;
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
    if (ext === '.gif') {
        // GIF87a atau GIF89a
        return buf.length >= 6 &&
            buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 &&
            buf[3] === 0x38 && (buf[4] === 0x37 || buf[4] === 0x39) && buf[5] === 0x61;
    }
    if (ext === '.webp') {
        // RIFF....WEBP
        return buf.length >= 12 &&
            buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 &&
            buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50;
    }
    if (ext === '.ico') {
        return buf.length >= 4 &&
            buf[0] === 0x00 && buf[1] === 0x00 &&
            buf[2] === 0x01 && buf[3] === 0x00;
    }
    if (ext === '.bmp') {
        return buf.length >= 2 && buf[0] === 0x42 && buf[1] === 0x4D;
    }
    if (ext === '.svg') {
        const head = buf.slice(0, 512).toString('utf-8', 0, 512);
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
// SEC_HEADERS untuk halaman upload admin (strict, no script)
const SEC_HEADERS = {
    'X-Content-Type-Options' : 'nosniff',
    'X-Frame-Options'        : 'DENY',
    'X-XSS-Protection'       : '1; mode=block',
    'Referrer-Policy'        : 'no-referrer',
    'Cache-Control'          : 'no-store, no-cache',
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
    '.jpeg' : 'image/jpeg',
    '.gif'  : 'image/gif',
    '.webp' : 'image/webp',
    '.ico'  : 'image/x-icon',
    '.bmp'  : 'image/bmp'
};

const ALLOWED_EXT = ['.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp'];

function findCustomLogo() {
    for (const ext of ALLOWED_EXT) {
        const f = LOGO_BASE + ext;
        if (fs.existsSync(f)) return f;
    }
    return null;
}

function deleteAllLogo() {
    for (const ext of ALLOWED_EXT) {
        try { fs.unlinkSync(LOGO_BASE + ext); } catch(_) {}
    }
}

// ════════════════════════════════════════════════════════════
//  UPLOAD PAGE HTML
// ════════════════════════════════════════════════════════════
function uploadPage(msg = '', authed = false, csrfNonce = '') {
    const custom = findCustomLogo();
    const ts = Date.now();

    // Kalau sudah login GenieACS: tidak perlu isi token manual
    const csrfHidden = csrfNonce ? `<input type="hidden" name="_csrf" value="${csrfNonce}">` : '';
    const tokenField = authed
        ? `<input type="hidden" name="token" value="__genie_session__">${csrfHidden}`
        : `<label>🔑 Token Admin</label>
           <input type="password" name="token" placeholder="Masukkan token admin" required autocomplete="new-password">${csrfHidden}`;

    const resetTokenField = authed
        ? `<input type="hidden" name="token" value="__genie_session__">${csrfHidden}`
        : `<label>🔑 Token Admin</label>
           <input type="password" name="token" placeholder="Token admin" required autocomplete="new-password">${csrfHidden}`;

    const authBadge = authed
        ? `<div style="background:#e8f5e9;border:1px solid #a5d6a7;border-radius:6px;padding:8px 12px;font-size:13px;color:#2e7d32;margin-bottom:14px">
             ✅ Login terdeteksi — langsung upload tanpa token
           </div>`
        : `<div style="background:#fff3e0;border:1px solid #ffcc80;border-radius:6px;padding:8px 12px;font-size:13px;color:#e65100;margin-bottom:14px">
             ⚠️ Akses langsung — masukkan token admin
           </div>`;

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
  h2{color:#333;font-size:20px;margin-bottom:14px}
  label{display:block;font-size:13px;font-weight:bold;color:#555;margin:14px 0 4px}
  input[type=password]{width:100%;padding:9px 12px;border:1px solid #ddd;border-radius:6px;font-size:14px;outline:none}
  input[type=password]:focus{border-color:#3498db}
  input[type=file]{width:100%;padding:6px 0;font-size:14px;margin-top:6px}
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
  ${authBadge}
  ${msg}
  ${custom ? `<div class="prev">
    <img src="/__admin/logo/preview?t=${ts}" alt="Logo saat ini">
    <p>Logo aktif saat ini</p>
  </div>` : `<p style="color:#aaa;font-size:13px;margin-bottom:14px">Menampilkan logo default GenieACS.</p>`}

  <form method="POST" action="/__admin/logo/upload" enctype="multipart/form-data" autocomplete="off">
    ${tokenField}
    <label>📁 File Logo</label>
    <small style="color:#888;font-size:12px">SVG / PNG / JPG / GIF / WebP / ICO / BMP · maks 2 MB</small>
    <input type="file" name="logo" accept=".svg,.png,.jpg,.jpeg,.gif,.webp,.ico,.bmp" required>
    <button type="submit" class="btn g">⬆ Upload Logo</button>
  </form>

  ${custom ? `<hr>
  <form method="POST" action="/__admin/logo/reset" autocomplete="off">
    ${resetTokenField}
    <button type="submit" class="btn r">🗑 Reset ke Logo Default</button>
  </form>` : ''}

  <p class="note">⚡ Logo aktif langsung tanpa restart.</p>
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
//  INJECT LOGO LINK — masuk ke navbar GenieACS
//  Inject link "🖼 Logo" sejajar dengan tab nav yang ada.
//  Tidak menggunakan position:fixed agar tidak nutup konten.
// ════════════════════════════════════════════════════════════
const NAV_INJECT = String.raw`<script>
(function(){
  'use strict';
  var ADMIN = '/__admin/logo';
  var _modal = null; // simpan referensi modal agar tidak terhapus Mithril

  /* ════════════════════════════════════════
     Buat modal sepenuhnya via JS
     (tidak pakai HTML statis agar tidak
      dihapus oleh Mithril virtual-DOM)
  ════════════════════════════════════════ */
  function buildModal(){
    if(_modal && document.body.contains(_modal)) return _modal;

    // Inject CSS sekali saja
    if(!document.getElementById('rf-style')){
      var s = document.createElement('style');
      s.id = 'rf-style';
      s.textContent = [
        '#rf-bd{display:none;position:fixed;top:0;left:0;right:0;bottom:0;',
        'z-index:2147483647;background:rgba(0,0,0,.5);',
        'align-items:center;justify-content:center;}',
        '#rf-bd.open{display:flex!important;}',
        '#rf-box{background:#fff;border-radius:4px;width:420px;max-width:95vw;',
        'box-shadow:0 6px 32px rgba(0,0,0,.35);font-family:Arial,sans-serif;',
        'font-size:14px;overflow:hidden;}',
        '#rf-head{background:#d4c89a;padding:10px 16px;display:flex;',
        'align-items:center;justify-content:space-between;',
        'border-bottom:1px solid #b8ae82;}',
        '#rf-head h3{margin:0;font-size:15px;color:#333;}',
        '#rf-xbtn{background:none;border:none;font-size:22px;cursor:pointer;',
        'color:#555;line-height:1;padding:0 2px;}',
        '#rf-body{padding:16px;}',
        '#rf-prev{text-align:center;border:1px solid #ddd;border-radius:4px;',
        'padding:10px;margin-bottom:12px;background:#fafafa;min-height:56px;',
        'display:flex;align-items:center;justify-content:center;}',
        '#rf-prev img{max-height:56px;max-width:100%;object-fit:contain;}',
        '#rf-prev span{color:#aaa;font-size:13px;}',
        '#rf-area{border:2px dashed #c8c0a0;border-radius:4px;padding:12px;',
        'text-align:center;cursor:pointer;margin-bottom:10px;background:#fffdf5;}',
        '#rf-area:hover{border-color:#8a7d50;}',
        '#rf-area label{cursor:pointer;color:#555;font-size:13px;}',
        '#rf-fname{font-size:12px;color:#888;margin-top:4px;}',
        '#rf-area input[type=file]{display:none;}',
        '.rf-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}',
        '.rf-btn{padding:7px 18px;border:none;border-radius:3px;cursor:pointer;',
        'font-size:13px;font-weight:bold;}',
        '.rf-ok{background:#5a8a2a;color:#fff;}',
        '.rf-rm{background:#c0392b;color:#fff;font-size:12px;padding:5px 12px;}',
        '#rf-msg{padding:7px 10px;border-radius:3px;margin-bottom:10px;',
        'font-size:13px;display:none;}',
        '#rf-msg.ok{background:#dff0d8;color:#2d6a0f;border:1px solid #b8dca0;display:block;}',
        '#rf-msg.er{background:#f2dede;color:#8b1a1a;border:1px solid #e0b0b0;display:block;}',
      ].join('');
      document.head.appendChild(s);
    }

    // Backdrop
    var bd = document.createElement('div'); bd.id='rf-bd';
    bd.addEventListener('click', function(e){ if(e.target===bd) closeModal(); });

    // Box
    var box = document.createElement('div'); box.id='rf-box';

    // Head
    var head = document.createElement('div'); head.id='rf-head';
    var h3 = document.createElement('h3'); h3.textContent='Upload Logo';
    var xbtn = document.createElement('button'); xbtn.id='rf-xbtn';
    xbtn.innerHTML='&times;'; xbtn.title='Tutup';
    xbtn.addEventListener('click', closeModal);
    head.appendChild(h3); head.appendChild(xbtn);

    // Body
    var body = document.createElement('div'); body.id='rf-body';

    // Message
    var msg = document.createElement('div'); msg.id='rf-msg';

    // Preview
    var prev = document.createElement('div'); prev.id='rf-prev';
    prev.innerHTML='<span>Memuat...</span>';

    // File area
    var area = document.createElement('div'); area.id='rf-area';
    var lbl  = document.createElement('label'); lbl.textContent='Klik atau drag file ke sini';
    var inp  = document.createElement('input'); inp.type='file'; inp.id='rf-finput';
    inp.accept='.svg,.png,.jpg,.jpeg,.gif,.webp,.ico,.bmp';
    lbl.setAttribute('for','rf-finput');
    var fname = document.createElement('div'); fname.id='rf-fname';
    fname.textContent='SVG / PNG / JPG / GIF / WebP — maks 2 MB';
    inp.addEventListener('change', function(){
      var f=inp.files[0];
      fname.textContent = f ? f.name+' ('+Math.round(f.size/1024)+' KB)' : 'SVG / PNG / JPG / GIF / WebP — maks 2 MB';
      if(f) safePreview(f, prev);
    });
    // Drag & drop
    area.addEventListener('dragover',function(e){e.preventDefault();area.style.borderColor='#8a7d50';});
    area.addEventListener('dragleave',function(){area.style.borderColor='';});
    area.addEventListener('drop',function(e){
      e.preventDefault(); area.style.borderColor='';
      var f=e.dataTransfer&&e.dataTransfer.files[0];
      if(f){
        try{ var dt=new DataTransfer(); dt.items.add(f); inp.files=dt.files; }catch(ex){}
        fname.textContent=f.name+' ('+Math.round(f.size/1024)+' KB)';
        safePreview(f, prev);
      }
    });
    area.appendChild(inp); area.appendChild(lbl); area.appendChild(fname);

    // Buttons row
    var row = document.createElement('div'); row.className='rf-row';
    var upBtn = document.createElement('button'); upBtn.className='rf-btn rf-ok'; upBtn.id='rf-ubtn';
    upBtn.textContent='Upload Logo';
    var rmBtn = document.createElement('button'); rmBtn.className='rf-btn rf-rm'; rmBtn.id='rf-rbtn';
    rmBtn.textContent='Reset Default';

    upBtn.addEventListener('click', function(){
      var f=inp.files[0];
      if(!f){setMsg('er','Pilih file terlebih dahulu.');return;}
      if(f.size>2*1024*1024){setMsg('er','File terlalu besar (maks 2 MB).');return;}
      upBtn.disabled=true; upBtn.textContent='Mengupload...';
      fetch(ADMIN+'/csrf',{credentials:'include'})
        .then(function(r){
          if(!r.ok) return Promise.reject('AUTH_FAIL:'+r.status);
          return r.json();
        })
        .then(function(j){
          var fd=new FormData();
          fd.append('logo',f);
          fd.append('token','__genie_session__');
          fd.append('_csrf', j.csrf||'');
          return fetch(ADMIN+'/upload',{method:'POST',body:fd,credentials:'include'});
        })
        .then(function(r){return r.text().then(function(t){return {s:r.status,t:t};});})
        .then(function(d){
          var ok=d.t.indexOf('berhasil')>=0||d.t.indexOf('Logo berhasil')>=0;
          if(ok){
            setMsg('ok','✅ Logo berhasil diupload! Memuat ulang halaman...');
            setTimeout(function(){ location.reload(); }, 1500);
          } else if(d.s===403){
            setMsg('er','❌ Token keamanan gagal (403). Muat ulang halaman lalu coba lagi.');
          } else if(d.s===413){
            setMsg('er','❌ File terlalu besar, maks 2 MB.');
          } else if(d.s===400){
            setMsg('er','❌ File tidak valid atau format tidak didukung (400).');
          } else {
            setMsg('er','❌ Gagal upload ('+d.s+'). Coba lagi.');
          }
        })
        .catch(function(e){
          var m=String(e);
          if(m.indexOf('AUTH_FAIL:403')>=0)
            setMsg('er','❌ Sesi tidak terdeteksi (403). Pastikan sudah login ke GenieACS, lalu muat ulang halaman.');
          else if(m.indexOf('AUTH_FAIL:')>=0)
            setMsg('er','❌ Error autentikasi ('+m+'). Muat ulang halaman.');
          else
            setMsg('er','❌ Error koneksi. Cek jaringan dan coba lagi.');
        })
        .finally(function(){upBtn.disabled=false;upBtn.textContent='Upload Logo';});
    });

    rmBtn.addEventListener('click', function(){
      if(!confirm('Reset logo ke default GenieACS?')) return;
      fetch(ADMIN+'/csrf',{credentials:'include'})
        .then(function(r){
          if(!r.ok) return Promise.reject('AUTH_FAIL:'+r.status);
          return r.json();
        })
        .then(function(j){
          return fetch(ADMIN+'/reset',{method:'POST',credentials:'include',
            headers:{'Content-Type':'application/x-www-form-urlencoded'},
            body:'token=__genie_session__&_csrf='+encodeURIComponent(j.csrf||'')});
        })
        .then(function(r){return r.text().then(function(t){return {s:r.status,t:t};});})
        .then(function(d){
          var ok=d.t.indexOf('direset')>=0||d.t.indexOf('default')>=0;
          if(ok){
            setMsg('ok','✅ Logo direset ke default! Memuat ulang halaman...');
            setTimeout(function(){ location.reload(); }, 1500);
          } else setMsg('er','❌ Gagal reset ('+d.s+'). Muat ulang dan coba lagi.');
        })
        .catch(function(e){
          var m=String(e);
          if(m.indexOf('AUTH_FAIL:403')>=0)
            setMsg('er','❌ Sesi tidak terdeteksi. Muat ulang halaman lalu coba lagi.');
          else
            setMsg('er','❌ Error koneksi saat reset.');
        });
    });

    row.appendChild(upBtn); row.appendChild(rmBtn);
    body.appendChild(msg); body.appendChild(prev); body.appendChild(area); body.appendChild(row);
    box.appendChild(head); box.appendChild(body);
    bd.appendChild(box);

    function setMsg(cls,txt){ msg.className=cls; msg.textContent=txt; }

    _modal = bd;
    return bd;
  }

  /* ════════════════════════════════════════
     SAFE PREVIEW — cegah XSS via SVG inject
     1. Whitelist ekstensi & MIME
     2. SVG: strip semua script/event handler
        sebelum render (client-side sanitize)
     3. Bungkus dalam Blob dengan MIME eksplisit
        → img.src = blob URL (bukan inline data)
     4. Revoke blob URL setelah render selesai
  ════════════════════════════════════════ */
  var SAFE_MIME = {
    'svg' :'image/svg+xml','png':'image/png',
    'jpg' :'image/jpeg','jpeg':'image/jpeg',
    'gif' :'image/gif','webp':'image/webp',
    'ico' :'image/x-icon','bmp':'image/bmp'
  };

  function sanitizeSVGClient(svgText){
    // Hapus <script> dan isinya
    svgText = svgText.replace(/<script[\s\S]*?<\/script\s*>/gi,'');
    svgText = svgText.replace(/<script[^>]*\/>/gi,'');
    // Hapus <foreignObject> (bisa embed HTML)
    svgText = svgText.replace(/<foreignObject[\s\S]*?<\/foreignObject\s*>/gi,'');
    // Hapus semua event handler (on*)
    svgText = svgText.replace(/\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]*)/gi,'');
    // Hapus javascript: di href/src/xlink:href
    svgText = svgText.replace(/(href|xlink:href|src|action)\s*=\s*["']\s*javascript:[^"']*/gi,
      function(m,a){return a+'="#"';});
    // Hapus data: URI di href/src (bisa load HTML)
    svgText = svgText.replace(/(href|xlink:href|src)\s*=\s*["']\s*data:[^"']*/gi,
      function(m,a){return a+'="#"';});
    // Hapus url(javascript:...) dan url(data:...) di style
    svgText = svgText.replace(/url\s*\(\s*["']?\s*(?:javascript|data):[^)]*["']?\s*\)/gi,'url(#)');
    // Hapus -moz-binding dan expression()
    svgText = svgText.replace(/(?:-moz-binding|expression)\s*[:(][^;")']*/gi,'');
    // Hapus <?xml-stylesheet ... ?> (load CSS eksternal)
    svgText = svgText.replace(/<\?xml-stylesheet[^?]*\?>/gi,'');
    // Hapus <!DOCTYPE (XXE)
    svgText = svgText.replace(/<!DOCTYPE[^>]*>/gi,'');
    return svgText;
  }

  function safePreview(file, prevEl){
    // 1. Validasi ekstensi
    var name = (file.name||'').toLowerCase();
    var dotIdx = name.lastIndexOf('.');
    var ext = dotIdx>=0 ? name.slice(dotIdx+1) : '';
    // Cegah null-byte dan double-extension trick
    if(!ext || !SAFE_MIME[ext] || name.indexOf('\x00')>=0){
      prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; Tipe file tidak didukung untuk preview.</span>';
      return;
    }
    // 2. Validasi ukuran (sudah di-cap 2MB tapi double-check)
    if(file.size > 2*1024*1024){
      prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; File terlalu besar.</span>';
      return;
    }

    var safeMime = SAFE_MIME[ext];

    if(ext==='svg'){
      // SVG: baca teks, sanitasi, lalu bungkus dalam Blob
      var reader = new FileReader();
      reader.onload = function(e){
        try{
          var cleaned = sanitizeSVGClient(e.target.result);
          // Pastikan masih valid SVG setelah sanitasi
          if(!/<svg[\s>]/i.test(cleaned)){
            prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; SVG tidak valid.</span>';
            return;
          }
          var blob = new Blob([cleaned],{type:'image/svg+xml'});
          renderPreviewBlob(blob, prevEl);
        }catch(ex){
          prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; Gagal memuat SVG.</span>';
        }
      };
      reader.onerror=function(){
        prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; Gagal baca file.</span>';
      };
      reader.readAsText(file);
    } else {
      // Non-SVG: buat Blob dengan MIME eksplisit (bukan dari file asli)
      var reader2 = new FileReader();
      reader2.onload = function(e){
        try{
          // Validasi magic bytes minimal (4 byte pertama)
          var arr = new Uint8Array(e.target.result.slice(0,12));
          if(!checkMagic(arr, ext)){
            prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; Format file tidak sesuai ekstensi.</span>';
            return;
          }
          var blob = new Blob([e.target.result],{type:safeMime});
          renderPreviewBlob(blob, prevEl);
        }catch(ex){
          prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; Gagal memuat gambar.</span>';
        }
      };
      reader2.onerror=function(){
        prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; Gagal baca file.</span>';
      };
      reader2.readAsArrayBuffer(file);
    }
  }

  function renderPreviewBlob(blob, prevEl){
    var url = URL.createObjectURL(blob);
    var img = document.createElement('img');
    img.alt = 'Preview';
    img.style.cssText='max-height:80px;max-width:100%;object-fit:contain;border-radius:3px;';
    // Atribut keamanan pada img
    img.setAttribute('referrerpolicy','no-referrer');
    img.setAttribute('crossorigin','anonymous');
    img.onload  = function(){ URL.revokeObjectURL(url); }; // bebaskan memori
    img.onerror = function(){
      URL.revokeObjectURL(url);
      prevEl.innerHTML='<span style="color:#c0392b;font-size:12px">&#9888; Gagal render preview.</span>';
    };
    img.src = url;
    var lbl = document.createElement('div');
    lbl.textContent='Preview (belum diupload)';
    lbl.style.cssText='font-size:11px;color:#e67e22;margin-top:4px;font-style:italic;';
    prevEl.innerHTML='';
    prevEl.appendChild(img);
    prevEl.appendChild(lbl);
  }

  function checkMagic(arr, ext){
    if(ext==='png')  return arr[0]===0x89&&arr[1]===0x50&&arr[2]===0x4E&&arr[3]===0x47;
    if(ext==='jpg'||ext==='jpeg') return arr[0]===0xFF&&arr[1]===0xD8&&arr[2]===0xFF;
    if(ext==='gif')  return arr[0]===0x47&&arr[1]===0x49&&arr[2]===0x46&&arr[3]===0x38;
    if(ext==='webp') return arr[0]===0x52&&arr[1]===0x49&&arr[2]===0x46&&arr[3]===0x46&&
                            arr[8]===0x57&&arr[9]===0x45&&arr[10]===0x42&&arr[11]===0x50;
    if(ext==='bmp')  return arr[0]===0x42&&arr[1]===0x4D;
    if(ext==='ico')  return arr[0]===0x00&&arr[1]===0x00&&arr[2]===0x01&&arr[3]===0x00;
    return true; // tipe lain lolos (sudah dihandle server-side)
  }

  function loadPrev(prev){
    var img=document.createElement('img');
    img.src=ADMIN+'/preview?t='+Date.now(); img.alt='Logo';
    img.onerror=function(){prev.innerHTML='<span>Logo default GenieACS</span>';};
    img.onload=function(){prev.innerHTML=''; prev.appendChild(img);};
  }

  function refreshLogoImgs(){
    document.querySelectorAll('img').forEach(function(img){
      if(img.src&&img.src.indexOf('logo')>=0){
        var s=img.src.split('?')[0]; img.src=s+'?t='+Date.now();
      }
    });
  }

  /* ── Open / Close ── */
  function openModal(){
    var bd = buildModal();
    if(!document.body.contains(bd)) document.body.appendChild(bd);
    bd.classList.add('open');
    // Load preview
    var prev = bd.querySelector('#rf-prev');
    if(prev) loadPrev(prev);
    // Clear msg
    var msg = bd.querySelector('#rf-msg');
    if(msg){ msg.className=''; msg.textContent=''; msg.style.display='none'; }
  }
  var _apiModal = null;

  function closeModal(){
    if(_modal){ _modal.classList.remove('open'); }
    if(_apiModal){ _apiModal.classList.remove('open'); _apiModal.style.display='none'; }
  }

  function apiUrlFromPath(path){ return location.protocol+'//'+location.host+(path||''); }
  // URL lengkap siap-copy ke RadFastBill (langsung ke endpoint /devices)
  function apiUrlFull(path){ return path ? (apiUrlFromPath(path)+'/devices') : ''; }
  function apiMsg(el, cls, txt){
    el.style.display='block';
    el.style.background=cls==='ok'?'#dff0d8':'#f2dede';
    el.style.color=cls==='ok'?'#2d6a0f':'#8b1a1a';
    el.style.border='1px solid '+(cls==='ok'?'#b8dca0':'#e0b0b0');
    el.textContent=txt;
  }

  function buildApiModal(){
    if(_apiModal && document.body.contains(_apiModal)) return _apiModal;
    // Pastikan style tombol ada walau modal logo belum pernah dibuka
    if(!document.getElementById('rf-api-style')){
      var st=document.createElement('style'); st.id='rf-api-style';
      st.textContent='#rf-api-bd.open{display:flex!important}'+
        '#rf-api-box .rf-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}'+
        '#rf-api-box .rf-btn{padding:7px 16px;border:none;border-radius:3px;cursor:pointer;font-size:13px;font-weight:bold}'+
        '#rf-api-box .rf-btn:disabled{opacity:.5;cursor:not-allowed}'+
        '#rf-api-box .rf-rm{background:#c0392b;color:#fff}';
      document.head.appendChild(st);
    }
    var bd=document.createElement('div'); bd.id='rf-api-bd';
    bd.style.cssText='display:none;position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483647;background:rgba(0,0,0,.5);align-items:center;justify-content:center;';
    bd.addEventListener('click',function(e){ if(e.target===bd) closeModal(); });

    var box=document.createElement('div'); box.id='rf-api-box';
    box.style.cssText='background:#fff;border-radius:4px;width:560px;max-width:95vw;box-shadow:0 6px 32px rgba(0,0,0,.35);font-family:Arial,sans-serif;font-size:14px;overflow:hidden;';

    var head=document.createElement('div');
    head.style.cssText='background:#d4c89a;padding:10px 16px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #b8ae82;';
    var title=document.createElement('h3'); title.textContent='API URL GenieACS (NBI)'; title.style.cssText='margin:0;font-size:15px;color:#333;';
    var x=document.createElement('button'); x.innerHTML='&times;'; x.title='Tutup'; x.style.cssText='background:none;border:none;font-size:22px;cursor:pointer;color:#555;line-height:1;padding:0 2px;';
    x.addEventListener('click',closeModal); head.appendChild(title); head.appendChild(x);

    var body=document.createElement('div'); body.style.cssText='padding:16px;';
    body.innerHTML = '<div id="rf-api-msg" style="display:none;padding:8px 10px;border-radius:3px;margin-bottom:10px;font-size:13px"></div>'+
      '<div style="font-size:13px;color:#444;margin-bottom:10px">Cek dulu URL API yang aktif. URL ini yang dipakai di RadFastBill.</div>'+
      '<label style="display:block;font-size:12px;font-weight:bold;color:#555;margin-bottom:4px">URL API lengkap (siap copy ke RadFastBill)</label>'+
      '<div style="display:flex;gap:6px;margin-bottom:10px">'+
        '<div id="rf-api-url" style="flex:1;font-family:monospace;font-size:13px;word-break:break-all;background:#f7f9fb;border:1px solid #dce4ea;border-radius:4px;padding:9px">Belum dicek</div>'+
        '<button id="rf-api-copy" class="rf-btn" style="background:#16a085;color:#fff;white-space:nowrap">📋 Copy</button>'+
      '</div>'+
      '<label style="display:block;font-size:12px;font-weight:bold;color:#555;margin-bottom:4px">Secret Path</label>'+
      '<input id="rf-api-secret" readonly style="width:100%;box-sizing:border-box;font-family:monospace;font-size:13px;background:#fafafa;border:1px solid #ddd;border-radius:4px;padding:8px;margin-bottom:10px" value="Belum dicek">'+
      '<label style="display:block;font-size:12px;font-weight:bold;color:#555;margin-bottom:4px">Token Admin (opsional kalau sudah login)</label>'+
      '<input id="rf-api-token" type="password" autocomplete="new-password" placeholder="Isi token jika belum terbaca dari session" style="width:100%;box-sizing:border-box;border:1px solid #ddd;border-radius:4px;padding:8px;margin-bottom:10px">'+
      '<div class="rf-row">'+
        '<button id="rf-api-check" class="rf-btn rf-ok" style="background:#5a8a2a;color:#fff">✓ Cek URL</button>'+
        '<button id="rf-api-change" class="rf-btn" style="background:#2980b9;color:#fff">🔄 Ganti Secret</button>'+
        '<button id="rf-api-reset" class="rf-btn rf-rm">♻ Reset</button>'+
      '</div>'+
      '<div id="rf-api-note" style="font-size:12px;color:#888;margin-top:10px;line-height:1.4">Ganti secret maksimal 3× per restart instance. Setelah secret diganti, update URL ini di RadFastBill.</div>';

    box.appendChild(head); box.appendChild(body); bd.appendChild(box);
    var msg=body.querySelector('#rf-api-msg');
    var url=body.querySelector('#rf-api-url');
    var secret=body.querySelector('#rf-api-secret');
    var token=body.querySelector('#rf-api-token');
    var check=body.querySelector('#rf-api-check');
    var change=body.querySelector('#rf-api-change');
    var reset=body.querySelector('#rf-api-reset');
    var copy=body.querySelector('#rf-api-copy');

    function call(action){
      return fetch('/__admin/api/nbi-key',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action,token:token.value||''})}).then(function(r){return r.json();});
    }
    function render(d){
      if(!d.ok){ apiMsg(msg,'er',d.error||'Gagal cek API URL'); return; }
      secret.value=d.secretPath||'(NBI gate nonaktif)';
      url.textContent=d.secretPath?apiUrlFull(d.secretPath):'(NBI gate nonaktif)';
      change.disabled=(d.maxChanges>0 && d.changesLeft<=0);
      change.textContent=d.maxChanges>0?'🔄 Ganti Secret (sisa '+d.changesLeft+'/'+d.maxChanges+')':'🔄 Ganti Secret';
      apiMsg(msg,'ok',d.autoGenerated
        ? 'URL berhasil dibuat otomatis. Salin URL ini ke RadFastBill. Catatan: tambahkan RADFAST_NBI_GATE_PATH ke .env agar tetap sama setelah restart.'
        : 'URL berhasil dicek. Salin URL ini ke RadFastBill.');
    }
    function checkInfo(){
      msg.style.display='none'; url.textContent='Mengecek...'; secret.value='Mengecek...';
      call('info').then(render).catch(function(){apiMsg(msg,'er','Gagal cek URL API. Cek koneksi/session.');});
    }
    check.addEventListener('click',function(e){ e.preventDefault(); checkInfo(); });
    change.addEventListener('click',function(e){
      e.preventDefault();
      if(!confirm('Ganti secret NBI? URL lama langsung tidak berlaku.')) return;
      call('regenerate').then(function(d){ render(d); if(d.ok) apiMsg(msg,'ok','Secret diganti. Update URL baru ini di RadFastBill.'); }).catch(function(){apiMsg(msg,'er','Gagal ganti secret.');});
    });
    reset.addEventListener('click',function(e){
      e.preventDefault();
      if(!confirm('Reset secret ke nilai awal dari .env?')) return;
      call('reset').then(function(d){ render(d); if(d.ok) apiMsg(msg,'ok','Secret direset ke awal.'); }).catch(function(){apiMsg(msg,'er','Gagal reset secret.');});
    });
    copy.addEventListener('click',function(e){
      e.preventDefault();
      var txt=url.textContent||'';
      if(!txt || txt.indexOf('http')!==0){ apiMsg(msg,'er','Cek URL dulu sebelum copy.'); return; }
      function done(){ apiMsg(msg,'ok','URL tersalin: '+txt); }
      function fallback(){
        try{ secret.focus(); var ta=document.createElement('textarea'); ta.value=txt; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); done(); }
        catch(ex){ apiMsg(msg,'er','Gagal copy otomatis. Salin manual: '+txt); }
      }
      if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done).catch(fallback); }
      else { fallback(); }
    });
    bd._rfCheckInfo = checkInfo;
    _apiModal=bd;
    return bd;
  }

  function openApiModal(){
    var bd=buildApiModal();
    if(!document.body.contains(bd)) document.body.appendChild(bd);
    bd.classList.add('open');
    bd.style.display='flex';
    if(bd._rfCheckInfo) bd._rfCheckInfo();
  }

  /* ESC key */
  document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeModal(); });

  /* ── Posisikan tombol SEJAJAR dengan tab nav (Overview, dll) ── */
  /* MutationObserver handle Mithril re-render otomatis */
  /* ── Posisikan tombol di KANAN tab Admin (paling kanan header) ── */
  function alignToNav(b){
    // Cari tab Admin (terakhir di nav)
    var adminLink = document.querySelector('#header a[href*="admin"]');
    if(!adminLink){
      // Fallback: link terakhir di #header
      var all = document.querySelectorAll('#header a');
      adminLink = all.length ? all[all.length - 1] : null;
    }
    if(!adminLink){ b.style.display='none'; return; }
    var ar = adminLink.getBoundingClientRect();
    var btnH = ar.height || 22;
    b.style.opacity   = '0';
    b.style.display   = '';
    b.style.position  = 'fixed';
    // Vertikal: sejajar tengah tab Admin
    b.style.top       = Math.round(ar.top + (ar.height - btnH) / 2) + 'px';
    // Horizontal: offset di kanan tab Admin (offsetPx untuk tombol kedua)
    b.style.left      = Math.round(ar.right + 6 + (b._rfOffset || 0)) + 'px';
    b.style.right     = 'auto';
    b.style.height    = btnH + 'px';
    b.style.lineHeight= btnH + 'px';
    b.style.opacity   = '1';
  }

  function syncBtn(){
    // Deteksi halaman login GenieACS, abaikan field password milik modal kita
    var onLogin = !!document.querySelector('input[type="password"]:not(#rf-api-token):not(#rf-finput)');
    var btn = document.getElementById('rf-nav-btn');
    var apiBtn = document.getElementById('rf-nav-api');
    if(onLogin){
      if(btn) btn.style.display='none';
      if(apiBtn) apiBtn.style.display='none';
      return;
    }
    if(!btn){
      btn = document.createElement('span');
      btn.id = 'rf-nav-btn';
      btn.setAttribute('style',
        'position:fixed;z-index:2147483647;display:none;' +
        'background:#c0392b;color:#fff;border-radius:3px;padding:0 8px;' +
        'font-weight:bold;font-size:11px;font-family:Arial,sans-serif;' +
        'user-select:none;white-space:nowrap;cursor:pointer;' +
        'letter-spacing:0.3px;box-shadow:0 1px 3px rgba(0,0,0,.25);'
      );
      btn.innerHTML='\u270E Ganti Logo';
      btn.addEventListener('click', function(e){
        e.preventDefault(); e.stopPropagation(); openModal();
      });
      document.documentElement.appendChild(btn);
    }
    if(!apiBtn){
      apiBtn = document.createElement('span');
      apiBtn.id = 'rf-nav-api';
      apiBtn.setAttribute('style',
        'position:fixed;z-index:2147483647;display:none;' +
        'background:#2980b9;color:#fff;border-radius:3px;padding:0 8px;' +
        'font-weight:bold;font-size:11px;font-family:Arial,sans-serif;' +
        'user-select:none;white-space:nowrap;cursor:pointer;' +
        'letter-spacing:0.3px;box-shadow:0 1px 3px rgba(0,0,0,.25);'
      );
      apiBtn.innerHTML='\uD83D\uDD11 API URL';
      apiBtn.addEventListener('click', function(e){
        e.preventDefault(); e.stopPropagation(); openApiModal();
      });
      document.documentElement.appendChild(apiBtn);
    }
    // Posisikan: Logo tepat di kanan Admin, API di kanan tombol Logo
    btn._rfOffset = 0;
    alignToNav(btn);
    var logoW = btn.getBoundingClientRect().width || 78;
    apiBtn._rfOffset = logoW + 6;
    alignToNav(apiBtn);
  }

  /* ── Startup: MutationObserver + resize listener ── */
  function startBtn(){
    syncBtn();
    // Observer deteksi Mithril render ulang header → realign tombol
    var lastHdr = null;
    var observer = new MutationObserver(function(){ syncBtn(); });
    var hdr = document.getElementById('header');
    if(hdr){ observer.observe(hdr, {childList:true, subtree:true}); lastHdr=hdr; }
    // Juga watch body untuk case header muncul lambat
    observer.observe(document.body, {childList:true, subtree:true});
    // Resize listener
    window.addEventListener('resize', function(){ syncBtn(); });
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded', startBtn);
  } else {
    startBtn();
  }

  // Handle direct URL /__admin/logo
  if(location.pathname==='/__admin/logo'){
    history.replaceState(null,'','/');
    setTimeout(openModal,800);
  }
})();
</script>`;

// ── Cookie isolation wrapper ─────────────────────────────────
// Diinjeksi di awal <head> SEBELUM app.js agar aktif sebelum Mithril baca cookie.
// Teknik: walk prototype chain cari descriptor, lalu Object.defineProperty
// di document instance (bukan prototype) — ini yang benar & aman.
// Bug lama: cek `!d.configurable` terlalu ketat (undefined → early return).
// Fix: hapus cek itu, pakai try-catch saja.
const COOKIE_WRAPPER = String.raw`<script>
(function(){
  'use strict';
  var PFX='_p${PUBLIC_PORT}_';
  // Cari cookie descriptor dengan walk prototype chain
  var d=null, proto=document;
  while((proto=Object.getPrototypeOf(proto))){
    d=Object.getOwnPropertyDescriptor(proto,'cookie');
    if(d&&d.get&&d.set)break;
    d=null;
  }
  if(!d)return;
  var _get=d.get.bind(document);
  var _set=d.set.bind(document);
  try{
    Object.defineProperty(document,'cookie',{
      configurable:true,
      enumerable:true,
      get:function(){
        return _get().split(';').map(function(c){
          var t=c.trim();
          if(!t)return null;
          if(t.slice(0,PFX.length)===PFX)return t.slice(PFX.length);
          if(/^_p\d+_/.test(t))return null;
          return c;
        }).filter(function(x){return x!==null&&x!=='';}).join('; ');
      },
      set:function(v){
        if(!v)return;
        var eq=v.indexOf('=');
        if(eq<0){_set(v);return;}
        var n=v.slice(0,eq).trim();
        if(/^_p\d+_/.test(n)||n==='_rfcsrf'){_set(v);return;}
        _set(PFX+n+v.slice(eq));
      }
    });
  }catch(e){}
})();
</script>`;

// Script ganti logo GenieACS via DOM — FALLBACK saja.
// Mekanisme utama = patch SVG data URI di app.js (patchLogoInJS), jadi
// Mithril render logo custom secara NATIVE tanpa flash.
// Script ini HANYA bertindak kalau patch JS gagal (src masih SVG asli /public/).
// PENTING: jangan pernah set opacity:0 — kalau onload tidak fire (cached /
// element diganti Mithril), logo bisa hilang permanen.
function buildLogoReplacerScript(ts) {
    return String.raw`<script>
(function(){
  'use strict';
  var SRC='/__admin/logo/preview?t=${ts}';
  var DONE='__rfLogoDone';

  function isOriginalLogo(src){
    /* Logo asli GenieACS = SVG data URI ATAU file dari /public/ */
    if(!src) return false;
    if(src.indexOf('data:image/svg+xml')>=0) return true;
    if(src.indexOf('/public/')>=0 && src.indexOf('.svg')>=0) return true;
    return false;
  }

  function applyLogo(){
    var hdr=document.getElementById('header');
    if(!hdr) return;
    var logo=hdr.querySelector('.logo')||hdr;
    var imgs=logo.querySelectorAll('img');
    for(var i=0;i<imgs.length;i++){
      var img=imgs[i];
      var src=img.getAttribute('src')||'';
      /* Sudah pakai logo custom (dari JS patch ATAU dari kita) → biarkan */
      if(src.indexOf('/__admin/logo/preview')>=0){
        img.setAttribute(DONE,'1');
        continue;
      }
      /* JS patch gagal & ini logo asli → ganti src LANGSUNG (tanpa hide) */
      if(isOriginalLogo(src) && !img.getAttribute(DONE)){
        img.setAttribute('src',SRC);
        img.setAttribute(DONE,'1');
      }
    }
  }

  function init(){
    applyLogo();
    /* Observer ringan: pantau perubahan DOM, debounce 40ms */
    new MutationObserver(function(){
      clearTimeout(window.__rfLogoTimer);
      window.__rfLogoTimer=setTimeout(applyLogo,40);
    }).observe(document.body,{childList:true,subtree:true});
  }

  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded',init);
  } else {
    init();
  }
  window.addEventListener('load',function(){setTimeout(applyLogo,150);});
})();
</script>`;
}

function injectNavLink(html) {
    // Inject di awal <head>:
    //   1. COOKIE_WRAPPER — harus sebelum app.js untuk cookie isolation
    //   2. Logo CSS — override posisi versi saat custom logo aktif
    // TIDAK perlu DOM injection untuk logo — GenieACS logo request diintercept
    // langsung di proxy (isLogoReq handler) dan diganti dengan logo custom.
    const LOGO_CSS = findCustomLogo() ? `<style id="__rf-logo-css">
/* Override posisi logo+versi — pastikan versi di bawah logo, rata kiri */
#header>.logo                { display:inline-flex!important;flex-direction:column!important;align-items:flex-start!important;position:relative!important;vertical-align:top!important;padding-bottom:10px!important;gap:0!important }
#header>.logo>img            { margin:10px!important;margin-bottom:0!important;height:56px!important;width:auto!important;object-fit:contain!important;vertical-align:top!important }
#header>.logo>.version      { position:absolute!important;bottom:0!important;left:auto!important;right:10px!important;top:auto!important;font-family:monospace!important;font-size:10px!important;color:#666!important;line-height:1!important;white-space:nowrap!important;transform:none!important;letter-spacing:0!important }
</style>` : '';
    const headInject = COOKIE_WRAPPER + LOGO_CSS;

    var headTag = html.match(/<head[^>]*>/i);
    if (headTag) {
        html = html.replace(headTag[0], headTag[0] + headInject);
    } else if (html.includes('</head>')) {
        html = html.replace('</head>', headInject + '</head>');
    }

    if (html.includes('</body>')) {
        return html.replace('</body>', NAV_INJECT + '</body>');
    }
    if (html.includes('</html>')) {
        return html.replace('</html>', NAV_INJECT + '</html>');
    }
    return html + NAV_INJECT;
}

// ════════════════════════════════════════════════════════════
//  JS BUNDLE LOGO PATCH
//  GenieACS inline logo sebagai SVG data URI di app.js (webpack).
//  Proxy intercept response app.js, replace data URI dengan URL
//  logo custom kita → logo muncul native tanpa DOM injection.
//  Cache in-memory dengan ETag; clear saat logo baru diupload.
// ════════════════════════════════════════════════════════════
let _jsPatch   = null;    // { buf: Buffer, etag: string }
let _origSVG   = null;    // { w, h, viewBox } dimensi SVG asli GenieACS
let _svgPreview = { buf: null, tag: null };  // cache preview SVG logo

// ── Cache logo di memory → serve instan, tidak re-read disk tiap request ──
// Didefinisikan SEKALI di module scope (bukan per-request).
let _logoMemCache = { buf: null, ext: null, etag: null };
function refreshLogoMemCache() {
    const custom = findCustomLogo();
    if (!custom) { _logoMemCache = { buf: null, ext: null, etag: null }; return; }
    try {
        const buf  = fs.readFileSync(custom);
        const ext  = path.extname(custom).toLowerCase();
        const st   = fs.statSync(custom);
        const etag = '"' + st.size.toString(16) + '-' + st.mtimeMs.toString(16) + '"';
        _logoMemCache = { buf, ext, etag };
        console.log(`[logo] mem-cache refreshed: ${custom} (${buf.length} bytes)`);
    } catch(e) { _logoMemCache = { buf: null, ext: null, etag: null }; }
}
// Load awal + watch perubahan file (debounce 1s)
refreshLogoMemCache();
let _logoWatchTimer = null;
try {
    const _watchDir = path.dirname(process.env.RADFAST_LOGO_FILE || '/tmp/radfast-logo');
    fs.watch(_watchDir, function(){
        clearTimeout(_logoWatchTimer);
        _logoWatchTimer = setTimeout(refreshLogoMemCache, 1000);
    });
} catch(_){}

function clearJSPatch() {
    _jsPatch = null;
    _svgPreview = { buf: null, tag: null };  // clear preview cache juga
    refreshLogoMemCache();                   // refresh logo mem-cache juga
    console.log('[logo-patch] JS patch + preview + logo mem-cache cleared');
}

function patchLogoInJS(jsStr) {
    if (!findCustomLogo()) return null;

    const svgRe = /data:image\/svg\+xml;base64,([A-Za-z0-9+/=]{200,})/g;
    let n = 0;
    const ts = Date.now();
    const patched = jsStr.replace(svgRe, (_, b64) => {
        n++;
        // Ambil dimensi SVG asli dari match pertama (logo utama)
        if (n === 1 && !_origSVG) {
            try {
                const svgTxt = Buffer.from(b64, 'base64').toString('utf-8');
                const vb  = svgTxt.match(/viewBox\s*=\s*["']([^"']+)["']/i);
                const w   = svgTxt.match(/<svg[^>]+\bwidth\s*=\s*["']([^"'%]+)["']/i);
                const h   = svgTxt.match(/<svg[^>]+\bheight\s*=\s*["']([^"'%]+)["']/i);
                if (vb || (w && h)) {
                    const parts = vb ? vb[1].trim().split(/\s+/).map(Number) : null;
                    _origSVG = {
                        viewBox : vb  ? vb[1]  : `0 0 ${w[1]} ${h[1]}`,
                        w       : w   ? w[1]   : (parts ? parts[2] : null),
                        h       : h   ? h[1]   : (parts ? parts[3] : null)
                    };
                    console.log(`[logo-patch] Dimensi SVG asli: ${JSON.stringify(_origSVG)}`);
                }
            } catch(e) { /* abaikan */ }
        }
        return `/__admin/logo/preview?t=${ts}`;
    });
    if (n === 0) { console.log('[logo-patch] Tidak ada SVG ditemukan di bundle'); return null; }
    console.log(`[logo-patch] ${n} SVG data URI diganti`);
    return patched;
}

// Buat SVG wrapper dengan dimensi SAMA seperti logo asli GenieACS.
// Logo custom di-embed di dalamnya → CSS GenieACS tetap bekerja,
// posisi teks versi, padding, dll. persis seperti logo asli.
function buildLogoSVG(logoPath) {
    try {
        const data = fs.readFileSync(logoPath);
        const ext  = path.extname(logoPath).toLowerCase();
        const mime = MIME[ext] || 'image/png';
        const b64  = data.toString('base64');

        const vb   = (_origSVG && _origSVG.viewBox) || '0 0 250 40';
        const parts = vb.trim().split(/\s+/).map(Number);
        const W    = (_origSVG && _origSVG.w)       || parts[2] || 250;
        const H    = (_origSVG && _origSVG.h)       || parts[3] || 40;

        // Gunakan preserveAspectRatio xMidYMid meet → logo tetap proporsional
        // dan terpusat dalam kotak yang sama dengan logo GenieACS asli
        return Buffer.from(
            `<?xml version="1.0" encoding="UTF-8"?>` +
            `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"` +
            ` viewBox="${vb}" width="${W}" height="${H}">` +
            `<image href="data:${mime};base64,${b64}"` +
            ` x="0" y="0" width="${W}" height="${H}" preserveAspectRatio="xMidYMid meet"/>` +
            `</svg>`,
            'utf-8'
        );
    } catch(e) {
        return null;
    }
}

// ════════════════════════════════════════════════════════════
//  PROXY KE GENIEACS UI
//  - Strip Accept-Encoding supaya response tidak gzip
//    (agar bisa inject tombol ke HTML dan patch JS bundle)
// ════════════════════════════════════════════════════════════
function proxyRequest(req, res) {
    // Hapus Accept-Encoding agar GenieACS kirim HTML plain (bukan gzip)
    const headers = { ...req.headers, host: `127.0.0.1:${GENIE_PORT}` };
    delete headers['accept-encoding'];
    // Strip prefix sebelum diteruskan ke GenieACS
    if (headers.cookie) headers.cookie = rewriteCookieForUpstream(headers.cookie);

    const opts = {
        hostname : '127.0.0.1',
        port     : GENIE_PORT,
        path     : req.url,
        method   : req.method,
        headers
    };

    const proxy = http.request(opts, (pRes) => {
        const ct = (pRes.headers['content-type'] || '');

        const respHeaders = { ...pRes.headers };
        // Prefix Set-Cookie dari GenieACS agar tiap instance punya cookie berbeda
        if (respHeaders['set-cookie']) {
            const sc = respHeaders['set-cookie'];
            respHeaders['set-cookie'] = Array.isArray(sc)
                ? sc.map(rewriteSetCookie) : [rewriteSetCookie(sc)];
        }

        // ── HTML: inject navbar + cookie wrapper ──────────────
        if (ct.includes('text/html')) {
            const chunks = [];
            pRes.on('data', c => chunks.push(c));
            pRes.on('end', () => {
                let html = Buffer.concat(chunks).toString('utf-8');
                html = injectNavLink(html);

                delete respHeaders['content-length'];
                delete respHeaders['content-encoding'];
                delete respHeaders['transfer-encoding'];
                delete respHeaders['content-security-policy'];
                delete respHeaders['x-content-security-policy'];

                const buf = Buffer.from(html, 'utf-8');
                respHeaders['content-length'] = buf.length;
                res.writeHead(pRes.statusCode, respHeaders);
                res.end(buf);
            });
            pRes.on('error', () => res.end());

        // ── JS bundle: patch logo data URI ────────────────────
        } else if ((ct.includes('javascript') || ct.includes('text/plain')) &&
                   /\/public\/[^/]+\.js(\?|$)/i.test(req.url) &&
                   findCustomLogo()) {

            // Serve dari cache kalau ETag cocok (browser tidak perlu re-download)
            const inm = req.headers['if-none-match'];
            if (_jsPatch && inm && inm === _jsPatch.etag) {
                res.writeHead(304, {
                    'ETag'          : _jsPatch.etag,
                    'Cache-Control' : 'max-age=0, must-revalidate'
                });
                res.end();
                return;
            }

            const chunks = [];
            pRes.on('data', c => chunks.push(c));
            pRes.on('end', () => {
                const js      = Buffer.concat(chunks).toString('utf-8');
                const patched = patchLogoInJS(js);
                const content = patched || js;
                const buf     = Buffer.from(content, 'utf-8');

                delete respHeaders['content-encoding'];
                delete respHeaders['transfer-encoding'];
                respHeaders['content-length'] = buf.length;

                if (patched) {
                    // ETag unik untuk versi patched — cache di browser, refresh saat logo ganti
                    const etag = '"rf-' + crypto.createHash('md5')
                        .update(buf).digest('hex').slice(0, 8) + '"';
                    respHeaders['etag']          = etag;
                    respHeaders['cache-control'] = 'max-age=0, must-revalidate';
                    _jsPatch = { buf, etag };
                }

                res.writeHead(pRes.statusCode, respHeaders);
                res.end(buf);
            });
            pRes.on('error', () => res.end());

        } else {
            // Non-HTML, non-JS → pass-through
            res.writeHead(pRes.statusCode, respHeaders);
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
//  NBI SECURE GATE
//  NBI (REST API GenieACS) TIDAK punya auth bawaan. Daripada buka
//  port NBI ke publik, kita expose lewat SECRET PATH di port UI publik
//  ini. Hanya yang tahu path rahasia yang bisa akses.
//  Contoh: http://IP:3001/<secret>/devices  →  127.0.0.1:7558/devices
// ════════════════════════════════════════════════════════════
function proxyNbiRequest(req, res, upstreamPath) {
    const headers = { ...req.headers, host: `127.0.0.1:${NBI_PORT}` };
    delete headers['accept-encoding'];
    // Cookie UI tidak relevan untuk NBI — buang biar bersih
    delete headers['cookie'];

    const opts = {
        hostname : '127.0.0.1',
        port     : NBI_PORT,
        path     : upstreamPath,
        method   : req.method,
        headers
    };

    const proxy = http.request(opts, (pRes) => {
        const respHeaders = { ...pRes.headers };
        delete respHeaders['content-security-policy'];
        delete respHeaders['x-content-security-policy'];
        res.writeHead(pRes.statusCode, respHeaders);
        pRes.pipe(res);
    });

    proxy.on('error', () => {
        sendSecure(res, 502, 'application/json', '{"error":"NBI upstream tidak tersedia"}');
    });

    req.pipe(proxy);
}

// ════════════════════════════════════════════════════════════
//  MAIN SERVER
// ════════════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0].replace(/\/+$/, '') || '/';
    const ip  = getIP(req);

    // ── Slow-loris / timeout protection ──────────────────────
    req.socket.setTimeout(30000);
    // Tambah listener sekali saja per socket (keep-alive bisa reuse socket)
    if (!req.socket._rfTimeout) {
        req.socket._rfTimeout = true;
        req.socket.on('timeout', () => { req.socket.destroy(); });
    }

    // ── Blokir Content-Length terlalu besar SEBELUM baca body ─
    if (req.method === 'POST') {
        const cl = parseInt(req.headers['content-length'] || '0', 10);
        if (cl > MAX_SIZE + 65536) { // 64KB toleransi untuk header multipart
            auditLog('REJECT', ip, `Content-Length terlalu besar: ${cl} bytes`);
            sendSecure(res, 413, 'text/plain', 'Payload Too Large');
            return;
        }
    }

    // ── Admin API: lihat/ganti/reset NBI secret path ─────────
    if (url === '/__admin/api/nbi-key' && req.method === 'POST') {
        let raw = '';
        req.on('data', c => { raw += c; if (raw.length > 4096) req.destroy(); });
        req.on('end', () => {
            try {
                const data = JSON.parse(raw || '{}');
                const token = String(data.token || '').trim();
                const action = String(data.action || '').trim();
                const authedBySession = isGenieSession(req);
                const authedByToken = ADMIN_TOKEN && token === ADMIN_TOKEN;
                if (!authedBySession && !authedByToken) {
                    sendSecure(res, 401, 'application/json', JSON.stringify({ ok: false, error: 'Unauthorized (session/token)' }));
                    return;
                }

                if (action === 'info') {
                    sendSecure(res, 200, 'application/json', JSON.stringify({
                        ok: true,
                        secretPath: nbiGateCurrentPath,
                        originalPath: nbiGateOriginalPath,
                        changesLeft: nbiGateChangesLeft,
                        maxChanges: NBI_GATE_MAX_CHANGES,
                        autoGenerated: NBI_GATE_AUTO_GENERATED
                    }));
                    return;
                }

                if (action === 'reset') {
                    nbiGateCurrentPath = nbiGateOriginalPath;
                    nbiGateChangesLeft = NBI_GATE_MAX_CHANGES;
                    refreshNbiGateConst();
                    sendSecure(res, 200, 'application/json', JSON.stringify({
                        ok: true,
                        secretPath: nbiGateCurrentPath,
                        changesLeft: nbiGateChangesLeft,
                        maxChanges: NBI_GATE_MAX_CHANGES
                    }));
                    return;
                }

                if (action === 'regenerate') {
                    if (NBI_GATE_MAX_CHANGES > 0 && nbiGateChangesLeft <= 0) {
                        sendSecure(res, 400, 'application/json', JSON.stringify({ ok: false, error: 'Batas ganti secret sudah habis. Reset/restart instance untuk mengulang.' }));
                        return;
                    }
                    nbiGateCurrentPath = `/_acs-${crypto.randomBytes(20).toString('hex')}`;
                    if (NBI_GATE_MAX_CHANGES > 0) nbiGateChangesLeft--;
                    refreshNbiGateConst();
                    sendSecure(res, 200, 'application/json', JSON.stringify({
                        ok: true,
                        secretPath: nbiGateCurrentPath,
                        changesLeft: nbiGateChangesLeft,
                        maxChanges: NBI_GATE_MAX_CHANGES
                    }));
                    return;
                }

                sendSecure(res, 400, 'application/json', JSON.stringify({ ok: false, error: 'Action tidak dikenal' }));
            } catch(e) {
                sendSecure(res, 400, 'application/json', JSON.stringify({ ok: false, error: 'Request tidak valid' }));
            }
        });
        return;
    }

    // ── NBI secure gate → teruskan ke REST API GenieACS ────
    // Hanya request yang lewat SECRET PATH yang diteruskan ke NBI lokal.
    // Akses /devices dll tanpa path rahasia TIDAK akan match → jatuh ke UI.
    if (NBI_GATE_PATH &&
        (req.url === NBI_GATE_PATH ||
         req.url.startsWith(NBI_GATE_PATH + '/') ||
         req.url.startsWith(NBI_GATE_PATH + '?'))) {
        let upstreamPath = req.url.slice(NBI_GATE_PATH.length);
        if (upstreamPath === '' || upstreamPath[0] === '?') upstreamPath = '/' + upstreamPath;
        proxyNbiRequest(req, res, upstreamPath);
        return;
    }

    // ── Admin: tampilkan form ──────────────────────────────
    if (url === '/__admin/logo') {
        const authed = isGenieSession(req);
        if (!authed && !ADMIN_TOKEN) {
            sendSecure(res, 302, 'text/html; charset=utf-8', '');
            res.setHeader('Location', '/');
            res.end();
            return;
        }
        // Set CSRF token sebagai cookie HttpOnly SameSite=Strict
        const nonce = genCSRF(ip);
        res.setHeader('Set-Cookie', `_rfcsrf=${nonce}; HttpOnly; SameSite=Strict; Path=/__admin`);
        sendSecure(res, 200, 'text/html; charset=utf-8', uploadPage('', authed, nonce));
        return;
    }

    // ── Admin: endpoint CSRF token (untuk modal via fetch) ──
    if (url === '/__admin/logo/csrf' && req.method === 'GET') {
        const authed = isGenieSession(req);
        if (!authed) {
            sendSecure(res, 403, 'application/json', '{"error":"Unauthorized"}');
            return;
        }
        const nonce = genCSRF(ip);
        res.setHeader('Set-Cookie', `_rfcsrf=${nonce}; HttpOnly; SameSite=Strict; Path=/__admin`);
        sendSecure(res, 200, 'application/json', JSON.stringify({ csrf: nonce }));
        return;
    }

    // ── Admin: preview logo ────────────────────────────────
    if (url === '/__admin/logo/preview') {
        const f = findCustomLogo();
        if (f) {
            // Cek cache server-side — kalau logo tidak berubah, skip buildLogoSVG
            if (!_svgPreview.buf) {
                _svgPreview.buf = buildLogoSVG(f);
                if (_svgPreview.buf) _svgPreview.tag = crypto.createHash('md5').update(_svgPreview.buf).digest('hex').slice(0, 12);
            }
            if (_svgPreview.buf) {
                const inm = req.headers['if-none-match'];
                if (inm && inm === ('"rf-' + _svgPreview.tag + '"')) {
                    res.writeHead(304, { 'Cache-Control': 'max-age=5', 'ETag': '"rf-' + _svgPreview.tag + '"' });
                    return res.end();
                }
                res.writeHead(200, {
                    'Content-Type'          : 'image/svg+xml',
                    'Cache-Control'         : 'max-age=5, must-revalidate',
                    'ETag'                  : '"rf-' + _svgPreview.tag + '"',
                    'X-Content-Type-Options': 'nosniff'
                });
                return res.end(_svgPreview.buf);
            } else {
                // Fallback: serve file asli
                const ext = path.extname(f).toLowerCase();
                const tag2 = crypto.createHash('md5').update(String(fs.statSync(f).mtimeMs)).digest('hex').slice(0,8);
                res.writeHead(200, {
                    'Content-Type'          : MIME[ext] || 'image/svg+xml',
                    'Cache-Control'         : 'max-age=5, must-revalidate',
                    'ETag'                  : '"rf-' + tag2 + '"',
                    'X-Content-Type-Options': 'nosniff'
                });
                fs.createReadStream(f).pipe(res);
            }
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

                // ── Cek auth: session GenieACS ATAU token manual ──
                const tok       = (parts.token && parts.token.value) ? parts.token.value : '';
                const bySession = tok === '__genie_session__' && isGenieSession(req);
                const byToken   = !bySession && safeTokenCheck(tok);

                if (!bySession && !byToken) {
                    recordFail(ip, 'Token salah / session tidak valid');
                    const authed = isGenieSession(req);
                    sendSecure(res, 403, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ Akses ditolak. Login ke GenieACS dulu atau masukkan token yang benar.</div>', authed));
                    return;
                }

                // ── CSRF check (hanya untuk akses langsung/form, bukan modal AJAX) ──
                // Modal kirim CSRF via field _csrf (fetch dari /__admin/logo/csrf)
                // Kalau tidak ada CSRF field → pastikan Origin sama (AJAX dari dashboard)
                const csrfField  = (parts._csrf && parts._csrf.value) || '';
                const origin     = req.headers['origin'] || '';
                const referer    = req.headers['referer'] || '';
                const sameOrigin = origin.includes(`${req.headers.host}`) ||
                                   referer.includes(`${req.headers.host}`);
                if (csrfField) {
                    if (!checkCSRF(csrfField, ip)) {
                        recordFail(ip, 'CSRF token tidak valid');
                        sendSecure(res, 403, 'text/html; charset=utf-8',
                            uploadPage('<div class="msg er">❌ Token keamanan tidak valid. Muat ulang halaman dan coba lagi.</div>'));
                        return;
                    }
                } else if (!sameOrigin && !bySession) {
                    // Tidak ada CSRF field, bukan same-origin, bukan session → tolak
                    recordFail(ip, 'CSRF missing + cross-origin');
                    sendSecure(res, 403, 'text/plain', 'Forbidden');
                    return;
                }

                if (bySession) auditLog('SESSION', ip, 'Upload via GenieACS session');
                if (byToken)   auditLog('TOKEN',   ip, 'Upload via admin token');

                // ── Cek file ada ───────────────────────────
                const file = parts.logo;
                if (!file || !file.data || file.data.length < 16) {
                    sendSecure(res, 400, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ File tidak diterima.</div>'));
                    return;
                }

                // ── Tentukan ekstensi dari nama file ────────
                const rawFilename = file.filename || '';
                // Cegah null-byte injection (bypass ekstensi check)
                if (rawFilename.includes('\x00') || rawFilename.includes('%00')) {
                    recordFail(ip, 'Null byte dalam filename');
                    sendSecure(res, 400, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ Nama file tidak valid.</div>'));
                    return;
                }
                const origExt = path.extname(rawFilename).toLowerCase();
                if (!ALLOWED_EXT.includes(origExt)) {
                    recordFail(ip, `Ekstensi tidak diizinkan: ${origExt}`);
                    sendSecure(res, 400, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ Format tidak didukung. Gunakan SVG, PNG, JPG, GIF, WebP, ICO, atau BMP.</div>'));
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
                clearJSPatch(); // paksa re-patch app.js dengan logo baru

                sendSecure(res, 200, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg ok">✅ Logo berhasil diupload!</div>', bySession || isGenieSession(req)));

            } catch(e) {
                console.error(`[logo-proxy] Upload error dari ${ip}:`, e.message);
                sendSecure(res, 500, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg er">❌ Terjadi kesalahan server. Coba lagi.</div>', isGenieSession(req)));
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
            const body      = Buffer.concat(chunks).toString('utf-8', 0, 4096);
            const tokM      = body.match(/(?:^|&)token=([^&]*)/);
            const csrfM     = body.match(/(?:^|&)_csrf=([^&]*)/);
            const tok       = tokM  ? decodeURIComponent(tokM[1])  : '';
            const csrfVal   = csrfM ? decodeURIComponent(csrfM[1]) : '';
            const bySession = tok === '__genie_session__' && isGenieSession(req);
            const byToken   = !bySession && safeTokenCheck(tok);
            const authed    = isGenieSession(req);

            if (!bySession && !byToken) {
                recordFail(ip, 'Token salah saat reset');
                sendSecure(res, 403, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg er">❌ Akses ditolak.</div>', authed));
                return;
            }

            // CSRF check
            const origin    = req.headers['origin'] || '';
            const referer   = req.headers['referer'] || '';
            const sameOrig  = origin.includes(req.headers.host) || referer.includes(req.headers.host);
            if (csrfVal) {
                if (!checkCSRF(csrfVal, ip)) {
                    recordFail(ip, 'CSRF invalid saat reset');
                    sendSecure(res, 403, 'text/html; charset=utf-8',
                        uploadPage('<div class="msg er">❌ Token keamanan tidak valid. Muat ulang halaman.</div>', authed));
                    return;
                }
            } else if (!sameOrig && !bySession) {
                recordFail(ip, 'CSRF missing cross-origin reset');
                sendSecure(res, 403, 'text/plain', 'Forbidden');
                return;
            }

            deleteAllLogo();
            clearJSPatch(); // paksa re-patch app.js (tidak ada logo lagi)
            auditLog('RESET', ip, 'Logo direset ke default');
            sendSecure(res, 200, 'text/html; charset=utf-8',
                uploadPage('<div class="msg ok">✅ Logo direset ke logo default.</div>', authed));
        });
        req.on('error', () => {});
        return;
    }

    // ── Blokir akses admin lain ────────────────────────────
    if (url.startsWith('/__admin')) {
        sendSecure(res, 404, 'text/plain', 'Not found');
        return;
    }

    // ── Intercept semua request logo GenieACS ─────────────
    // GenieACS serve static via koa-static dengan root=<install>/public,
    // jadi URL-nya TANPA prefix /public/, contoh:
    //   /logo-3976e73d.svg   (logo utama, di-referensikan var Mo di bundle)
    //   /logo-white.svg, /logo.svg, /public/logo.svg (varian)
    // ── Logo HTTP intercept ──────────────────────────────
    // Tangkap path apapun yang ada kata "logo" + ekstensi gambar,
    // dengan ATAU tanpa prefix /public/.
    const isLogoReq = /(?:^|\/)[^/?]*logo[^/?]*\.(svg|png|jpe?g|gif|webp|ico|bmp)(?:\?|$)/i.test(req.url);
    if (isLogoReq) {
        if (_logoMemCache.buf) {
            const etag = _logoMemCache.etag;
            const mime = MIME[_logoMemCache.ext] || 'image/svg+xml';
            // Browser sudah punya versi sama? → 304 (0 bytes, instant)
            if (etag && req.headers['if-none-match'] === etag) {
                res.writeHead(304, { 'ETag': etag, 'Cache-Control': 'public, max-age=31536000, immutable' });
                res.end();
                return;
            }
            console.log(`[logo] intercept ${req.url} → serve from mem-cache (${_logoMemCache.buf.length}b)`);
            res.writeHead(200, {
                'Content-Type'          : mime,
                'Content-Length'         : _logoMemCache.buf.length,
                // immutable + 1tahun: browser TIDAK akan re-request selama ETag sama
                // → no-flash. Saat logo diganti → ETag beda → browser download sekali.
                'Cache-Control'         : 'public, max-age=31536000, immutable',
                'X-Content-Type-Options': 'nosniff',
                ...(etag ? { 'ETag': etag } : {})
            });
            res.end(_logoMemCache.buf);  // end() langsung dari memory, 0ms latency
            return;
        }
        // Tidak ada custom logo → pass-through ke GenieACS (logo default)
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
    // Di bawah multi-proxy: jangan bunuh seluruh proses (instance lain masih jalan).
    if (process.env.RADFAST_MULTI_PROXY === '1') {
        console.error(`[logo-proxy] :${PUBLIC_PORT} SKIP (${err.code || err.message})`);
        return;
    }
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
