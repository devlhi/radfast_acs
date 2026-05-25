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
    // (tidak bergantung pada nama cookie, kompatibel dengan semua versi GenieACS)
    const cookieStr = req.headers['cookie'] || '';
    for (const part of cookieStr.split(';')) {
        const val = part.trim().split('=').slice(1).join('=');
        try {
            if (val && verifyGenieJWT(decodeURIComponent(val))) return true;
        } catch(_) {}
    }
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
        '@keyframes rf-bounce{0%,100%{transform:translateY(0)}50%{transform:translateY(-4px)}}'
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
      // Fetch CSRF token dulu (anti-CSRF)
      fetch(ADMIN+'/csrf',{credentials:'include'})
        .then(function(r){return r.ok?r.json():Promise.reject('csrf-fail');})
        .then(function(j){
          var fd=new FormData();
          fd.append('logo',f);
          fd.append('token','__genie_session__');
          fd.append('_csrf', j.csrf||'');
          return fetch(ADMIN+'/upload',{method:'POST',body:fd,credentials:'include'});
        })
        .then(function(r){return r.text();})
        .then(function(t){
          var ok=t.indexOf('berhasil')>=0||t.indexOf('Logo berhasil')>=0;
          setMsg(ok?'ok':'er', ok?'✅ Logo berhasil diupload!':'❌ Gagal upload, coba lagi.');
          if(ok){ loadPrev(prev); refreshLogoImgs(); }
        })
        .catch(function(){setMsg('er','❌ Error koneksi atau token keamanan gagal.');})
        .finally(function(){upBtn.disabled=false;upBtn.textContent='Upload Logo';});
    });

    rmBtn.addEventListener('click', function(){
      if(!confirm('Reset logo ke default GenieACS?')) return;
      // Fetch CSRF token dulu
      fetch(ADMIN+'/csrf',{credentials:'include'})
        .then(function(r){return r.ok?r.json():Promise.reject('csrf-fail');})
        .then(function(j){
          return fetch(ADMIN+'/reset',{method:'POST',credentials:'include',
            headers:{'Content-Type':'application/x-www-form-urlencoded'},
            body:'token=__genie_session__&_csrf='+encodeURIComponent(j.csrf||'')});
        })
        .then(function(r){return r.text();})
        .then(function(t){
          var ok=t.indexOf('direset')>=0||t.indexOf('default')>=0;
          setMsg(ok?'ok':'er',ok?'✅ Logo direset ke default.':'❌ Gagal reset.');
          if(ok){ loadPrev(prev); refreshLogoImgs(); }
        })
        .catch(function(){setMsg('er','❌ Error koneksi.');});
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
  function closeModal(){
    if(_modal){ _modal.classList.remove('open'); }
  }

  /* ESC key */
  document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeModal(); });

  /* ── Inject / hapus nav button sesuai halaman ── */
  function syncBtn(){
    var onLogin = !!document.querySelector('input[type="password"]');
    var btn = document.getElementById('rf-nav-btn');
    if(onLogin){
      // Halaman login — sembunyikan tombol
      if(btn) btn.style.display = 'none';
      return;
    }
    // Sudah login — tampilkan tombol
    if(btn){
      btn.style.display = '';
      return;
    }
    // Buat tombol baru
    var b = document.createElement('div');
    b.id = 'rf-nav-btn';
    b.setAttribute('style',
      'position:fixed;top:8px;right:12px;z-index:2147483647;' +
      'cursor:pointer;background:#c0392b;color:#fff;' +
      'border-radius:5px;padding:6px 14px;font-weight:bold;font-size:13px;' +
      'font-family:Arial,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.4);' +
      'user-select:none;line-height:1.5;'
    );
    b.textContent = '🖼 Ganti Logo';
    b.addEventListener('click', function(e){
      e.preventDefault(); e.stopPropagation(); openModal();
    });
    document.documentElement.appendChild(b);
  }

  /* ── Startup ── */
  // Gunakan window.load agar Mithril sudah selesai render sebelum kita inject.
  // hashchange menangani navigasi antar halaman (login ↔ dashboard).
  // Tidak pakai MutationObserver agar tidak mengganggu Mithril.
  window.addEventListener('load', function(){
    syncBtn();
    window.addEventListener('hashchange', syncBtn);
  });

  // Handle direct URL /__admin/logo
  if(location.pathname==='/__admin/logo'){
    history.replaceState(null,'','/');
    setTimeout(openModal,800);
  }
})();
</script>`;

// Injeksi di <head> — SEBELUM app.js dijalankan — agar document.cookie sudah
// terisolasi saat Mithril/GenieACS membaca atau menulis sesi.
// Getter: strip PORT_PREFIX dari cookie milik instance ini, sembunyikan cookie
//         instance lain (nama mulai _p<angka>_).
// Setter: tambah PORT_PREFIX ke semua cookie kecuali yang sudah punya prefix
//         atau milik proxy CSRF.
const COOKIE_WRAPPER = String.raw`<script>
(function(){
  'use strict';
  var P='_p${PUBLIC_PORT}_';
  var d=Object.getOwnPropertyDescriptor(Document.prototype,'cookie')||
        Object.getOwnPropertyDescriptor(HTMLDocument.prototype,'cookie');
  if(!d||!d.configurable)return;
  Object.defineProperty(document,'cookie',{
    configurable:true,
    get:function(){
      return d.get.call(document).split(';').map(function(c){
        var t=c.trim();if(!t)return'';
        if(t.slice(0,P.length)===P)return t.slice(P.length);
        if(/^_p\d+_/.test(t))return'';
        return c;
      }).filter(Boolean).join('; ');
    },
    set:function(v){
      if(v==null)return;
      var e=v.indexOf('=');
      if(e<0){d.set.call(document,v);return;}
      var n=v.slice(0,e).trim();
      if(/^_p\d+_/.test(n)||n==='_rfcsrf'){d.set.call(document,v);return;}
      d.set.call(document,P+n+v.slice(e));
    }
  });
})();
</script>`;

function injectNavLink(html) {
    // COOKIE_WRAPPER harus jalan SEBELUM app.js — inject di awal <head>
    // bukan di </head>, karena GenieACS load app.js synchronous di <head>
    if (html.includes('<head>')) {
        html = html.replace('<head>', '<head>' + COOKIE_WRAPPER);
    } else if (html.includes('<HEAD>')) {
        html = html.replace('<HEAD>', '<HEAD>' + COOKIE_WRAPPER);
    } else if (html.includes('</head>')) {
        html = html.replace('</head>', COOKIE_WRAPPER + '</head>');
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
//  PROXY KE GENIEACS UI
//  - Strip Accept-Encoding supaya response tidak gzip
//    (agar bisa inject tombol ke HTML)
// ════════════════════════════════════════════════════════════
function proxyRequest(req, res) {
    // Hapus Accept-Encoding agar GenieACS kirim HTML plain (bukan gzip)
    const headers = { ...req.headers, host: `127.0.0.1:${GENIE_PORT}` };
    delete headers['accept-encoding'];

    // Cookie isolation: hapus prefix sebelum diteruskan ke GenieACS
    if (headers.cookie) {
        headers.cookie = rewriteCookieForUpstream(headers.cookie);
    }

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

        // Cookie isolation: prefix semua Set-Cookie dari GenieACS
        if (respHeaders['set-cookie']) {
            const sc = respHeaders['set-cookie'];
            respHeaders['set-cookie'] = Array.isArray(sc)
                ? sc.map(rewriteSetCookie)
                : [rewriteSetCookie(sc)];
        }

        // Inject tombol hanya ke halaman HTML
        if (ct.includes('text/html')) {
            const chunks = [];
            pRes.on('data', c => chunks.push(c));
            pRes.on('end', () => {
                let html = Buffer.concat(chunks).toString('utf-8');

                // Inject link logo ke navbar GenieACS
                html = injectNavLink(html);

                delete respHeaders['content-length'];
                delete respHeaders['content-encoding'];
                delete respHeaders['transfer-encoding'];
                // Hapus CSP dari GenieACS agar script inject kita bisa jalan
                delete respHeaders['content-security-policy'];
                delete respHeaders['x-content-security-policy'];

                const buf = Buffer.from(html, 'utf-8');
                respHeaders['content-length'] = buf.length;

                res.writeHead(pRes.statusCode, respHeaders);
                res.end(buf);
            });
            pRes.on('error', () => res.end());
        } else {
            // Non-HTML (JS, CSS, JSON, dll) — pass-through dengan header yang sudah di-rewrite
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
//  MAIN SERVER
// ════════════════════════════════════════════════════════════
const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0].replace(/\/+$/, '') || '/';
    const ip  = getIP(req);

    // ── Slow-loris / timeout protection ──────────────────────
    req.socket.setTimeout(30000); // 30 detik max per koneksi
    req.socket.on('timeout', () => { req.socket.destroy(); });

    // ── Blokir Content-Length terlalu besar SEBELUM baca body ─
    if (req.method === 'POST') {
        const cl = parseInt(req.headers['content-length'] || '0', 10);
        if (cl > MAX_SIZE + 65536) { // 64KB toleransi untuk header multipart
            auditLog('REJECT', ip, `Content-Length terlalu besar: ${cl} bytes`);
            sendSecure(res, 413, 'text/plain', 'Payload Too Large');
            return;
        }
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
    // GenieACS pakai nama seperti:
    //   /public/logo-white.svg
    //   /public/logo-favicon.svg
    //   /public/logo.svg
    //   /public/logo-<hash>.svg
    // Tangkap semua path yang ada kata "logo" di bawah /public/
    // dengan ekstensi gambar apapun.
    const isLogoReq = /\/public\/[^/]*logo[^/]*\.(svg|png|jpe?g|gif|webp|ico|bmp)/i.test(req.url);
    if (isLogoReq) {
        const custom = findCustomLogo();
        if (custom) {
            const ext = path.extname(custom).toLowerCase();
            // Log untuk debug
            console.log(`[logo] intercept ${req.url} → serve custom: ${custom}`);
            res.writeHead(200, {
                'Content-Type'          : MIME[ext] || 'image/svg+xml',
                'Cache-Control'         : 'no-store, no-cache, must-revalidate',
                'Pragma'                : 'no-cache',
                'Expires'               : '0',
                'X-Content-Type-Options': 'nosniff'
            });
            fs.createReadStream(custom).pipe(res);
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
