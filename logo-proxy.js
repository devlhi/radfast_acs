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
const APP_PUBLIC   = process.env.RADFAST_APP_PUBLIC                || '/opt/genieacs-app/public';
const MAX_SIZE     = 2 * 1024 * 1024; // 2 MB hard limit

// Temukan semua file logo di folder public GenieACS (logo-*.svg dst)
function findAppLogoFiles() {
    try {
        return fs.readdirSync(APP_PUBLIC)
            .filter(f => /^logo[^/]*\.(svg|png|jpe?g|gif|webp|ico|bmp)$/i.test(f))
            .map(f => path.join(APP_PUBLIC, f));
    } catch(_) { return []; }
}

// Backup logo asli GenieACS (simpan sekali saja)
function backupOriginalLogos() {
    for (const f of findAppLogoFiles()) {
        const bak = f + '.radfast-orig';
        if (!fs.existsSync(bak)) {
            try { fs.copyFileSync(f, bak); } catch(_) {}
        }
    }
}

// Bungkus PNG/JPG/GIF/WebP dalam SVG agar bisa replace file .svg
// tanpa merusak format (browser expect SVG, kita embed image di dalamnya)
function wrapInSVG(imageData, ext) {
    const mimeType = MIME[ext] || 'image/png';
    const b64 = imageData.toString('base64');
    return Buffer.from(
        `<svg xmlns="http://www.w3.org/2000/svg" ` +
        `xmlns:xlink="http://www.w3.org/1999/xlink" ` +
        `viewBox="0 0 300 100" preserveAspectRatio="xMidYMid meet">` +
        `<image href="data:${mimeType};base64,${b64}" ` +
        `x="0" y="0" width="300" height="100" ` +
        `preserveAspectRatio="xMidYMid meet"/>` +
        `</svg>`
    );
}

// Terapkan custom logo ke folder public GenieACS
// Semua file logo-*.svg di public diganti dengan custom logo
// Kalau upload bukan SVG → bungkus dalam SVG wrapper dulu
function applyLogoToApp(logoFile) {
    backupOriginalLogos();
    const targets = findAppLogoFiles();
    if (targets.length === 0) {
        console.warn('[logo] Tidak ada file logo di', APP_PUBLIC);
        return;
    }

    const ext = path.extname(logoFile).toLowerCase();
    let fileData = fs.readFileSync(logoFile);

    // Kalau bukan SVG, bungkus dalam SVG supaya browser bisa render
    if (ext !== '.svg') {
        fileData = wrapInSVG(fileData, ext);
        console.log(`[logo] Wrapped ${ext} → SVG untuk app/public`);
    }

    for (const target of targets) {
        try {
            fs.writeFileSync(target, fileData);
            console.log('[logo] Applied custom logo →', target);
        } catch(e) {
            console.error('[logo] Gagal write ke', target, ':', e.message);
        }
    }
}

// Restore logo asli GenieACS dari backup
function restoreOriginalLogos() {
    for (const f of findAppLogoFiles()) {
        const bak = f + '.radfast-orig';
        if (fs.existsSync(bak)) {
            try {
                fs.copyFileSync(bak, f);
                console.log('[logo] Restored original →', f);
            } catch(e) {
                console.error('[logo] Gagal restore', f, ':', e.message);
            }
        }
    }
}

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

    // Cek semua cookie — coba tiap nilai sebagai JWT
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
function uploadPage(msg = '', authed = false) {
    const custom = findCustomLogo();
    const ts = Date.now();

    // Kalau sudah login GenieACS: tidak perlu isi token manual
    const tokenField = authed
        ? `<input type="hidden" name="token" value="__genie_session__">`
        : `<label>🔑 Token Admin</label>
           <input type="password" name="token" placeholder="Masukkan token admin" required autocomplete="new-password">`;

    const resetTokenField = authed
        ? `<input type="hidden" name="token" value="__genie_session__">`
        : `<label>🔑 Token Admin</label>
           <input type="password" name="token" placeholder="Token admin" required autocomplete="new-password">`;

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
const NAV_INJECT = `
<style>
/* ── Modal backdrop ── */
#rf-modal-backdrop{
  display:none;position:fixed;inset:0;z-index:99998;
  background:rgba(0,0,0,.45);
  align-items:center;justify-content:center;
}
#rf-modal-backdrop.open{display:flex}

/* ── Modal box — ikuti style GenieACS (beige header) ── */
#rf-modal{
  background:#fff;border-radius:4px;
  box-shadow:0 4px 24px rgba(0,0,0,.25);
  width:400px;max-width:94vw;
  font-family:Arial,sans-serif;font-size:14px;
  overflow:hidden;
}
#rf-modal-head{
  background:#d4c89a;padding:10px 16px;
  display:flex;align-items:center;justify-content:space-between;
  border-bottom:1px solid #b8ae82;
}
#rf-modal-head h3{margin:0;font-size:15px;color:#333;font-weight:bold}
#rf-modal-close{
  background:none;border:none;font-size:20px;cursor:pointer;
  color:#555;line-height:1;padding:0 4px;
}
#rf-modal-close:hover{color:#000}
#rf-modal-body{padding:18px}

/* Preview logo */
#rf-preview-wrap{
  text-align:center;border:1px solid #e0e0e0;
  border-radius:4px;padding:10px;margin-bottom:14px;
  background:#fafafa;min-height:60px;
  display:flex;align-items:center;justify-content:center;
}
#rf-preview-wrap img{max-height:60px;max-width:100%;object-fit:contain}
#rf-preview-wrap span{color:#aaa;font-size:13px}

/* File input area */
#rf-file-area{
  border:2px dashed #c8c0a0;border-radius:4px;
  padding:12px;text-align:center;cursor:pointer;
  transition:border-color .2s;margin-bottom:12px;
  background:#fffdf5;
}
#rf-file-area:hover,#rf-file-area.drag{border-color:#8a7d50}
#rf-file-area input{display:none}
#rf-file-area label{cursor:pointer;color:#555;font-size:13px}
#rf-file-name{font-size:12px;color:#888;margin-top:4px}

/* Buttons */
#rf-modal-body .rf-btn{
  display:inline-block;padding:7px 18px;border:none;
  border-radius:3px;cursor:pointer;font-size:13px;
  font-weight:bold;transition:opacity .15s;
}
#rf-modal-body .rf-btn:hover{opacity:.85}
.rf-btn-primary{background:#5a8a2a;color:#fff}
.rf-btn-danger{background:#c0392b;color:#fff;font-size:12px;padding:5px 12px}
.rf-btn-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}

/* Status message */
#rf-msg{
  padding:7px 10px;border-radius:3px;margin-bottom:10px;
  font-size:13px;display:none;
}
#rf-msg.ok{background:#dff0d8;color:#2d6a0f;border:1px solid #b8dca0;display:block}
#rf-msg.er{background:#f2dede;color:#8b1a1a;border:1px solid #e0b0b0;display:block}

/* Nav link */
#rf-nav-btn{
  color:inherit;text-decoration:none;
  padding:0 10px;font-size:inherit;
  cursor:pointer;background:none;border:none;
}
#rf-nav-btn:hover{text-decoration:underline}
</style>

<!-- Modal HTML -->
<div id="rf-modal-backdrop">
  <div id="rf-modal">
    <div id="rf-modal-head">
      <h3>&#128444; Upload Logo</h3>
      <button id="rf-modal-close" title="Tutup">&times;</button>
    </div>
    <div id="rf-modal-body">
      <div id="rf-msg"></div>
      <div id="rf-preview-wrap">
        <span>Memuat logo...</span>
      </div>
      <div id="rf-file-area">
        <input type="file" id="rf-file-input" accept=".svg,.png,.jpg,.jpeg,.gif,.webp,.ico,.bmp">
        <label for="rf-file-input">&#128194; Klik atau drag file ke sini</label>
        <div id="rf-file-name">SVG / PNG / JPG / GIF / WebP &mdash; maks 2 MB</div>
      </div>
      <div class="rf-btn-row">
        <button class="rf-btn rf-btn-primary" id="rf-upload-btn">&#8679; Upload Logo</button>
        <button class="rf-btn rf-btn-danger" id="rf-reset-btn">&#128465; Reset Default</button>
      </div>
    </div>
  </div>
</div>

<script>
(function(){
  var ADMIN = '/__admin/logo';

  /* ── Inject nav button ── */
  function injectNav(){
    if(document.getElementById('rf-nav-btn')) return;
    var btn = document.createElement('button');
    btn.id = 'rf-nav-btn';
    btn.title = 'Upload Logo';
    btn.innerHTML = '&#128444; Logo';
    btn.onclick = openModal;

    var logout = Array.from(document.querySelectorAll('a')).find(function(a){
      return a.textContent.trim().toLowerCase()==='log out';
    });
    if(logout && logout.parentNode){
      var sep = document.createTextNode(' | ');
      logout.parentNode.insertBefore(sep, logout);
      logout.parentNode.insertBefore(btn, sep);
      return;
    }
    var nav = document.querySelector('nav');
    if(nav){ nav.appendChild(btn); return; }
    btn.style.cssText='position:fixed;top:8px;right:90px;z-index:9999;'+
      'background:#5a8a2a;color:#fff;padding:3px 12px;border-radius:12px;font-size:12px;';
    document.body && document.body.appendChild(btn);
  }

  /* ── Modal open/close ── */
  function openModal(){
    document.getElementById('rf-modal-backdrop').classList.add('open');
    loadPreview();
    clearMsg();
  }
  function closeModal(){
    document.getElementById('rf-modal-backdrop').classList.remove('open');
    document.getElementById('rf-file-input').value='';
    document.getElementById('rf-file-name').textContent='SVG / PNG / JPG / GIF / WebP \\u2014 maks 2 MB';
    clearMsg();
  }

  /* ── Preview ── */
  function loadPreview(){
    var wrap = document.getElementById('rf-preview-wrap');
    var img = document.createElement('img');
    img.src = ADMIN+'/preview?t='+Date.now();
    img.alt = 'Logo aktif';
    img.onerror = function(){ wrap.innerHTML='<span>Logo default GenieACS</span>'; };
    img.onload  = function(){ wrap.innerHTML=''; wrap.appendChild(img); };
  }

  /* ── Message ── */
  function showMsg(type, text){
    var el = document.getElementById('rf-msg');
    el.className = type; el.textContent = text;
  }
  function clearMsg(){
    var el = document.getElementById('rf-msg');
    el.className=''; el.textContent=''; el.style.display='none';
  }

  /* ── Upload via fetch ── */
  function doUpload(){
    var fileInput = document.getElementById('rf-file-input');
    var file = fileInput.files[0];
    if(!file){ showMsg('er','Pilih file terlebih dahulu.'); return; }
    if(file.size > 2*1024*1024){ showMsg('er','File terlalu besar (maks 2 MB).'); return; }

    var btn = document.getElementById('rf-upload-btn');
    btn.disabled = true; btn.textContent = 'Mengupload...';

    var fd = new FormData();
    fd.append('logo', file);
    fd.append('token', '__genie_session__');

    fetch(ADMIN+'/upload', { method:'POST', body:fd, credentials:'include' })
      .then(function(r){ return r.text(); })
      .then(function(html){
        var ok = html.indexOf('berhasil') >= 0 || html.indexOf('Logo berhasil') >= 0;
        if(ok){
          showMsg('ok','\\u2705 Logo berhasil diupload! Refresh halaman untuk melihat perubahan.');
          loadPreview();
          // Auto refresh logo di halaman utama tanpa full reload
          var logoImgs = document.querySelectorAll('img[src*="logo"]');
          logoImgs.forEach(function(img){
            var s=img.src; img.src=''; img.src=s+'?t='+Date.now();
          });
        } else {
          showMsg('er','\\u274C Gagal upload. Coba lagi.');
        }
      })
      .catch(function(){ showMsg('er','\\u274C Error koneksi.'); })
      .finally(function(){
        btn.disabled=false; btn.innerHTML='&#8679; Upload Logo';
      });
  }

  /* ── Reset via fetch ── */
  function doReset(){
    if(!confirm('Reset logo ke default GenieACS?')) return;
    fetch(ADMIN+'/reset', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'token=__genie_session__'
    })
    .then(function(r){ return r.text(); })
    .then(function(html){
      var ok = html.indexOf('direset') >= 0 || html.indexOf('default') >= 0;
      showMsg(ok?'ok':'er', ok?'\\u2705 Logo direset ke default.':'\\u274C Gagal reset.');
      if(ok) loadPreview();
    })
    .catch(function(){ showMsg('er','\\u274C Error koneksi.'); });
  }

  /* ── Event listeners ── */
  function setup(){
    document.getElementById('rf-modal-close').onclick = closeModal;
    document.getElementById('rf-modal-backdrop').onclick = function(e){
      if(e.target===this) closeModal();
    };
    document.getElementById('rf-upload-btn').onclick = doUpload;
    document.getElementById('rf-reset-btn').onclick  = doReset;

    // Drag & drop
    var area = document.getElementById('rf-file-area');
    area.addEventListener('dragover', function(e){ e.preventDefault(); area.classList.add('drag'); });
    area.addEventListener('dragleave', function(){ area.classList.remove('drag'); });
    area.addEventListener('drop', function(e){
      e.preventDefault(); area.classList.remove('drag');
      var f = e.dataTransfer.files[0];
      if(f){ document.getElementById('rf-file-input').files;
        // Assign via DataTransfer
        var dt = new DataTransfer(); dt.items.add(f);
        document.getElementById('rf-file-input').files = dt.files;
        document.getElementById('rf-file-name').textContent = f.name+' ('+Math.round(f.size/1024)+' KB)';
      }
    });

    // File name display
    document.getElementById('rf-file-input').onchange = function(){
      var f = this.files[0];
      document.getElementById('rf-file-name').textContent = f
        ? f.name+' ('+Math.round(f.size/1024)+' KB)'
        : 'SVG / PNG / JPG / GIF / WebP \\u2014 maks 2 MB';
    };

    // Keyboard ESC close
    document.addEventListener('keydown', function(e){
      if(e.key==='Escape') closeModal();
    });
  }

  /* ── Init ── */
  function init(){
    setup();
    injectNav();
  }

  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded', init);
  } else { init(); }

  // SPA navigation
  var last = location.href;
  setInterval(function(){
    if(location.href!==last){ last=location.href; setTimeout(injectNav,400); }
  }, 500);

  // Handle direct URL /__admin/logo → redirect ke dashboard + buka modal
  if(location.pathname==='/__admin/logo'){
    history.replaceState(null,'','/');
    setTimeout(openModal, 600);
  }
})();
</script>`;

function injectNavLink(html) {
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

                // Inject link logo ke navbar GenieACS
                html = injectNavLink(html);

                // Bersihkan headers yang perlu diupdate
                const respHeaders = { ...pRes.headers };
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
        const authed = isGenieSession(req);
        if (!authed && !ADMIN_TOKEN) {
            // Tidak ada session & tidak ada token → minta login dulu
            sendSecure(res, 302, 'text/html; charset=utf-8', '');
            res.setHeader('Location', '/');
            res.end();
            return;
        }
        sendSecure(res, 200, 'text/html; charset=utf-8', uploadPage('', authed));
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
                const origExt = path.extname(file.filename || '').toLowerCase();
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

                // ── Terapkan langsung ke folder public GenieACS ──
                // Ini memastikan logo berubah langsung tanpa tergantung proxy intercept
                applyLogoToApp(savePath);

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
            const tok       = tokM ? decodeURIComponent(tokM[1]) : '';
            const bySession = tok === '__genie_session__' && isGenieSession(req);
            const byToken   = !bySession && safeTokenCheck(tok);
            const authed    = isGenieSession(req);

            if (!bySession && !byToken) {
                recordFail(ip, 'Token salah saat reset');
                sendSecure(res, 403, 'text/html; charset=utf-8',
                    uploadPage('<div class="msg er">❌ Akses ditolak.</div>', authed));
                return;
            }

            deleteAllLogo();
            restoreOriginalLogos();
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
