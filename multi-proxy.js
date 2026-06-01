#!/usr/bin/env node
'use strict';

/**
 * multi-proxy.js — single-process runner untuk semua instance logo-proxy.js
 *
 * Strategi:
 * - Baca /opt/genieacs-instances/.registry + .env tiap instance
 * - Jalankan logo-proxy.js per-instance pakai Module.wrap + vm.runInThisContext
 * - process.env di-swap sementara tiap run → logo-proxy.js baca config beda
 * - Tiap run punya local scope sendiri (csrfStore, ipData, logoCache, server, dll)
 * - Built-in modules (http, fs, crypto) di-share aman (stateless)
 * - logo-proxy.js TIDAK perlu diubah — 100% backward compatible
 */

const fs     = require('fs');
const path   = require('path');
const vm     = require('vm');
const Module = require('module');
const { createRequire } = require('module');

const SCRIPT        = process.env.RADFAST_PROXY_SCRIPT   || path.join(__dirname, 'logo-proxy.js');
const INSTANCES_DIR = process.env.RADFAST_INSTANCES_DIR  || '/opt/genieacs-instances';
const REGISTRY      = process.env.RADFAST_REGISTRY       || path.join(INSTANCES_DIR, '.registry');

// ── Parse .env → object ───────────────────────────────────
function parseEnvFile(file) {
  const env = {};
  if (!fs.existsSync(file)) return env;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith('#')) continue;
    const m = s.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))
      v = v.slice(1, -1);
    env[m[1]] = v;
  }
  return env;
}

// ── Parse .registry line ──────────────────────────────────
// Format: username UI=3001 CWMP=7548 NBI=7558 FS=7568 DB=name IP=x DATE=...
function parseRegistryLine(line) {
  const parts = line.trim().split(/\s+/);
  if (!parts[0]) return null;
  const obj = { name: parts[0] };
  for (const p of parts.slice(1)) {
    const i = p.indexOf('=');
    if (i > 0) obj[p.slice(0, i)] = p.slice(i + 1);
  }
  return obj;
}

// ── Load semua instance dari registry + .env ──────────────
function loadInstances() {
  if (!fs.existsSync(REGISTRY)) {
    console.warn(`[multi-proxy] Registry tidak ada: ${REGISTRY}`);
    return [];
  }
  const lines = fs.readFileSync(REGISTRY, 'utf8')
    .split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith('#'));
  const instances = [];

  for (const line of lines) {
    const r = parseRegistryLine(line);
    if (!r || !r.name) continue;

    const instDir  = path.join(INSTANCES_DIR, r.name);
    const envConf  = parseEnvFile(path.join(instDir, '.env'));
    const logoDir  = path.join(instDir, 'logo');
    const logoFile = path.join(logoDir, 'custom-logo');

    const merged = {
      RADFAST_MULTI_PROXY       : '1',
      RADFAST_PROXY_PORT        : envConf.RADFAST_PROXY_PORT        || r.UI,
      RADFAST_UI_INTERNAL       : envConf.RADFAST_UI_INTERNAL,
      RADFAST_LOGO_FILE         : envConf.RADFAST_LOGO_FILE         || logoFile,
      RADFAST_ADMIN_TOKEN       : envConf.RADFAST_ADMIN_TOKEN       || '',
      // RadFast Admin (backend VPN) — sumber data status VPN ONT (server-to-server)
      RADFAST_ADMIN_URL         : envConf.RADFAST_ADMIN_URL         || process.env.RADFAST_ADMIN_URL     || '',
      RADFAST_ADMIN_API_KEY     : envConf.RADFAST_ADMIN_API_KEY     || process.env.RADFAST_ADMIN_API_KEY || '',
      // Nama instance ini → filter status VPN agar tiap dashboard lihat miliknya saja
      RADFAST_INSTANCE_NAME     : envConf.RADFAST_INSTANCE_NAME     || r.name || '',
      GENIEACS_UI_JWT_SECRET    : envConf.GENIEACS_UI_JWT_SECRET    || '',
      GENIEACS_MONGODB_CONNECTION_URL: envConf.GENIEACS_MONGODB_CONNECTION_URL || '',
      // NBI gate config — wajib di-pass agar proxy tahu port NBI & secret path
      GENIEACS_NBI_PORT         : envConf.GENIEACS_NBI_PORT         || '',
      RADFAST_NBI_GATE_PATH     : envConf.RADFAST_NBI_GATE_PATH     || '',
      RADFAST_NBI_GATE_MAX_CHANGES: envConf.RADFAST_NBI_GATE_MAX_CHANGES || '',
      // Port publik khusus NBI (opsional) — endpoint REST API terpisah dari dashboard
      RADFAST_NBI_PROXY_PORT    : envConf.RADFAST_NBI_PROXY_PORT    || '',
    };

    if (!merged.RADFAST_PROXY_PORT || !merged.RADFAST_UI_INTERNAL) {
      console.warn(`[multi-proxy] skip "${r.name}": port/internal kosong`);
      continue;
    }

    try { fs.mkdirSync(logoDir, { recursive: true }); } catch (_) {}

    instances.push({
      name: r.name,
      dir: instDir,
      port: parseInt(String(merged.RADFAST_PROXY_PORT)),
      geniePort: parseInt(String(merged.RADFAST_UI_INTERNAL)),
      env: merged,
    });
  }
  return instances;
}

// ── Jalankan 1 instance logo-proxy.js ─────────────────────
function runInstance(instance) {
  const { name, dir, env } = instance;

  // Simpan & swap process.env
  const origEnv = { ...process.env };
  try {
    process.env = { ...origEnv, ...env };

    // Baca fresh — tiap instance punya closure sendiri
    let code       = fs.readFileSync(SCRIPT, 'utf8');
    const filename = SCRIPT;

    // Strip shebang (#!/usr/bin/env node) — Module.wrap tidak handle ini,
    // hanya valid saat Node load file langsung. Ganti jadi baris kosong
    // agar nomor baris di stack trace tetap akurat.
    if (code.charCodeAt(0) === 0x23 && code.charCodeAt(1) === 0x21) {
      const nl = code.indexOf('\n');
      code = (nl >= 0) ? code.slice(nl) : '';
    }

    // Module.wrap → (function(exports, require, module, __filename, __dirname) { ... })
    // vm.runInThisContext → compile di Node.js utama → require('http') etc tetap jalan
    const wrapped    = Module.wrap(code);
    const compiledFn = vm.runInThisContext(wrapped, {
      filename,
      lineOffset: 0,
      displayErrors: true,
    });

    if (typeof compiledFn !== 'function') {
      throw new Error(`Compiled to ${typeof compiledFn}, expected function`);
    }

    // Module object sendiri untuk instance ini
    const mod = {
      id: filename,
      filename,
      loaded: false,
      parent: null,
      children: [],
      exports: {},
      paths: Module._nodeModulePaths(dir),
    };

    // require per-instance — resolve built-in modules naturally
    const instanceRequire = createRequire(filename);

    // Jalankan → csrfStore, ipData, _logoMemCache, server.listen semua lokal
    compiledFn.call(mod.exports, mod.exports, instanceRequire, mod, filename, dir);
    mod.loaded = true;

  } catch (err) {
    console.error(`[multi-proxy] ✗ "${name}" error:`, err.stack || err.message);
  } finally {
    process.env = origEnv; // selalu restore
  }
}

// ── MAIN ──────────────────────────────────────────────────
function main() {
  console.log(`[multi-proxy] script     : ${SCRIPT}`);
  console.log(`[multi-proxy] registry   : ${REGISTRY}`);

  const instances = loadInstances();
  if (!instances.length) {
    console.log('[multi-proxy] Tidak ada instance. Jalankan logo-proxy.js langsung untuk single mode.');
    return;
  }

  // Cek port duplikat
  const portMap = new Map();
  for (const inst of instances) {
    const key = String(inst.port);
    if (portMap.has(key)) {
      console.error(`[multi-proxy] Port duplikat: :${key} = "${inst.name}" & "${portMap.get(key)}"`);
      process.exit(1);
    }
    portMap.set(key, inst.name);
  }

  console.log(`[multi-proxy] Start ${instances.length} instance dalam 1 proses Node.js:`);
  for (const inst of instances) {
    console.log(`  • ${inst.name}  :${inst.port} → :${inst.geniePort}`);
  }
  console.log('');

  for (const inst of instances) {
    runInstance(inst);
  }

  console.log(`\n[multi-proxy] ✓ Selesai. ${instances.length} servers aktif dalam 1 process.`);
}

// ── Global error handlers ─────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error('[multi-proxy] Uncaught:', err.stack || err);
  // Jangan exit — instance lain mungkin masih jalan
});
process.on('unhandledRejection', (reason) => {
  console.error('[multi-proxy] Unhandled:', reason);
});

main();
