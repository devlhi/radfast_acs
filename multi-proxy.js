#!/usr/bin/env node
'use strict';

/**
 * multi-proxy.js — menjalankan banyak instance logo-proxy.js dalam 1 proses Node.js.
 *
 * Cara kerja:
 * - Baca /opt/genieacs-instances/.registry
 * - Baca .env tiap instance untuk port, internal UI, logo, token, JWT secret
 * - Jalankan logo-proxy.js berkali-kali di VM context terpisah dalam proses yang sama
 * - Tiap context punya singleton sendiri: CSRF, rate-limit, logo cache, cookie prefix, server
 *
 * Ini menjaga kompatibilitas 100% dengan logo-proxy.js lama tanpa refactor besar.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const Module = require('module');

const SCRIPT = process.env.RADFAST_PROXY_SCRIPT || path.join(__dirname, 'logo-proxy.js');
const INSTANCES_DIR = process.env.RADFAST_INSTANCES_DIR || '/opt/genieacs-instances';
const REGISTRY = process.env.RADFAST_REGISTRY || path.join(INSTANCES_DIR, '.registry');

function parseEnvFile(file) {
  const env = {};
  if (!fs.existsSync(file)) return env;
  const text = fs.readFileSync(file, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s || s.startsWith('#')) continue;
    const m = s.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    env[m[1]] = v;
  }
  return env;
}

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

function loadInstances() {
  if (!fs.existsSync(REGISTRY)) throw new Error(`Registry tidak ditemukan: ${REGISTRY}`);
  const lines = fs.readFileSync(REGISTRY, 'utf8').split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith('#'));
  const instances = [];
  for (const line of lines) {
    const r = parseRegistryLine(line);
    if (!r || !r.name) continue;
    const instDir = path.join(INSTANCES_DIR, r.name);
    const env = parseEnvFile(path.join(instDir, '.env'));
    const merged = {
      ...process.env,
      ...env,
      RADFAST_MULTI_CHILD: '1',
      RADFAST_INSTANCE_NAME: r.name,
      RADFAST_PROXY_PORT: env.RADFAST_PROXY_PORT || r.UI,
      RADFAST_UI_INTERNAL: env.RADFAST_UI_INTERNAL,
      RADFAST_LOGO_FILE: env.RADFAST_LOGO_FILE || path.join(instDir, 'logo', 'custom-logo'),
      RADFAST_ADMIN_TOKEN: env.RADFAST_ADMIN_TOKEN || '',
      GENIEACS_UI_JWT_SECRET: env.GENIEACS_UI_JWT_SECRET || ''
    };
    if (!merged.RADFAST_PROXY_PORT || !merged.RADFAST_UI_INTERNAL) {
      console.warn(`[multi-proxy] skip ${r.name}: RADFAST_PROXY_PORT/RADFAST_UI_INTERNAL kosong`);
      continue;
    }
    instances.push({ name: r.name, dir: instDir, env: merged });
  }
  return instances;
}

function runInstance(inst, code) {
  const localModule = new Module(SCRIPT, module.parent || module);
  localModule.filename = SCRIPT;
  localModule.paths = Module._nodeModulePaths(path.dirname(SCRIPT));

  const sandboxProcess = Object.create(process);
  sandboxProcess.env = { ...inst.env };
  sandboxProcess.argv = [process.execPath, SCRIPT];
  sandboxProcess.cwd = () => inst.dir;
  sandboxProcess.chdir = process.chdir.bind(process);

  const wrapped = Module.wrap(code);
  const script = new vm.Script(wrapped, { filename: SCRIPT, displayErrors: true });
  const context = vm.createContext({
    console,
    Buffer,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    setImmediate,
    clearImmediate,
    URL,
    URLSearchParams,
    process: sandboxProcess,
    global: null,
    globalThis: null,
    __filename: SCRIPT,
    __dirname: path.dirname(SCRIPT)
  });
  context.global = context;
  context.globalThis = context;

  const fn = script.runInContext(context);
  fn.call(localModule.exports, localModule.exports, localModule.require.bind(localModule), localModule, SCRIPT, path.dirname(SCRIPT));
}

function main() {
  const instances = loadInstances();
  if (!instances.length) throw new Error('Tidak ada instance valid di registry');
  const ports = new Set();
  for (const inst of instances) {
    const p = String(inst.env.RADFAST_PROXY_PORT);
    if (ports.has(p)) throw new Error(`Port duplikat: ${p}`);
    ports.add(p);
  }

  const code = fs.readFileSync(SCRIPT, 'utf8');
  console.log(`[multi-proxy] start ${instances.length} instance dalam 1 proses Node.js`);
  for (const inst of instances) {
    runInstance(inst, code);
  }
}

process.on('uncaughtException', err => {
  console.error('[multi-proxy] uncaught:', err && err.stack || err);
  process.exit(1);
});
process.on('unhandledRejection', err => {
  console.error('[multi-proxy] unhandled:', err && err.stack || err);
  process.exit(1);
});

main();
