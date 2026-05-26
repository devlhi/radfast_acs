/**
 * Simulasi fixVersion() — inline-flex COLUMN (logo atas, versi bawah)
 * Jalankan: node test-fix.js
 */
'use strict';
const { JSDOM } = require('jsdom');

// ── fungsi yang akan ditest (mirror persis dari logo-proxy.js) ──────────
function fixVersionFn(doc, img) {
    var par = img.parentElement; if (!par) return;
    // div.logo → inline-flex column: [logo] di atas, [versi] di bawah
    par.style.cssText = (par.getAttribute('style') || '') +
        ';display:inline-flex!important;flex-direction:column!important;' +
        'align-items:flex-start!important;justify-content:center!important;' +
        'vertical-align:middle!important;flex-wrap:nowrap!important;';
    var nodes = Array.prototype.slice.call(par.childNodes);
    for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        if (n === img) continue;
        if (n.nodeType === 1) {
            if (n.getAttribute('data-rf-v')) continue;
            if (/v\d+\.\d+/.test(n.textContent || '')) {
                n.setAttribute('data-rf-v', '1');
                par.insertBefore(n, img.nextSibling);
                n.style.cssText = 'position:static!important;display:block!important;' +
                    'font-size:0.6em!important;color:#888!important;' +
                    'margin:1px 0 0 0!important;white-space:nowrap!important;' +
                    'inset:auto!important;line-height:1.2!important;';
            }
        } else if (n.nodeType === 3) {
            if (!/v\d+\.\d+/.test(n.nodeValue || '')) continue;
            var sp = doc.createElement('span');
            sp.setAttribute('data-rf-v', '1');
            sp.style.cssText = 'position:static!important;display:block!important;' +
                'font-size:0.6em!important;color:#888!important;' +
                'margin:1px 0 0 0!important;white-space:nowrap!important;line-height:1.2!important;';
            sp.textContent = n.nodeValue.trim();
            par.removeChild(n);
            par.insertBefore(sp, img.nextSibling);
        }
    }
}
// ────────────────────────────────────────────────────────────────────────

function runTest(name, html, expectVersionAfterImg) {
    const dom = new JSDOM(`<body>${html}</body>`);
    const doc = dom.window.document;
    const img = doc.querySelector('img');
    const par = img.parentElement;

    fixVersionFn(doc, img);

    // Cek 1: versi ada SETELAH img?
    const verEl = par.querySelector('[data-rf-v]');
    const imgIdx = Array.from(par.childNodes).indexOf(img);
    const verIdx = verEl ? Array.from(par.childNodes).indexOf(verEl) : -1;
    const verAfterImg = verIdx > imgIdx;

    // Cek 2: parent inline-flex column?
    const parStyle = par.getAttribute('style') || '';
    const hasFlex = /inline-flex/.test(parStyle) && /column/.test(parStyle);

    // Cek 3: versi display:block?
    const verStyle = verEl ? (verEl.getAttribute('style') || '') : '';
    const hasBlock = /display\s*:\s*block/.test(verStyle);

    const verText = verEl ? verEl.textContent.trim() : '(tidak ditemukan)';
    const pass = verAfterImg === expectVersionAfterImg && !!verEl && hasFlex && hasBlock;
    const mark = pass ? '✅ PASS' : '❌ FAIL';

    console.log(`\n${mark} — ${name}`);
    console.log(`  Versi teks   : "${verText}"`);
    console.log(`  Posisi versi : index ${verIdx} (img di index ${imgIdx}) → ${verAfterImg ? 'SETELAH' : 'SEBELUM'} img`);
    console.log(`  Parent flex? : ${hasFlex ? 'YA (inline-flex column)' : 'TIDAK — ' + parStyle.substring(0,80)}`);
    console.log(`  Versi block? : ${hasBlock ? 'YA (display:block)' : 'TIDAK — ' + verStyle.substring(0,80)}`);
    console.log(`  DOM setelah  : ${par.innerHTML.replace(/\s+/g, ' ').trim().substring(0, 200)}`);
    return pass;
}

const results = [];

// Skenario A: GenieACS asli — span.version SEBELUM img (position:absolute di bottom-left)
results.push(runTest(
    'Skenario A: span.version sebelum img (GenieACS asli)',
    `<div class="logo"><span class="version" style="position:absolute;bottom:4px;left:8px;font-size:0.6em;color:#555;">v1.2.16+26032938e9</span><img src="/__admin/logo/preview?t=123"></div>`,
    true
));

// Skenario B: span setelah img
results.push(runTest(
    'Skenario B: span.version sesudah img',
    `<div class="logo"><img src="/__admin/logo/preview?t=123"><span class="version" style="position:absolute;">v1.2.16+26032938e9</span></div>`,
    true
));

// Skenario C: text node sebelum img
results.push(runTest(
    'Skenario C: text node versi sebelum img',
    `<div class="logo">v1.2.16+26032938e9<img src="/__admin/logo/preview?t=123"></div>`,
    true
));

// Skenario D: small sebelum img
results.push(runTest(
    'Skenario D: <small> sebelum img',
    `<div class="logo"><small style="position:absolute;top:0;right:0;">v1.2.16+26032938e9</small><img src="/__admin/logo/preview?t=123"></div>`,
    true
));

// Skenario E: parent sudah punya style (style tidak hilang)
results.push(runTest(
    'Skenario E: parent sudah punya style (tidak hilang)',
    `<div class="logo" style="float:left;padding:4px;"><span class="version" style="position:absolute;">v1.2.16+26032938e9</span><img src="/__admin/logo/preview?t=123"></div>`,
    true
));

// ── Test idempoten ────────────────────────────────────────────────────────
{
    const dom2 = new JSDOM(`<body><div class="logo"><span class="version" style="position:absolute;">v1.2.16+test</span><img src="/logo"></div></body>`);
    const doc2 = dom2.window.document;
    const img2 = doc2.querySelector('img');

    fixVersionFn(doc2, img2);
    const html1 = img2.parentElement.innerHTML;
    fixVersionFn(doc2, img2);
    const html2 = img2.parentElement.innerHTML;
    const idem = html1 === html2;
    results.push(idem);
    console.log(`\n${idem ? '✅ PASS' : '❌ FAIL'} — Test idempoten (2x run = hasil sama)`);
    if (!idem) {
        console.log('  Run1:', html1);
        console.log('  Run2:', html2);
    }
}

// ── Ringkasan ─────────────────────────────────────────────────────────────
const allPass = results.every(r => r === true);
console.log(`\n${'═'.repeat(55)}`);
console.log(allPass
    ? '✅ SEMUA TEST PASS — aman di-push ke VPS'
    : '❌ ADA TEST GAGAL — periksa dulu sebelum push');
