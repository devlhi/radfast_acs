#!/usr/bin/env node
/* ============================================================
 *  RadFast ACS — Fallback BSON importer
 *  Dipakai add-instance.sh kalau `mongorestore` tidak tersedia.
 *  Membaca dump mongodump (*.bson) dari sebuah folder lalu
 *  meng-import-nya ke database tujuan (drop dulu tiap koleksi).
 *
 *  Usage:
 *    node import-bson.js <confDir> <dbName> [mongoUri]
 *
 *  Contoh:
 *    node import-bson.js /opt/genieacs-app/conf-acs genieacs_budi \
 *         mongodb://127.0.0.1:27017
 *
 *  Catatan: script ini WAJIB dijalankan dengan node yang punya akses
 *  ke node_modules milik genieacs-app (mongodb + bson). add-instance.sh
 *  menjalankannya dari dalam $APP_DIR sehingga require() ketemu.
 * ============================================================ */
'use strict'

const fs = require('fs')
const path = require('path')

function die(msg, code = 1) {
  process.stderr.write(`[import-bson] ERROR: ${msg}\n`)
  process.exit(code)
}

const confDir = process.argv[2]
const dbName = process.argv[3]
const mongoUri = process.argv[4] || process.env.MONGO_URI || 'mongodb://127.0.0.1:27017'

if (!confDir || !dbName) {
  die('Usage: node import-bson.js <confDir> <dbName> [mongoUri]')
}
if (!fs.existsSync(confDir) || !fs.statSync(confDir).isDirectory()) {
  die(`confDir tidak ditemukan / bukan folder: ${confDir}`)
}
if (!/^[a-zA-Z0-9_]+$/.test(dbName)) {
  die(`Nama database tidak valid: ${dbName}`)
}

let MongoClient
let BSON
try {
  ;({ MongoClient } = require('mongodb'))
  BSON = require('bson')
} catch (e) {
  die(
    'Dependency "mongodb"/"bson" tidak ditemukan. Jalankan dari folder ' +
      'genieacs-app (yang punya node_modules), atau install dulu. Detail: ' +
      e.message,
  )
}

// Decode satu file .bson (rangkaian dokumen BSON yang di-concat) → array dokumen.
// Tiap dokumen diawali 4 byte little-endian panjang totalnya (termasuk 4 byte itu).
function readBsonDocs(filePath) {
  const buf = fs.readFileSync(filePath)
  const docs = []
  let offset = 0
  while (offset < buf.length) {
    if (offset + 4 > buf.length) {
      throw new Error(`BSON rusak (header terpotong) di ${path.basename(filePath)} offset ${offset}`)
    }
    const size = buf.readInt32LE(offset)
    if (size < 5 || offset + size > buf.length) {
      throw new Error(`BSON rusak (ukuran tidak valid: ${size}) di ${path.basename(filePath)} offset ${offset}`)
    }
    const slice = buf.subarray(offset, offset + size)
    docs.push(BSON.deserialize(slice))
    offset += size
  }
  return docs
}

async function main() {
  const bsonFiles = fs
    .readdirSync(confDir)
    .filter(f => f.endsWith('.bson'))
    .sort()

  if (bsonFiles.length === 0) {
    die(`Tidak ada file .bson di ${confDir}`)
  }

  const client = new MongoClient(mongoUri, {
    serverSelectionTimeoutMS: 15000,
  })

  await client.connect()
  try {
    const db = client.db(dbName)
    let totalDocs = 0

    for (const file of bsonFiles) {
      const collName = path.basename(file, '.bson')
      const docs = readBsonDocs(path.join(confDir, file))

      const coll = db.collection(collName)
      // --drop: kosongkan koleksi dulu agar idempotent (mirip mongorestore --drop)
      try {
        await coll.drop()
      } catch (e) {
        // ns not found = koleksi belum ada, aman diabaikan
        if (!/ns not found/i.test(e.message || '')) throw e
      }

      if (docs.length > 0) {
        await coll.insertMany(docs, { ordered: false })
      }
      totalDocs += docs.length
      process.stdout.write(`[import-bson] ${collName}: ${docs.length} dokumen\n`)
    }

    process.stdout.write(
      `[import-bson] SELESAI → db "${dbName}" (${bsonFiles.length} koleksi, ${totalDocs} dokumen)\n`,
    )
  } finally {
    await client.close()
  }
}

main().catch(e => die(e.message || String(e)))
