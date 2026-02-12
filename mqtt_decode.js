#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const readline = require('readline');

function decodePayload(hexText, key) {
  const cleaned = String(hexText || '').replace(/\s+/g, '').trim();
  if (!cleaned) {
    return null;
  }
  if ((cleaned.length & 1) !== 0) {
    throw new Error(`odd hex len ${cleaned.length}`);
  }
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
    throw new Error('payload is not hex');
  }

  const ciphertext = Buffer.from(cleaned, 'hex');
  const iv = Buffer.alloc(16, 0);
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain;
}

function main() {
  const argv = process.argv.slice(2);
  const keyHex = String(argv[0] || '').trim();
  if (!/^[0-9a-fA-F]{32}$/.test(keyHex)) {
    console.error([
      'Usage:',
      '  node mqtt_decode.js <32-hex-key>',
    ].join('\n'));
    process.exit(2);
  }

  const key = Buffer.from(keyHex, 'hex');

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on('line', (line) => {
    try {
      const decoded = decodePayload(line, key);
      if (!decoded) {
        return;
      }
      process.stdout.write(decoded.toString('utf8').trimEnd() + '\n');
    } catch (err) {
      console.error(`[mqtt-decode] ${err.message || String(err)}`);
      process.exitCode = 1;
    }
  });
}

main();
