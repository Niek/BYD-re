#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const INPUT_SO = path.join(ROOT, 'byd', 'libencrypt.so.mem.so');
const OUTPUT_JS = path.join(ROOT, 'bangcle_auth_tables.js');
const IMAGE_BASE = 0x100000;

const TABLES = Object.freeze({
  invRound: { vaddr: 0x24c510, length: 0x28000 },
  invXor: { vaddr: 0x210510, length: 0x3c000 },
  invFirst: { vaddr: 0x20f510, length: 0x1000 },
  round: { vaddr: 0x2b1510, length: 0x28000 },
  xor: { vaddr: 0x274510, length: 0x3c000 },
  final: { vaddr: 0x2b0510, length: 0x1000 },
  permDecrypt: { vaddr: 0x31011, length: 8 },
  permEncrypt: { vaddr: 0x31010, length: 8 },
});

function parseLoadSegments(buffer) {
  if (buffer.toString('ascii', 0, 4) !== '\x7fELF') {
    throw new Error('Input is not an ELF file');
  }
  const phOff = Number(buffer.readBigUInt64LE(0x20));
  const phEntSize = buffer.readUInt16LE(0x36);
  const phNum = buffer.readUInt16LE(0x38);
  if (!phOff || !phEntSize || !phNum) {
    throw new Error('Invalid ELF program headers');
  }

  const segments = [];
  for (let i = 0; i < phNum; i += 1) {
    const off = phOff + (i * phEntSize);
    if (off + phEntSize > buffer.length) {
      break;
    }
    const pType = buffer.readUInt32LE(off);
    if (pType !== 1) {
      continue;
    }
    const pOffset = Number(buffer.readBigUInt64LE(off + 0x08));
    const pVaddr = Number(buffer.readBigUInt64LE(off + 0x10));
    const pFileSz = Number(buffer.readBigUInt64LE(off + 0x20));
    if (pFileSz <= 0) {
      continue;
    }
    segments.push({ offset: pOffset, vaddr: pVaddr, filesz: pFileSz });
  }
  return segments;
}

function mapVaddrToFileOffset(vaddr, segments) {
  for (const candidate of [vaddr, vaddr - IMAGE_BASE]) {
    for (const segment of segments) {
      if (candidate >= segment.vaddr && candidate < segment.vaddr + segment.filesz) {
        return segment.offset + (candidate - segment.vaddr);
      }
    }
  }
  throw new Error(`Unable to map vaddr 0x${vaddr.toString(16)}`);
}

function main() {
  const so = fs.readFileSync(INPUT_SO);
  const segments = parseLoadSegments(so);

  const out = {};
  for (const [name, spec] of Object.entries(TABLES)) {
    const off = mapVaddrToFileOffset(spec.vaddr, segments);
    const end = off + spec.length;
    if (end > so.length) {
      throw new Error(`${name} out of range (off=0x${off.toString(16)} len=0x${spec.length.toString(16)})`);
    }
    out[name] = so.subarray(off, end).toString('base64');
  }

  const header = [
    '/**',
    ' * Generated file: embedded Bangcle auth1 table slices for bangcle.js.',
    ' *',
    ' * Generation command:',
    ' *   node scripts/generate_bangcle_auth_tables.js',
    ' *',
    ' * Source binary:',
    ' *   byd/libencrypt.so.mem.so',
    ' *',
    ' * Extracted auth1 virtual addresses:',
    ' *   invRound=0x24c510 len=0x28000',
    ' *   invXor=0x210510 len=0x3c000',
    ' *   invFirst=0x20f510 len=0x1000',
    ' *   round=0x2b1510 len=0x28000',
    ' *   xor=0x274510 len=0x3c000',
    ' *   final=0x2b0510 len=0x1000',
    ' *   permDecrypt=0x31011 len=8',
    ' *   permEncrypt=0x31010 len=8',
    ' */',
    '\'use strict\';',
    '',
  ].join('\n');

  const body = `module.exports = Object.freeze(${JSON.stringify(out, null, 2)});\n`;
  fs.writeFileSync(OUTPUT_JS, header + body, 'utf8');
  console.log(`Wrote ${OUTPUT_JS}`);
}

main();
