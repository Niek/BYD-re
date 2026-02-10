'use strict';

// Generated from byd/libencrypt.so.mem.so via scripts/generate_bangcle_auth_tables.js.
const encodedAuthTables = require('./bangcle_auth_tables');

function decodeTable(name, expectedLength) {
  const base64 = encodedAuthTables[name];
  if (typeof base64 !== 'string' || !base64.length) {
    throw new Error(`Missing embedded auth table: ${name}`);
  }
  const table = Buffer.from(base64, 'base64');
  if (table.length !== expectedLength) {
    throw new Error(`Embedded auth table ${name} has unexpected size ${table.length} (expected ${expectedLength})`);
  }
  return table;
}

const AUTH_TABLES = Object.freeze({
  invRound: decodeTable('invRound', 0x28000),
  invXor: decodeTable('invXor', 0x3c000),
  invFirst: decodeTable('invFirst', 0x1000),
  round: decodeTable('round', 0x28000),
  xor: decodeTable('xor', 0x3c000),
  final: decodeTable('final', 0x1000),
  permDecrypt: decodeTable('permDecrypt', 8),
  permEncrypt: decodeTable('permEncrypt', 8),
});

function prepareAESMatrix(input, output) {
  for (let col = 0; col < 4; col += 1) {
    for (let row = 0; row < 4; row += 1) {
      output[col * 8 + row] = input[col + row * 4];
    }
  }
}

function decryptBlockAuth(block, round = 1, scratch = {}) {
  const tables = AUTH_TABLES;
  const param3 = (typeof round === 'number' && Number.isFinite(round)) ? round : 1;

  const state = scratch.state32 || new Uint8Array(32);
  scratch.state32 = state;
  const temp64 = scratch.temp64 || Buffer.alloc(64);
  scratch.temp64 = temp64;
  const tmp32 = scratch.tmp32 || new Uint8Array(32);
  scratch.tmp32 = tmp32;
  const output = scratch.out || new Uint8Array(16);
  scratch.out = output;

  prepareAESMatrix(block, state);

  for (let round = 9; round >= Math.max(1, param3); round -= 1) {
    const lVar20 = round;
    const lVar21 = lVar20 * 4;
    let permPtr = 0;

    for (let i = 0; i < 4; i += 1) {
      const bVar3 = tables.permDecrypt[permPtr];
      const lVar9 = i;
      const lVar16 = lVar9 * 8;
      const base = i * 16;

      for (let j = 0; j < 4; j += 1) {
        const uVar7 = (bVar3 + j) & 3;
        const byteVal = state[lVar16 + uVar7];
        const idx = byteVal + (lVar9 + (lVar21 + uVar7) * 4) * 256;
        const value = tables.invRound.readUInt32LE(idx * 4);
        temp64.writeUInt32LE(value, base + j * 4);
      }
      permPtr += 2;
    }

    let iVar15 = 1;
    for (let lVar21Xor = 0; lVar21Xor < 4; lVar21Xor += 1) {
      let pbVar18Offset = lVar21Xor;

      for (let lVar9Xor = 0; lVar9Xor < 4; lVar9Xor += 1) {
        const local10 = temp64[pbVar18Offset];
        let uVar6 = local10 & 0xf;
        let uVar26 = local10 & 0xf0;

        const localF0 = temp64[pbVar18Offset + 0x10];
        const localF1 = temp64[pbVar18Offset + 0x20];
        const localF2 = temp64[pbVar18Offset + 0x30];

        const lVar2 = lVar9Xor * 0x18 + lVar20 * 0x60;
        let iVar25 = iVar15;

        for (let lVar16 = 0; lVar16 < 3; lVar16 += 1) {
          const bVar3 = lVar16 === 0 ? localF0 : (lVar16 === 1 ? localF1 : localF2);
          const uVar1 = (bVar3 << 4) & 0xff;
          const uVar27 = uVar6 | uVar1;
          uVar26 = (uVar26 >> 4) | ((bVar3 >> 4) << 4);

          const idx1 = (lVar2 + (iVar25 - 1)) * 0x100 + uVar27;
          uVar6 = tables.invXor[idx1] & 0xf;

          const idx2 = (lVar2 + iVar25) * 0x100 + uVar26;
          const bVar3New = tables.invXor[idx2];
          uVar26 = (bVar3New & 0xf) << 4;
          iVar25 += 2;
        }

        state[lVar9Xor + lVar21Xor * 8] = (uVar26 | uVar6) & 0xff;
        pbVar18Offset += 4;
      }
      iVar15 += 6;
    }
  }

  if (param3 === 1) {
    tmp32.set(state);
    let uVar8 = 1;
    let uVar10 = 3;
    let uVar12 = 2;

    for (let row = 0; row < 4; row += 1) {
      const idx0 = tmp32[row] + row * 0x400;
      state[row] = tables.invFirst[idx0];

      const row1 = uVar10 & 3;
      const idx1 = tmp32[8 + row1] + row1 * 0x400 + 0x100;
      state[8 + row] = tables.invFirst[idx1];

      const row2 = uVar12 & 3;
      const idx2 = tmp32[0x10 + row2] + row2 * 0x400 + 0x200;
      state[0x10 + row] = tables.invFirst[idx2];

      const row3 = uVar8 & 3;
      const idx3 = tmp32[0x18 + row3] + row3 * 0x400 + 0x300;
      state[0x18 + row] = tables.invFirst[idx3];

      uVar8 += 1;
      uVar10 += 1;
      uVar12 += 1;
    }
  }

  for (let col = 0; col < 4; col += 1) {
    for (let row = 0; row < 4; row += 1) {
      output[col + row * 4] = state[col * 8 + row];
    }
  }
  return output;
}

function encryptBlockAuth(block, round = 10, scratch = {}) {
  const tables = AUTH_TABLES;
  const param3 = (typeof round === 'number' && Number.isFinite(round)) ? round : 10;

  const state = scratch.state32 || new Uint8Array(32);
  scratch.state32 = state;
  const temp64 = scratch.temp64 || Buffer.alloc(64);
  scratch.temp64 = temp64;
  const tmp32 = scratch.tmp32 || new Uint8Array(32);
  scratch.tmp32 = tmp32;
  const output = scratch.out || new Uint8Array(16);
  scratch.out = output;

  prepareAESMatrix(block, state);

  const rounds = Math.min(9, Math.max(0, param3));
  for (let round = 0; round < rounds; round += 1) {
    const lVar21 = round * 4;
    let permPtr = 0;

    for (let i = 0; i < 4; i += 1) {
      const bVar4 = tables.permEncrypt[permPtr];
      const lVar9 = i;
      const lVar16 = lVar9 * 8;
      const base = i * 16;

      for (let j = 0; j < 4; j += 1) {
        const uVar8 = (bVar4 + j) & 3;
        const byteVal = state[lVar16 + uVar8];
        const idx = byteVal + (lVar9 + (lVar21 + uVar8) * 4) * 256;
        const value = tables.round.readUInt32LE(idx * 4);
        temp64.writeUInt32LE(value, base + j * 4);
      }
      permPtr += 2;
    }

    let iVar16 = 1;
    for (let lVar22 = 0; lVar22 < 4; lVar22 += 1) {
      let pbVar19Offset = lVar22;
      for (let lVar10 = 0; lVar10 < 4; lVar10 += 1) {
        const local10 = temp64[pbVar19Offset];
        let uVar7 = local10 & 0xf;
        let uVar26 = local10 & 0xf0;

        const localF0 = temp64[pbVar19Offset + 0x10];
        const localF1 = temp64[pbVar19Offset + 0x20];
        const localF2 = temp64[pbVar19Offset + 0x30];

        const lVar2 = lVar10 * 0x18 + round * 0x60;
        let iVar25 = iVar16;

        for (let lVar17 = 0; lVar17 < 3; lVar17 += 1) {
          const bVar4 = lVar17 === 0 ? localF0 : (lVar17 === 1 ? localF1 : localF2);
          const uVar1 = (bVar4 << 4) & 0xff;
          const uVar27 = uVar7 | uVar1;
          uVar26 = (uVar26 >> 4) | ((bVar4 >> 4) << 4);

          const idx1 = (lVar2 + (iVar25 - 1)) * 0x100 + uVar27;
          uVar7 = tables.xor[idx1] & 0xf;

          const idx2 = (lVar2 + iVar25) * 0x100 + uVar26;
          const bVar4New = tables.xor[idx2];
          uVar26 = (bVar4New & 0xf) << 4;
          iVar25 += 2;
        }

        state[lVar10 + lVar22 * 8] = (uVar26 | uVar7) & 0xff;
        pbVar19Offset += 4;
      }
      iVar16 += 6;
    }
  }

  if (param3 === 10) {
    tmp32.set(state);
    let uVar13 = 3;
    let uVar9 = 2;
    let uVar11 = 1;
    let uVar8 = 0;

    for (let row = 0; row < 4; row += 1) {
      const row0 = uVar8 & 3;
      state[row] = tables.final[tmp32[row0] + row0 * 0x400];

      const row1 = uVar11 & 3;
      state[8 + row] = tables.final[tmp32[8 + row1] + row1 * 0x400 + 0x100];

      const row2 = uVar9 & 3;
      state[0x10 + row] = tables.final[tmp32[0x10 + row2] + row2 * 0x400 + 0x200];

      const row3 = uVar13 & 3;
      state[0x18 + row] = tables.final[tmp32[0x18 + row3] + row3 * 0x400 + 0x300];

      uVar8 += 1;
      uVar11 += 1;
      uVar9 += 1;
      uVar13 += 1;
    }
  }

  for (let col = 0; col < 4; col += 1) {
    for (let row = 0; row < 4; row += 1) {
      output[col + row * 4] = state[col * 8 + row];
    }
  }
  return output;
}

function xorInto(target, source) {
  for (let i = 0; i < target.length; i += 1) {
    target[i] ^= source[i];
  }
}

function decryptCbc(data, iv) {
  if (data.length % 16 !== 0) {
    throw new Error('Bangcle ciphertext length must be multiple of 16');
  }
  if (iv.length !== 16) {
    throw new Error('Bangcle CBC IV must be 16 bytes');
  }
  const scratch = {
    state32: new Uint8Array(32),
    tmp32: new Uint8Array(32),
    temp64: Buffer.alloc(64),
    out: new Uint8Array(16),
  };
  const result = Buffer.alloc(data.length);
  let prev = Uint8Array.from(iv);

  for (let offset = 0; offset < data.length; offset += 16) {
    const block = data.subarray(offset, offset + 16);
    const decrypted = decryptBlockAuth(block, 1, scratch);
    const decoded = Buffer.from(decrypted);
    xorInto(decoded, prev);
    decoded.copy(result, offset);
    prev = Uint8Array.from(block);
  }
  return result;
}

function encryptCbc(data, iv) {
  if (data.length % 16 !== 0) {
    throw new Error('Bangcle plaintext length must be multiple of 16');
  }
  if (iv.length !== 16) {
    throw new Error('Bangcle CBC IV must be 16 bytes');
  }
  const scratch = {
    state32: new Uint8Array(32),
    tmp32: new Uint8Array(32),
    temp64: Buffer.alloc(64),
    out: new Uint8Array(16),
  };
  const result = Buffer.alloc(data.length);
  let prev = Uint8Array.from(iv);
  for (let offset = 0; offset < data.length; offset += 16) {
    const block = Buffer.from(data.subarray(offset, offset + 16));
    xorInto(block, prev);
    const encrypted = encryptBlockAuth(block, 10, scratch);
    Buffer.from(encrypted).copy(result, offset);
    prev = Uint8Array.from(encrypted);
  }
  return result;
}

function stripPkcs7(buffer) {
  if (buffer.length === 0) {
    return buffer;
  }
  const pad = buffer[buffer.length - 1];
  if (pad === 0 || pad > 16) {
    return buffer;
  }
  for (let i = buffer.length - pad; i < buffer.length; i += 1) {
    if (buffer[i] !== pad) {
      return buffer;
    }
  }
  return buffer.slice(0, buffer.length - pad);
}

function addPkcs7(buffer, blockSize = 16) {
  const remainder = buffer.length % blockSize;
  const pad = remainder === 0 ? blockSize : blockSize - remainder;
  return Buffer.concat([buffer, Buffer.alloc(pad, pad)]);
}

function normaliseCheckcodeInput(input) {
  let cleaned = String(input || '').replace(/\s+/g, '').trim();
  cleaned = cleaned.replace(/-/g, '+').replace(/_/g, '/');
  if (!cleaned.length) {
    throw new Error('Bangcle input is empty');
  }
  if (!cleaned.startsWith('F')) {
    throw new Error('Bangcle envelope must start with "F"');
  }
  cleaned = cleaned.slice(1);
  const remainder = cleaned.length % 4;
  if (remainder !== 0) {
    cleaned = `${cleaned}${'='.repeat(4 - remainder)}`;
  }
  return cleaned;
}

function decodeEnvelope(base64) {
  const payload = normaliseCheckcodeInput(base64);
  const ciphertext = Buffer.from(payload, 'base64');
  if (!ciphertext.length) {
    throw new Error('Bangcle ciphertext is empty');
  }
  if (ciphertext.length % 16 !== 0) {
    throw new Error(`Bangcle ciphertext length ${ciphertext.length} is incompatible with 16-byte blocks`);
  }

  const iv = Buffer.alloc(16, 0);
  const plaintext = decryptCbc(ciphertext, iv);
  return stripPkcs7(plaintext);
}

function encodeEnvelope(plaintext) {
  const plainBuf = Buffer.isBuffer(plaintext) ? Buffer.from(plaintext) : Buffer.from(String(plaintext), 'utf8');
  const padded = addPkcs7(plainBuf);
  const iv = Buffer.alloc(16, 0);
  const ciphertext = encryptCbc(padded, iv);
  return `F${ciphertext.toString('base64')}`;
}

module.exports = {
  decodeEnvelope,
  encodeEnvelope,
};
