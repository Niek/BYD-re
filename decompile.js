#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bangcle = require('./bangcle');

const DEFAULT_ALGORITHM = 'aes-128-cbc';
const ZERO_IV = Buffer.alloc(16, 0);

const CONFIG_KEY = Buffer.from('796834E7A2839412D79DBC5F1327594D', 'hex');
const KNOWN_KEYS = Object.freeze([
  { name: 'CONFIG_KEY', key: CONFIG_KEY },
]);

const DEFAULT_STATE_FILE = process.env.BYD_DECODE_STATE_FILE
  ? path.resolve(process.env.BYD_DECODE_STATE_FILE)
  : path.join(os.tmpdir(), 'byd_http_dec_state.json');

function ensureBuffer(data, encoding = 'utf8') {
  if (Buffer.isBuffer(data)) {
    return Buffer.from(data);
  }
  if (typeof data === 'string') {
    return Buffer.from(data, encoding);
  }
  throw new TypeError('Expected data to be a Buffer or string');
}

function hexToBuffer(hexString) {
  if (Buffer.isBuffer(hexString)) {
    return Buffer.from(hexString);
  }
  if (typeof hexString !== 'string') {
    throw new TypeError('hexToBuffer expects a string or Buffer');
  }
  const normalised = hexString.replace(/\s+/g, '');
  if (!normalised.length || normalised.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(normalised)) {
    throw new Error('Invalid hex string');
  }
  return Buffer.from(normalised, 'hex');
}

function looksLikeBase64(text) {
  if (typeof text !== 'string' || !text.length) {
    return false;
  }
  const cleaned = text.replace(/\s+/g, '').trim();
  return /^[A-Za-z0-9+/]+={0,3}$/.test(cleaned);
}

function tryParseJson(text) {
  if (typeof text !== 'string') {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function md5HexUpper(value) {
  return crypto.createHash('md5').update(String(value), 'utf8').digest('hex').toUpperCase();
}

function printableRatio(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) {
    return 0;
  }
  let printable = 0;
  for (const byte of buffer) {
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d) {
      printable += 1;
    }
  }
  return printable / buffer.length;
}

function renderDecodedPayload(label, buffer) {
  const utf8 = buffer.toString('utf8').trim();
  const parsed = tryParseJson(utf8);
  const sample = buffer.toString('hex').slice(0, 64);
  console.log(`# ${label}: len=${buffer.length} hex=${sample}${buffer.length * 2 > sample.length ? '…' : ''}`);
  if (parsed) {
    console.log(JSON.stringify(parsed, null, 2));
  } else {
    console.log(utf8);
  }
}

function decryptAesCbc(cipherBuffer, keyBuffer, ivBuffer) {
  const decipher = crypto.createDecipheriv(
    keyBuffer.length === 16 ? 'aes-128-cbc' : 'aes-256-cbc',
    keyBuffer,
    ivBuffer,
  );
  return Buffer.concat([decipher.update(cipherBuffer), decipher.final()]);
}

function tryStaticKeyDecrypt(buffer) {
  for (const { name, key } of KNOWN_KEYS) {
    try {
      const plaintext = decryptAesCbc(buffer, key, ZERO_IV);
      const parsed = tryParseJson(plaintext.toString('utf8').trim());
      if (!parsed && printableRatio(plaintext) < 0.9) {
        continue;
      }
      return { keyName: name, buffer: plaintext };
    } catch {
      // continue
    }
  }
  return null;
}

function extractBalancedJsonWithOptionalPrefix(text) {
  if (typeof text !== 'string' || !text.length) {
    return null;
  }
  const trimmed = text.trim();
  if (!trimmed.length) {
    return null;
  }

  let prefix = '';
  let start = -1;
  let openChar = '{';
  let closeChar = '}';

  if (trimmed.startsWith('F{')) {
    prefix = 'F';
    start = 1;
  } else if (trimmed.startsWith('F[')) {
    prefix = 'F';
    start = 1;
    openChar = '[';
    closeChar = ']';
  } else if (trimmed.startsWith('{')) {
    start = 0;
  } else if (trimmed.startsWith('[')) {
    start = 0;
    openChar = '[';
    closeChar = ']';
  } else {
    const objIdx = trimmed.indexOf('{');
    const arrIdx = trimmed.indexOf('[');
    if (objIdx === -1 && arrIdx === -1) {
      return null;
    }
    if (objIdx === -1 || (arrIdx !== -1 && arrIdx < objIdx)) {
      start = arrIdx;
      openChar = '[';
      closeChar = ']';
    } else {
      start = objIdx;
    }
  }

  let depth = 0;
  let inString = false;
  let escaped = false;
  let end = -1;

  for (let i = start; i < trimmed.length; i += 1) {
    const ch = trimmed[i];
    if (inString) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        escaped = true;
        continue;
      }
      if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === openChar) {
      depth += 1;
      continue;
    }
    if (ch === closeChar) {
      depth -= 1;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }

  if (end === -1) {
    return null;
  }
  return `${prefix}${trimmed.slice(start, end)}`;
}

function decryptInnerPayload(hexCiphertext, identifier, options = {}) {
  if (!identifier || typeof identifier !== 'string') {
    throw new Error('Identifier must be a non-empty string');
  }
  const key = crypto.createHash('md5').update(identifier, 'utf8').digest();
  const cipherBuf = hexToBuffer(hexCiphertext);
  const plaintext = decryptAesCbc(cipherBuf, key, ZERO_IV);
  if (options.returnBuffer) {
    return plaintext;
  }
  return plaintext.toString(options.outputEncoding || 'utf8');
}

function encryptInnerPayload(plaintext, identifier, options = {}) {
  if (!identifier || typeof identifier !== 'string') {
    throw new Error('Identifier must be a non-empty string');
  }
  const key = crypto.createHash('md5').update(identifier, 'utf8').digest();
  const plainBuf = ensureBuffer(plaintext, options.inputEncoding || 'utf8');
  const cipher = crypto.createCipheriv(DEFAULT_ALGORITHM, key, ZERO_IV);
  const ciphertext = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
  if (options.returnBuffer) {
    return ciphertext;
  }
  const encoding = options.outputEncoding || 'hex';
  const rendered = ciphertext.toString(encoding);
  return encoding === 'hex' ? rendered.toUpperCase() : rendered;
}

function loadState(stateFile = DEFAULT_STATE_FILE) {
  try {
    const raw = fs.readFileSync(stateFile, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.keys)) {
      return { keys: [] };
    }
    const keys = parsed.keys
      .filter((entry) => entry && typeof entry.keyHex === 'string')
      .map((entry) => ({
        keyHex: entry.keyHex.toUpperCase(),
        identifier: typeof entry.identifier === 'string' ? entry.identifier : null,
        source: typeof entry.source === 'string' ? entry.source : 'state',
        updatedAt: Number(entry.updatedAt) || Date.now(),
      }));
    return { keys };
  } catch {
    return { keys: [] };
  }
}

function saveState(state, stateFile = DEFAULT_STATE_FILE) {
  const normalised = {
    keys: (state.keys || [])
      .slice(0, 64)
      .map((entry) => ({
        keyHex: String(entry.keyHex || '').toUpperCase(),
        identifier: typeof entry.identifier === 'string' ? entry.identifier : null,
        source: typeof entry.source === 'string' ? entry.source : 'state',
        updatedAt: Number(entry.updatedAt) || Date.now(),
      }))
      .filter((entry) => /^[0-9A-F]{32}$/.test(entry.keyHex)),
  };
  fs.writeFileSync(stateFile, JSON.stringify(normalised, null, 2));
}

function addStateKey(state, keyHex, identifier, source = 'state') {
  if (!state || !keyHex) {
    return false;
  }
  const clean = String(keyHex).trim().toUpperCase();
  if (!/^[0-9A-F]{32}$/.test(clean)) {
    return false;
  }
  const id = typeof identifier === 'string' && identifier.trim().length
    ? identifier.trim()
    : null;
  const now = Date.now();
  const existing = (state.keys || []).find((entry) => entry.keyHex === clean && entry.identifier === id);
  if (existing) {
    existing.updatedAt = now;
    existing.source = source;
    return false;
  }
  if (!Array.isArray(state.keys)) {
    state.keys = [];
  }
  state.keys.unshift({
    keyHex: clean,
    identifier: id,
    source,
    updatedAt: now,
  });
  return true;
}

function getStateCandidates(state, identifier) {
  const keys = Array.isArray(state && state.keys) ? state.keys : [];
  const preferred = [];
  const others = [];
  for (const entry of keys) {
    if (!entry || !entry.keyHex || !/^[0-9A-F]{32}$/.test(entry.keyHex)) {
      continue;
    }
    if (identifier && entry.identifier === identifier) {
      preferred.push(entry);
    } else {
      others.push(entry);
    }
  }
  const seen = new Set();
  const out = [];
  for (const entry of preferred.concat(others)) {
    if (seen.has(entry.keyHex)) {
      continue;
    }
    seen.add(entry.keyHex);
    out.push(entry);
  }
  return out;
}

function deriveStateKeysFromOuter(outerObject) {
  if (!outerObject || typeof outerObject !== 'object') {
    return [];
  }
  const functionType = typeof outerObject.functionType === 'string'
    ? outerObject.functionType.toLowerCase()
    : '';
  if (functionType !== 'pwdlogin') {
    return [];
  }
  if (typeof outerObject.signKey !== 'string' || !outerObject.signKey.length) {
    return [];
  }
  const keyHex = md5HexUpper(md5HexUpper(outerObject.signKey));
  const identifier = typeof outerObject.identifier === 'string' ? outerObject.identifier : null;
  return [{
    keyHex,
    identifier,
    source: 'pwdLogin.signKey',
  }];
}

function captureStateFromDecodedField(state, outerObject, field, decodedResult, debug = false) {
  if (!decodedResult || !decodedResult.buffer || field !== 'respondData') {
    return false;
  }
  const utf8 = decodedResult.buffer.toString('utf8').trim();
  const parsed = tryParseJson(utf8);
  if (!parsed || typeof parsed !== 'object') {
    return false;
  }
  const token = parsed.token && typeof parsed.token === 'object' ? parsed.token : null;
  if (!token || typeof token.encryToken !== 'string') {
    return false;
  }
  const userId = (typeof token.userId === 'string' || typeof token.userId === 'number')
    ? String(token.userId)
    : (typeof outerObject.identifier === 'string' ? outerObject.identifier : null);
  const contentKey = crypto.createHash('md5').update(token.encryToken, 'utf8').digest('hex').toUpperCase();
  const added = addStateKey(state, contentKey, userId, 'token.encryToken');
  if (debug && added) {
    console.error(`# state: learned content key for identifier=${userId || 'unknown'}`);
  }
  return added;
}

if (require.main === module) {
  function printUsage() {
    console.error([
      'Usage:',
      '  node decompile.js http-dec <payload> [--identifier <id>] [--field <name>] [--key <hex>] [--state-file <path>] [--debug]',
      '  node decompile.js http-enc <plaintext> --identifier <id>',
    ].join('\n'));
  }

  function parseArgs(argv) {
    const positional = [];
    const options = {};
    for (let i = 0; i < argv.length; i += 1) {
      const arg = argv[i];
      if (!arg.startsWith('--')) {
        positional.push(arg);
        continue;
      }
      const eqIndex = arg.indexOf('=');
      if (eqIndex !== -1) {
        options[arg.slice(2, eqIndex)] = arg.slice(eqIndex + 1);
        continue;
      }
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next != null && !next.startsWith('--')) {
        options[key] = next;
        i += 1;
      } else {
        options[key] = true;
      }
    }
    return { positional, options };
  }

  function decodeHexField(label, rawHex, options = {}) {
    const cleanedHex = String(rawHex || '').replace(/\s+/g, '');
    if (!cleanedHex.length || cleanedHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleanedHex)) {
      return null;
    }

    const cipherBuffer = Buffer.from(cleanedHex, 'hex');
    const tryKey = (hex, display) => {
      try {
        const keyBuf = Buffer.from(hex, 'hex');
        if (keyBuf.length !== 16 && keyBuf.length !== 32) {
          return null;
        }
        const plaintext = decryptAesCbc(cipherBuffer, keyBuf, ZERO_IV);
        const parsed = tryParseJson(plaintext.toString('utf8').trim());
        if (!parsed && printableRatio(plaintext) < 0.9) {
          return null;
        }
        renderDecodedPayload(`${label} (${display})`, plaintext);
        return { label: display, keyHex: hex.toUpperCase(), buffer: plaintext };
      } catch {
        return null;
      }
    };

    const staticAttempt = tryStaticKeyDecrypt(cipherBuffer);
    if (staticAttempt) {
      renderDecodedPayload(`${label} (static:${staticAttempt.keyName})`, staticAttempt.buffer);
      return { label: `static:${staticAttempt.keyName}`, buffer: staticAttempt.buffer };
    }

    if (options.keyHex) {
      const keyed = tryKey(options.keyHex, `key:${options.keyHex}`);
      if (keyed) {
        return keyed;
      }
    }

    for (const entry of options.stateCandidates || []) {
      const dynamic = tryKey(entry.keyHex, `state:${entry.keyHex.slice(0, 12).toLowerCase()}`);
      if (dynamic) {
        return dynamic;
      }
    }

    if (options.identifier) {
      try {
        const buffer = decryptInnerPayload(cleanedHex, options.identifier, { returnBuffer: true });
        renderDecodedPayload(`${label} (md5(identifier))`, buffer);
        return { label: 'md5(identifier)', buffer };
      } catch {
        // continue
      }
    }

    return null;
  }

  const [command, ...rest] = process.argv.slice(2);
  if (!command) {
    printUsage();
    process.exit(1);
  }

  try {
    if (command === 'http-enc') {
      const { positional, options } = parseArgs(rest);
      const plaintext = positional[0];
      const identifier = options.identifier || options.id;
      if (!plaintext || !identifier) {
        throw new Error('http-enc requires <plaintext> and --identifier <id>');
      }
      console.log(encryptInnerPayload(plaintext, identifier));
      process.exit(0);
    }

    if (command !== 'http-dec') {
      throw new Error(`Unknown command "${command}"`);
    }

    const { positional, options } = parseArgs(rest);
    const payload = positional[0];
    if (!payload) {
      throw new Error('http-dec requires <payload>');
    }

    const explicitIdentifier = options.identifier || options.id || null;
    const fieldOverride = options.field;
    const keyHex = options.key || null;
    const debug = Boolean(options.debug || options.verbose);
    const stateFile = options['state-file']
      ? path.resolve(String(options['state-file']))
      : DEFAULT_STATE_FILE;
    const state = loadState(stateFile);
    let stateDirty = false;

    const cleanedInput = payload.trim();
    const inputJson = tryParseJson(cleanedInput);
    let decodeInput = cleanedInput;
    if (inputJson && typeof inputJson === 'object') {
      if (typeof inputJson.request === 'string' && inputJson.request.trim().length) {
        decodeInput = inputJson.request.trim();
        if (debug) {
          console.log('# Extracted request field from input JSON');
        }
      } else if (typeof inputJson.response === 'string' && inputJson.response.trim().length) {
        decodeInput = inputJson.response.trim();
        if (debug) {
          console.log('# Extracted response field from input JSON');
        }
      }
    }
    const compactInput = decodeInput.replace(/\s+/g, '');

    let outerText = null;
    let outerObject = null;

    const setOuter = (text) => {
      if (typeof text !== 'string') {
        return;
      }
      const trimmed = text.trim();
      if (!trimmed.length) {
        return;
      }
      const normalised = (trimmed.startsWith('F{') || trimmed.startsWith('F['))
        ? trimmed.slice(1)
        : trimmed;
      const parsed = tryParseJson(normalised);
      if (parsed) {
        outerObject = parsed;
        outerText = JSON.stringify(parsed, null, 2);
      } else {
        outerText = trimmed;
      }
    };

    if (/^[0-9a-fA-F]+$/.test(compactInput)) {
      const hexResult = decodeHexField('hex', compactInput, {
        identifier: explicitIdentifier,
        keyHex,
        stateCandidates: getStateCandidates(state, explicitIdentifier),
      });
      if (!hexResult) {
        throw new Error('No decrypt strategy succeeded for hex input');
      }
      if (captureStateFromDecodedField(state, {}, 'respondData', hexResult, debug)) {
        stateDirty = true;
      }
      if (stateDirty) {
        saveState(state, stateFile);
      }
      process.exit(0);
    }

    if (looksLikeBase64(compactInput)) {
      try {
        const plaintext = bangcle.decodeEnvelope(compactInput);
        const utf8 = plaintext.toString('utf8');
        const balanced = extractBalancedJsonWithOptionalPrefix(utf8);
        setOuter(balanced || utf8);
      } catch (err) {
        if (debug) {
          console.error(`Bangcle decode failed: ${err.message}`);
        }
      }
    } else {
      setOuter(decodeInput);
    }

    if (outerText) {
      console.log(outerText);
    }

    if (!outerObject || typeof outerObject !== 'object') {
      process.exit(0);
    }

    for (const entry of deriveStateKeysFromOuter(outerObject)) {
      if (addStateKey(state, entry.keyHex, entry.identifier, entry.source)) {
        stateDirty = true;
      }
    }

    const effectiveIdentifier = explicitIdentifier
      || (typeof outerObject.identifier === 'string' ? outerObject.identifier : null);
    const stateCandidates = getStateCandidates(state, effectiveIdentifier);

    const candidateFields = [];
    if (fieldOverride) {
      if (typeof outerObject[fieldOverride] === 'string') {
        candidateFields.push(fieldOverride);
      } else {
        console.error(`Field "${fieldOverride}" not present or not a string on parsed payload.`);
      }
    } else {
      ['encryData', 'respondData', 'data'].forEach((field) => {
        if (typeof outerObject[field] === 'string') {
          candidateFields.push(field);
        }
      });
    }

    for (const field of candidateFields) {
      const value = outerObject[field];
      if (typeof value !== 'string' || !value.length) {
        continue;
      }
      let hex = value.replace(/\s+/g, '');
      if (!/^[0-9a-fA-F]+$/.test(hex)) {
        const matches = hex.match(/[0-9a-fA-F]+/g);
        if (matches && matches.length) {
          hex = matches.reduce((longest, current) => (current.length > longest.length ? current : longest), '');
        }
      }
      const decodeResult = decodeHexField(field, hex, {
        identifier: effectiveIdentifier,
        keyHex,
        stateCandidates,
      });
      if (!decodeResult) {
        console.error(`No decrypt strategy succeeded for ${field}.`);
        continue;
      }
      if (captureStateFromDecodedField(state, outerObject, field, decodeResult, debug)) {
        stateDirty = true;
      }
    }
    if (stateDirty) {
      saveState(state, stateFile);
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}
