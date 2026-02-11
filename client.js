#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const util = require('util');
const { loadEnvFile } = require('node:process');
const bangcle = require('./bangcle');

try {
  loadEnvFile();
} catch (err) {
  if (!err || err.code !== 'ENOENT') {
    throw err;
  }
}

const BASE_URL = 'https://dilinkappoversea-eu.byd.auto';
const USER_AGENT = 'okhttp/4.12.0';

// Username/password are expected from environment or .env. Optional BYD_* overrides can also be placed in .env.
const CONFIG = Object.freeze({
  username: process.env.BYD_USERNAME || '',
  password: process.env.BYD_PASSWORD || '',
  countryCode: process.env.BYD_COUNTRY_CODE || 'NL',
  language: process.env.BYD_LANGUAGE || 'en',
  imeiMd5: process.env.BYD_IMEI_MD5 || '00000000000000000000000000000000',
  vin: process.env.BYD_VIN || '',
  networkType: process.env.BYD_NETWORK_TYPE || 'wifi',
  appInnerVersion: process.env.BYD_APP_INNER_VERSION || '220',
  appVersion: process.env.BYD_APP_VERSION || '2.2.1',
  osType: process.env.BYD_OS_TYPE || '15',
  osVersion: process.env.BYD_OS_VERSION || '35',
  timeZone: process.env.BYD_TIME_ZONE || 'Europe/Amsterdam',
  deviceType: process.env.BYD_DEVICE_TYPE || '0',
  mobileBrand: process.env.BYD_MOBILE_BRAND || 'XIAOMI',
  mobileModel: process.env.BYD_MOBILE_MODEL || 'POCO F1',
  softType: process.env.BYD_SOFT_TYPE || '0',
  tboxVersion: process.env.BYD_TBOX_VERSION || '3',
  isAuto: process.env.BYD_IS_AUTO || '1',
  ostype: process.env.BYD_OSTYPE || 'and',
  imei: process.env.BYD_IMEI || 'BANGCLE01234',
  mac: process.env.BYD_MAC || '00:00:00:00:00:00',
  model: process.env.BYD_MODEL || 'POCO F1',
  sdk: process.env.BYD_SDK || '35',
  mod: process.env.BYD_MOD || 'Xiaomi',
  realtimePollAttempts: 10,
  realtimePollIntervalMs: 1500,
});

const cookieJar = new Map();

function md5Hex(value) {
  return crypto.createHash('md5').update(value, 'utf8').digest('hex').toUpperCase();
}

function pwdLoginKey(password) {
  return md5Hex(md5Hex(password));
}

function sha1Mixed(value) {
  const digest = crypto.createHash('sha1').update(value, 'utf8').digest();
  const mixed = Array.from(digest)
    .map((byte, index) => {
      const hex = byte.toString(16).padStart(2, '0');
      return index % 2 === 0 ? hex.toUpperCase() : hex.toLowerCase();
    })
    .join('');

  let filtered = '';
  for (let i = 0; i < mixed.length; i += 1) {
    const ch = mixed[i];
    if (ch === '0' && i % 2 === 0) {
      continue;
    }
    filtered += ch;
  }
  return filtered;
}

function buildSignString(fields, password) {
  const keys = Object.keys(fields).sort();
  const joined = keys.map((key) => `${key}=${String(fields[key])}`).join('&');
  return `${joined}&password=${password}`;
}

function computeCheckcode(payload) {
  const json = JSON.stringify(payload);
  const md5 = crypto.createHash('md5').update(json, 'utf8').digest('hex');
  return `${md5.slice(24, 32)}${md5.slice(8, 16)}${md5.slice(16, 24)}${md5.slice(0, 8)}`;
}

function aesEncryptHex(plaintextUtf8, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.alloc(16, 0);
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([cipher.update(plaintextUtf8, 'utf8'), cipher.final()]).toString('hex').toUpperCase();
}

function aesDecryptUtf8(cipherHex, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.alloc(16, 0);
  const ciphertext = Buffer.from(cipherHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function randomHex16() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function commonOuterFields() {
  return {
    ostype: CONFIG.ostype,
    imei: CONFIG.imei,
    mac: CONFIG.mac,
    model: CONFIG.model,
    sdk: CONFIG.sdk,
    mod: CONFIG.mod,
  };
}

function stepLog(message, details) {
  if (details && typeof details === 'object') {
    console.error(`[client] ${message} ${JSON.stringify(details)}`);
    return;
  }
  console.error(`[client] ${message}`);
}

function encodeOuterPayload(payload) {
  return bangcle.encodeEnvelope(JSON.stringify(payload));
}

function decodeOuterPayload(rawPayload) {
  if (typeof rawPayload !== 'string' || !rawPayload.trim()) {
    throw new Error('Empty response payload');
  }
  const decodedText = bangcle.decodeEnvelope(rawPayload).toString('utf8').trim();
  const normalised = (decodedText.startsWith('F{') || decodedText.startsWith('F['))
    ? decodedText.slice(1)
    : decodedText;
  try {
    return JSON.parse(normalised);
  } catch {
    throw new Error(`Bangcle response is not JSON (head=${JSON.stringify(decodedText.slice(0, 64))})`);
  }
}

function decryptRespondDataJson(respondDataHex, keyHex) {
  const plain = aesDecryptUtf8(respondDataHex, keyHex);
  return JSON.parse(plain);
}

function updateCookiesFromHeaders(headers) {
  const getSetCookie = headers.getSetCookie;
  if (typeof getSetCookie === 'function') {
    for (const raw of getSetCookie.call(headers) || []) {
      const first = String(raw).split(';', 1)[0];
      const idx = first.indexOf('=');
      if (idx > 0) {
        cookieJar.set(first.slice(0, idx), first.slice(idx + 1));
      }
    }
    return;
  }

  const single = headers.get('set-cookie');
  if (!single) {
    return;
  }
  const first = String(single).split(';', 1)[0];
  const idx = first.indexOf('=');
  if (idx > 0) {
    cookieJar.set(first.slice(0, idx), first.slice(idx + 1));
  }
}

function buildCookieHeader() {
  if (!cookieJar.size) {
    return '';
  }
  return Array.from(cookieJar.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
}

async function postSecure(endpoint, outerPayload) {
  const headers = {
    'accept-encoding': 'identity',
    'content-type': 'application/json; charset=UTF-8',
    'user-agent': USER_AGENT,
  };

  const cookie = buildCookieHeader();
  if (cookie) {
    headers.cookie = cookie;
  }

  const requestPayload = encodeOuterPayload(outerPayload);

  const response = await fetch(`${BASE_URL}${endpoint}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ request: requestPayload }),
  });

  updateCookiesFromHeaders(response.headers);

  const bodyText = await response.text();
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${endpoint}: ${bodyText.slice(0, 200)}`);
  }

  let body;
  try {
    body = JSON.parse(bodyText);
  } catch {
    throw new Error(`Invalid JSON response from ${endpoint}: ${bodyText.slice(0, 200)}`);
  }

  if (!body || typeof body.response !== 'string') {
    throw new Error(`Missing response payload for ${endpoint}`);
  }

  const decoded = decodeOuterPayload(body.response);
  return decoded;
}

function buildLoginRequest(nowMs) {
  const random = randomHex16();
  const reqTimestamp = String(nowMs);
  const serviceTime = String(Date.now());

  const inner = {
    appInnerVersion: CONFIG.appInnerVersion,
    appVersion: CONFIG.appVersion,
    deviceName: `${CONFIG.mobileBrand}${CONFIG.mobileModel}`,
    deviceType: CONFIG.deviceType,
    imeiMD5: CONFIG.imeiMd5,
    isAuto: CONFIG.isAuto,
    mobileBrand: CONFIG.mobileBrand,
    mobileModel: CONFIG.mobileModel,
    networkType: CONFIG.networkType,
    osType: CONFIG.osType,
    osVersion: CONFIG.osVersion,
    random,
    softType: CONFIG.softType,
    timeStamp: reqTimestamp,
    timeZone: CONFIG.timeZone,
  };

  const encryData = aesEncryptHex(JSON.stringify(inner), pwdLoginKey(CONFIG.password));

  const signFields = {
    ...inner,
    countryCode: CONFIG.countryCode,
    functionType: 'pwdLogin',
    identifier: CONFIG.username,
    identifierType: '0',
    language: CONFIG.language,
    reqTimestamp,
  };

  const sign = sha1Mixed(buildSignString(signFields, md5Hex(CONFIG.password)));

  const outer = {
    countryCode: CONFIG.countryCode,
    encryData,
    functionType: 'pwdLogin',
    identifier: CONFIG.username,
    identifierType: '0',
    imeiMD5: CONFIG.imeiMd5,
    isAuto: CONFIG.isAuto,
    language: CONFIG.language,
    reqTimestamp,
    sign,
    signKey: CONFIG.password,
    ...commonOuterFields(),
    serviceTime,
  };
  outer.checkcode = computeCheckcode(outer);

  return { outer };
}

function buildTokenOuterEnvelope(nowMs, session, inner) {
  const reqTimestamp = String(nowMs);
  const contentKey = md5Hex(session.encryToken);
  const signKey = md5Hex(session.signToken);
  const encryData = aesEncryptHex(JSON.stringify(inner), contentKey);
  const signFields = {
    ...inner,
    countryCode: CONFIG.countryCode,
    identifier: session.userId,
    imeiMD5: CONFIG.imeiMd5,
    language: CONFIG.language,
    reqTimestamp,
  };
  const sign = sha1Mixed(buildSignString(signFields, signKey));
  const outer = {
    countryCode: CONFIG.countryCode,
    encryData,
    identifier: session.userId,
    imeiMD5: CONFIG.imeiMd5,
    language: CONFIG.language,
    reqTimestamp,
    sign,
    ...commonOuterFields(),
    serviceTime: String(Date.now()),
  };
  outer.checkcode = computeCheckcode(outer);
  return { outer, contentKey };
}

function buildListRequest(nowMs, session) {
  const inner = {
    deviceType: CONFIG.deviceType,
    imeiMD5: CONFIG.imeiMd5,
    networkType: CONFIG.networkType,
    random: randomHex16(),
    timeStamp: String(nowMs),
    version: CONFIG.appInnerVersion,
  };
  return buildTokenOuterEnvelope(nowMs, session, inner);
}

function buildVehicleRealtimeEnvelope(nowMs, session, vin, requestSerial = null) {
  const inner = {
    deviceType: CONFIG.deviceType,
    energyType: '0',
    imeiMD5: CONFIG.imeiMd5,
    networkType: CONFIG.networkType,
    random: randomHex16(),
    tboxVersion: CONFIG.tboxVersion,
    timeStamp: String(nowMs),
    version: CONFIG.appInnerVersion,
    vin,
  };
  if (requestSerial) {
    inner.requestSerial = requestSerial;
  }
  return buildTokenOuterEnvelope(nowMs, session, inner);
}

function buildGpsInfoEnvelope(nowMs, session, vin, requestSerial = null) {
  const inner = {
    deviceType: CONFIG.deviceType,
    imeiMD5: CONFIG.imeiMd5,
    networkType: CONFIG.networkType,
    random: randomHex16(),
    timeStamp: String(nowMs),
    version: CONFIG.appInnerVersion,
    vin,
  };
  if (requestSerial) {
    inner.requestSerial = requestSerial;
  }
  return buildTokenOuterEnvelope(nowMs, session, inner);
}

function isRealtimeDataReady(vehicleInfo) {
  if (!vehicleInfo || typeof vehicleInfo !== 'object') {
    return false;
  }
  if (Number(vehicleInfo.onlineState) === 2) {
    return false;
  }

  const tireFields = [
    'leftFrontTirepressure',
    'rightFrontTirepressure',
    'leftRearTirepressure',
    'rightRearTirepressure',
  ];
  const hasTireData = tireFields.some((field) => Number(vehicleInfo[field]) > 0);

  if (hasTireData) {
    return true;
  }
  if (Number(vehicleInfo.time) > 0) {
    return true;
  }
  if (Number(vehicleInfo.enduranceMileage) > 0) {
    return true;
  }
  return false;
}

async function fetchVehicleRealtime(endpoint, session, vin, requestSerial = null) {
  const req = buildVehicleRealtimeEnvelope(Date.now(), session, vin, requestSerial);
  const outer = await postSecure(endpoint, req.outer);
  if (String(outer.code) !== '0') {
    throw new Error(`${endpoint} failed: code=${outer.code} message=${outer.message || ''}`.trim());
  }
  const vehicleInfo = decryptRespondDataJson(outer.respondData, req.contentKey);
  const nextSerial = vehicleInfo && typeof vehicleInfo.requestSerial === 'string'
    ? vehicleInfo.requestSerial
    : (requestSerial || null);
  return { vehicleInfo, requestSerial: nextSerial };
}

async function pollVehicleRealtime(session, vin) {
  let latest = null;
  let serial = null;
  const pollTrace = [];

  const requestResult = await fetchVehicleRealtime('/vehicleInfo/vehicle/vehicleRealTimeRequest', session, vin, null);
  latest = requestResult.vehicleInfo;
  serial = requestResult.requestSerial || null;
  pollTrace.push({
    stage: 'request',
    endpoint: '/vehicleInfo/vehicle/vehicleRealTimeRequest',
    onlineState: latest && latest.onlineState,
    requestSerial: serial,
    rightRearTirepressure: latest && latest.rightRearTirepressure,
    time: latest && latest.time,
  });
  stepLog('Vehicle realtime poll', pollTrace[pollTrace.length - 1]);

  if (isRealtimeDataReady(latest)) {
    return { vehicleInfo: latest, requestSerial: serial, pollTrace };
  }

  if (!serial) {
    return { vehicleInfo: latest, requestSerial: serial, pollTrace };
  }

  for (let attempt = 1; attempt <= CONFIG.realtimePollAttempts; attempt += 1) {
    if (CONFIG.realtimePollIntervalMs > 0) {
      await sleep(CONFIG.realtimePollIntervalMs);
    }

    try {
      const resultData = await fetchVehicleRealtime('/vehicleInfo/vehicle/vehicleRealTimeResult', session, vin, serial);
      latest = resultData.vehicleInfo;
      serial = resultData.requestSerial || serial;
      pollTrace.push({
        stage: 'result',
        attempt,
        endpoint: '/vehicleInfo/vehicle/vehicleRealTimeResult',
        onlineState: latest && latest.onlineState,
        requestSerial: serial,
        rightRearTirepressure: latest && latest.rightRearTirepressure,
        time: latest && latest.time,
      });
      stepLog('Vehicle realtime poll', pollTrace[pollTrace.length - 1]);

      if (isRealtimeDataReady(latest)) {
        break;
      }
    } catch (err) {
      stepLog('Vehicle realtime result poll failed', {
        attempt,
        requestSerial: serial,
        error: err.message,
      });
    }
  }

  return { vehicleInfo: latest, requestSerial: serial, pollTrace };
}

function isGpsInfoReady(gpsInfo) {
  if (!gpsInfo || typeof gpsInfo !== 'object') {
    return false;
  }
  const keys = Object.keys(gpsInfo);
  if (!keys.length) {
    return false;
  }
  if (keys.length === 1 && keys[0] === 'requestSerial') {
    return false;
  }
  return true;
}

async function fetchGpsEndpoint(endpoint, session, vin, requestSerial = null) {
  const gpsReq = buildGpsInfoEnvelope(Date.now(), session, vin, requestSerial);
  const gpsOuter = await postSecure(endpoint, gpsReq.outer);
  if (String(gpsOuter.code) !== '0') {
    throw new Error(`${endpoint} failed: code=${gpsOuter.code} message=${gpsOuter.message || ''}`.trim());
  }
  const gpsInfo = decryptRespondDataJson(gpsOuter.respondData, gpsReq.contentKey);
  const nextSerial = gpsInfo && typeof gpsInfo.requestSerial === 'string'
    ? gpsInfo.requestSerial
    : (requestSerial || null);
  return {
    gpsInfo,
    requestSerial: nextSerial,
  };
}

async function pollGpsInfo(session, vin) {
  let latest = null;
  let serial = null;
  const pollTrace = [];

  try {
    const requestResult = await fetchGpsEndpoint('/control/getGpsInfo', session, vin, null);
    latest = requestResult.gpsInfo;
    serial = requestResult.requestSerial || null;
    pollTrace.push({
      stage: 'request',
      endpoint: '/control/getGpsInfo',
      requestSerial: serial,
      keys: latest && typeof latest === 'object' ? Object.keys(latest) : [],
    });
    stepLog('GPS poll', pollTrace[pollTrace.length - 1]);
  } catch (err) {
    return {
      ok: false,
      code: '',
      message: err.message,
      gpsInfo: null,
      requestSerial: null,
      pollTrace,
    };
  }

  if (isGpsInfoReady(latest)) {
    return {
      ok: true,
      code: '0',
      message: 'SUCCESS',
      gpsInfo: latest,
      requestSerial: serial,
      pollTrace,
    };
  }

  if (!serial) {
    return {
      ok: true,
      code: '0',
      message: 'SUCCESS',
      gpsInfo: latest,
      requestSerial: serial,
      pollTrace,
    };
  }

  for (let attempt = 1; attempt <= CONFIG.realtimePollAttempts; attempt += 1) {
    if (CONFIG.realtimePollIntervalMs > 0) {
      await sleep(CONFIG.realtimePollIntervalMs);
    }
    try {
      const result = await fetchGpsEndpoint('/control/getGpsInfoResult', session, vin, serial);
      latest = result.gpsInfo;
      serial = result.requestSerial || serial;
      pollTrace.push({
        stage: 'result',
        attempt,
        endpoint: '/control/getGpsInfoResult',
        requestSerial: serial,
        keys: latest && typeof latest === 'object' ? Object.keys(latest) : [],
      });
      stepLog('GPS poll', pollTrace[pollTrace.length - 1]);
      if (isGpsInfoReady(latest)) {
        break;
      }
    } catch (err) {
      pollTrace.push({
        stage: 'result-error',
        attempt,
        endpoint: '/control/getGpsInfoResult',
        requestSerial: serial,
        error: err.message,
      });
      stepLog('GPS poll failed', pollTrace[pollTrace.length - 1]);
    }
  }

  return {
    ok: true,
    code: '0',
    message: 'SUCCESS',
    gpsInfo: latest,
    requestSerial: serial,
    pollTrace,
  };
}

function serialiseForInlineScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003C')
    .replace(/>/g, '\\u003E')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function buildStatusHtml(output) {
  const serialisedOutput = serialiseForInlineScript(output);
  const generatedAt = new Date().toISOString();

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BYD Live Status</title>
  <style>
    :root {
      --bg: #eef4f7;
      --surface: #ffffff;
      --ink: #0f2a3b;
      --muted: #5c7385;
      --line: #d6e1e8;
      --accent: #00789f;
      --accent-soft: #e5f4fa;
      --shadow: 0 8px 20px rgba(16, 36, 51, 0.1);
    }
    * {
      box-sizing: border-box;
    }
    html,
    body {
      height: 100%;
    }
    body {
      margin: 0;
      font-family: "Avenir Next", "Segoe UI", "Helvetica Neue", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, #deedf4 0, transparent 32%),
        radial-gradient(circle at bottom right, #f6f2df 0, transparent 30%),
        var(--bg);
      padding: 14px;
    }
    .page {
      max-width: 1400px;
      margin: 0 auto;
      display: grid;
      gap: 12px;
    }
    .topbar {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 12px;
    }
    .topbar h1 {
      margin: 0;
      font-size: 1.38rem;
      line-height: 1.1;
      letter-spacing: 0.02em;
    }
    .subtitle {
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .generated-at {
      color: var(--muted);
      font-size: 0.86rem;
      white-space: nowrap;
    }
    .topbar-right {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .eye-toggle {
      border: 1px solid #c3d8e4;
      background: #ffffff;
      border-radius: 10px;
      width: 36px;
      height: 32px;
      font-size: 1.06rem;
      line-height: 1;
      cursor: pointer;
      box-shadow: 0 4px 10px rgba(20, 41, 59, 0.08);
    }
    .eye-toggle:hover {
      background: #f3f9fc;
    }
    .eye-toggle[aria-pressed="true"] {
      background: #e8f3f9;
      border-color: #9ec4d8;
    }
    .sensitive-value {
      transition: filter 120ms ease;
      display: inline-block;
    }
    .mask-sensitive .sensitive-value {
      filter: blur(0.32em);
      user-select: none;
    }
    .dashboard {
      display: grid;
      grid-template-columns: 1.45fr 1fr;
      gap: 12px;
      align-items: stretch;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: var(--shadow);
    }
    .hero {
      display: grid;
      grid-template-columns: 0.95fr 1.05fr;
      min-height: 250px;
      overflow: hidden;
    }
    .hero-visual {
      position: relative;
      background: linear-gradient(150deg, #daeaf2, #f4f7f9);
      border-right: 1px solid var(--line);
      min-height: 230px;
    }
    .hero-visual img {
      width: 100%;
      height: 100%;
      object-fit: contain;
      padding: 16px;
      display: none;
    }
    .image-placeholder {
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      color: #6f8595;
      font-size: 0.93rem;
      text-align: center;
      padding: 18px;
    }
    .hero-content {
      padding: 16px;
      display: grid;
      gap: 10px;
      align-content: start;
    }
    .hero-content h2 {
      margin: 0;
      font-size: 1.22rem;
      line-height: 1.2;
    }
    .hero-subtitle {
      margin: 0;
      color: var(--muted);
      font-size: 0.91rem;
    }
    .badge-row {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
    }
    .badge {
      background: var(--accent-soft);
      color: #0f3b52;
      border: 1px solid #c7dce6;
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 0.78rem;
      line-height: 1.2;
      white-space: nowrap;
    }
    .metrics {
      padding: 14px;
      display: grid;
      grid-template-rows: auto 1fr;
      min-height: 250px;
    }
    .metrics h3 {
      margin: 0 0 10px;
      font-size: 0.96rem;
      color: #184157;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      align-content: start;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 9px 10px;
      background: #f9fbfc;
      display: grid;
      gap: 3px;
      min-height: 56px;
    }
    .metric-label {
      color: #5a7283;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      line-height: 1.2;
    }
    .metric-value {
      font-size: 0.94rem;
      font-weight: 700;
      line-height: 1.2;
    }
    .detail-grid {
      grid-column: 1 / -1;
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .compact {
      padding: 12px;
      min-height: 180px;
    }
    .compact h3 {
      margin: 0 0 8px;
      font-size: 0.9rem;
      color: #184157;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .kv {
      display: grid;
      gap: 6px;
      align-content: start;
    }
    .kv-row {
      display: grid;
      grid-template-columns: 1fr auto;
      align-items: center;
      gap: 8px;
      padding: 5px 0;
      border-bottom: 1px dashed #deeaef;
      font-size: 0.84rem;
      line-height: 1.2;
    }
    .kv-row:last-child {
      border-bottom: 0;
    }
    .kv-row span {
      color: #5a7283;
    }
    .kv-row strong {
      font-size: 0.86rem;
      text-align: right;
      max-width: 220px;
      word-break: break-word;
    }
    .raw {
      padding: 12px;
    }
    details {
      border: 1px solid var(--line);
      border-radius: 10px;
      margin-bottom: 8px;
      background: #f7fafc;
    }
    details:last-child {
      margin-bottom: 0;
    }
    summary {
      cursor: pointer;
      list-style: none;
      padding: 9px 11px;
      font-weight: 600;
      font-size: 0.84rem;
      color: #184157;
    }
    summary::-webkit-details-marker {
      display: none;
    }
    pre {
      margin: 0;
      padding: 10px 11px 12px;
      border-top: 1px solid var(--line);
      overflow-x: auto;
      white-space: pre;
      font-size: 0.72rem;
      line-height: 1.35;
      color: #223f53;
      background: #fdfefe;
    }
    .empty {
      color: #708799;
      font-size: 0.84rem;
      padding: 5px 0;
    }
    @media (max-width: 1100px) {
      .dashboard {
        grid-template-columns: 1fr;
      }
      .detail-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .hero {
        grid-template-columns: 1fr;
      }
      .hero-visual {
        border-right: 0;
        border-bottom: 1px solid var(--line);
        min-height: 210px;
      }
    }
    @media (max-width: 760px) {
      body {
        padding: 10px;
      }
      .topbar {
        flex-direction: column;
        align-items: flex-start;
      }
      .topbar-right {
        width: 100%;
        justify-content: space-between;
      }
      .detail-grid {
        grid-template-columns: 1fr;
      }
      .metric-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="page">
    <header class="topbar">
      <div>
        <h1>BYD Live Status</h1>
        <p class="subtitle">Snapshot generated by client.js from current API state.</p>
      </div>
      <div class="topbar-right">
        <button id="sensitivity-toggle" class="eye-toggle" type="button" aria-label="Toggle sensitive blur" title="Blur sensitive values" aria-pressed="false">👀</button>
        <div class="generated-at" id="generated-at">-</div>
      </div>
    </header>

    <main class="dashboard">
      <section class="card hero">
        <div class="hero-visual">
          <img id="car-image" alt="Vehicle image">
          <div class="image-placeholder" id="car-image-placeholder">No vehicle image URL in current payload.</div>
        </div>
        <div class="hero-content">
          <h2 id="car-name">Vehicle</h2>
          <p class="hero-subtitle" id="car-subtitle">-</p>
          <div class="badge-row" id="identity-badges"></div>
        </div>
      </section>

      <section class="card metrics">
        <h3>Live Status</h3>
        <div class="metric-grid" id="summary-metrics"></div>
      </section>

      <div class="detail-grid">
        <section class="card compact">
          <h3>Doors / Locks / Windows</h3>
          <div class="kv" id="doors-content"></div>
        </section>
        <section class="card compact">
          <h3>Tires / Charge</h3>
          <div class="kv" id="tires-content"></div>
        </section>
        <section class="card compact">
          <h3>GPS / Polling</h3>
          <div class="kv" id="gps-content"></div>
        </section>
      </div>
    </main>

    <section class="card raw">
      <details>
        <summary>Full output JSON</summary>
        <pre id="raw-output"></pre>
      </details>
      <details>
        <summary>vehicleInfo JSON</summary>
        <pre id="raw-vehicle"></pre>
      </details>
      <details>
        <summary>gpsInfo JSON</summary>
        <pre id="raw-gps"></pre>
      </details>
    </section>
  </div>

  <script>
    (function () {
      var data = ${serialisedOutput};
      var generatedAt = ${JSON.stringify(generatedAt)};

      function isObject(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
      }

      function nonEmpty(value) {
        return value !== undefined && value !== null && String(value).trim() !== '';
      }

      function firstDefined(values) {
        for (var i = 0; i < values.length; i += 1) {
          if (nonEmpty(values[i])) {
            return values[i];
          }
        }
        return '';
      }

      function firstString(values) {
        for (var i = 0; i < values.length; i += 1) {
          if (typeof values[i] === 'string' && values[i].trim()) {
            return values[i].trim();
          }
        }
        return '';
      }

      function pick(obj, keys) {
        if (!isObject(obj)) {
          return '';
        }
        for (var i = 0; i < keys.length; i += 1) {
          var key = keys[i];
          if (Object.prototype.hasOwnProperty.call(obj, key) && nonEmpty(obj[key])) {
            return obj[key];
          }
        }
        return '';
      }

      function asNumber(value) {
        if (value === undefined || value === null) {
          return null;
        }
        if (typeof value === 'string' && value.trim() === '') {
          return null;
        }
        var num = Number(value);
        if (Number.isFinite(num)) {
          return num;
        }
        return null;
      }

      function formatValue(value) {
        if (!nonEmpty(value)) {
          return '-';
        }
        if (typeof value === 'boolean') {
          return value ? 'true' : 'false';
        }
        if (typeof value === 'number') {
          if (Number.isInteger(value)) {
            return String(value);
          }
          return value.toFixed(1);
        }
        if (typeof value === 'string') {
          return value;
        }
        return JSON.stringify(value);
      }

      function formatTimestamp(value) {
        var num = asNumber(value);
        if (num === null) {
          return formatValue(value);
        }
        if (num > 1000000000) {
          var ms = num > 9999999999 ? num : num * 1000;
          var date = new Date(ms);
          if (!Number.isNaN(date.getTime())) {
            return date.toLocaleString();
          }
        }
        return formatValue(value);
      }

      function formatDistance(value) {
        var num = asNumber(value);
        if (num === null) {
          return formatValue(value);
        }
        return Number.isInteger(num) ? String(num) + ' km' : num.toFixed(1) + ' km';
      }

      function formatPercent(value) {
        var num = asNumber(value);
        if (num === null) {
          return formatValue(value);
        }
        return Number.isInteger(num) ? String(num) + '%' : num.toFixed(1) + '%';
      }

      function formatTemp(value) {
        var num = asNumber(value);
        if (num === null) {
          return formatValue(value);
        }
        return Number.isInteger(num) ? String(num) + '°C' : num.toFixed(1) + '°C';
      }

      function formatSpeed(value) {
        var num = asNumber(value);
        if (num === null) {
          return formatValue(value);
        }
        return Number.isInteger(num) ? String(num) + ' km/h' : num.toFixed(1) + ' km/h';
      }

      function mapOnlineState(value) {
        var num = asNumber(value);
        if (num === 1) {
          return 'online';
        }
        if (num === 2) {
          return 'offline';
        }
        if (num === 0) {
          return 'unknown';
        }
        return formatValue(value);
      }

      function escapeHtml(text) {
        return String(text)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }

      function setText(id, value) {
        var el = document.getElementById(id);
        if (!el) {
          return;
        }
        el.textContent = nonEmpty(value) ? String(value) : '-';
      }

      function formatDisplayValue(value, sensitive) {
        var text = escapeHtml(formatValue(value));
        if (!sensitive) {
          return text;
        }
        return '<span class="sensitive-value">' + text + '</span>';
      }

      function renderBadgeRow(id, badges) {
        var el = document.getElementById(id);
        if (!el) {
          return;
        }
        var html = '';
        for (var i = 0; i < badges.length; i += 1) {
          var badge = badges[i];
          if (!badge || !nonEmpty(badge[1])) {
            continue;
          }
          html += '<span class="badge">' + escapeHtml(badge[0]) + ': ' + formatDisplayValue(badge[1], Boolean(badge[2])) + '</span>';
        }
        el.innerHTML = html || '<span class="badge">No identity details</span>';
      }

      function renderMetrics(id, metrics) {
        var el = document.getElementById(id);
        if (!el) {
          return;
        }
        var html = '';
        for (var i = 0; i < metrics.length; i += 1) {
          var item = metrics[i];
          if (!item || !nonEmpty(item[1])) {
            continue;
          }
          html += '<article class="metric">';
          html += '<span class="metric-label">' + escapeHtml(item[0]) + '</span>';
          html += '<strong class="metric-value">' + escapeHtml(formatValue(item[1])) + '</strong>';
          html += '</article>';
        }
        el.innerHTML = html || '<div class="empty">No live metrics available.</div>';
      }

      function renderRows(id, rows) {
        var el = document.getElementById(id);
        if (!el) {
          return;
        }
        var html = '';
        for (var i = 0; i < rows.length; i += 1) {
          var row = rows[i];
          if (!row || !nonEmpty(row[1])) {
            continue;
          }
          html += '<div class="kv-row">';
          html += '<span>' + escapeHtml(row[0]) + '</span>';
          html += '<strong>' + formatDisplayValue(row[1], Boolean(row[2])) + '</strong>';
          html += '</div>';
        }
        el.innerHTML = html || '<div class="empty">No data.</div>';
      }

      function stringifyPretty(value) {
        try {
          return JSON.stringify(value, null, 2);
        } catch (err) {
          return String(value);
        }
      }

      var vehicles = Array.isArray(data.vehicles) ? data.vehicles : [];
      var targetVin = nonEmpty(data.vin) ? String(data.vin) : '';
      var primaryVehicle = null;

      for (var i = 0; i < vehicles.length; i += 1) {
        var vehicle = vehicles[i];
        if (isObject(vehicle) && String(vehicle.vin || '') === targetVin) {
          primaryVehicle = vehicle;
          break;
        }
      }

      if (!isObject(primaryVehicle)) {
        primaryVehicle = isObject(vehicles[0]) ? vehicles[0] : {};
      }

      var vehicleInfo = isObject(data.vehicleInfo) ? data.vehicleInfo : {};
      var gpsWrap = isObject(data.gps) ? data.gps : {};
      var gpsInfo = isObject(gpsWrap.gpsInfo) ? gpsWrap.gpsInfo : {};
      var gpsData = isObject(gpsInfo.data) ? gpsInfo.data : gpsInfo;
      var realtimePoll = Array.isArray(data.realtimePoll) ? data.realtimePoll : [];
      var gpsPoll = Array.isArray(gpsWrap.pollTrace) ? gpsWrap.pollTrace : [];

      var carImageUrl = firstString([
        pick(primaryVehicle, ['picMainUrl', 'picSetUrl']),
        pick(primaryVehicle.cfPic, ['picMainUrl', 'picSetUrl']),
        pick(vehicleInfo, ['picMainUrl', 'picSetUrl']),
        pick(vehicleInfo.cfPic, ['picMainUrl', 'picSetUrl']),
      ]);

      var carName = firstString([
        pick(primaryVehicle, ['modelName', 'outModelType', 'autoAlias']),
        pick(vehicleInfo, ['modelName']),
      ]) || 'BYD Vehicle';

      var mileageSummary = firstDefined([
        asNumber(pick(vehicleInfo, ['totalMileageV2'])) > 0 ? pick(vehicleInfo, ['totalMileageV2']) : '',
        asNumber(pick(vehicleInfo, ['totalMileage'])) > 0 ? pick(vehicleInfo, ['totalMileage']) : '',
        asNumber(pick(primaryVehicle, ['totalMileage'])) > 0 ? pick(primaryVehicle, ['totalMileage']) : '',
      ]);

      setText('generated-at', 'Generated: ' + new Date(generatedAt).toLocaleString());
      setText('car-name', carName);

      var brandName = pick(primaryVehicle, ['brandName']);
      var plate = pick(primaryVehicle, ['autoPlate']);
      var subtitleElement = document.getElementById('car-subtitle');
      if (subtitleElement) {
        var subtitleParts = [];
        if (nonEmpty(brandName)) {
          subtitleParts.push(escapeHtml(String(brandName)));
        }
        if (nonEmpty(plate)) {
          subtitleParts.push('<span class="sensitive-value">' + escapeHtml(String(plate)) + '</span>');
        }
        if (targetVin) {
          subtitleParts.push('<span class="sensitive-value">' + escapeHtml(targetVin) + '</span>');
        }
        subtitleElement.innerHTML = subtitleParts.length ? subtitleParts.join(' · ') : '-';
      }

      renderBadgeRow('identity-badges', [
        ['User ID', data.userId, true],
        ['VIN', targetVin, true],
        ['Plate', plate, true],
        ['Model', pick(primaryVehicle, ['modelName', 'outModelType'])],
        ['Alias', pick(primaryVehicle, ['autoAlias'])],
        ['Energy type', pick(primaryVehicle, ['energyType'])],
        ['Vehicle state', pick(vehicleInfo, ['vehicleState'])],
      ]);

      var imageElement = document.getElementById('car-image');
      var placeholderElement = document.getElementById('car-image-placeholder');
      if (imageElement && placeholderElement) {
        if (carImageUrl) {
          imageElement.src = carImageUrl;
          imageElement.style.display = 'block';
          placeholderElement.style.display = 'none';
        } else {
          imageElement.style.display = 'none';
          placeholderElement.style.display = 'grid';
        }
      }

      var summaryMetrics = [
        ['Online', mapOnlineState(pick(vehicleInfo, ['onlineState']))],
        ['Connect state', pick(vehicleInfo, ['connectState'])],
        ['Battery', formatPercent(firstDefined([
          pick(vehicleInfo, ['elecPercent']),
          pick(vehicleInfo, ['powerBattery']),
        ]))],
        ['Range', formatDistance(firstDefined([
          pick(vehicleInfo, ['enduranceMileage']),
          pick(vehicleInfo, ['evEndurance']),
        ]))],
        ['Charge state', pick(vehicleInfo, ['chargingState', 'chargeState'])],
        ['Total power', pick(vehicleInfo, ['totalPower'])],
        ['Inside temp', formatTemp(pick(vehicleInfo, ['tempInCar']))],
        ['Speed', formatSpeed(pick(vehicleInfo, ['speed']))],
        ['Mileage', formatDistance(mileageSummary)],
        ['Realtime timestamp', formatTimestamp(pick(vehicleInfo, ['time']))],
        ['GPS status', gpsWrap.ok ? 'ok' : (gpsWrap.message || 'unavailable')],
        ['Realtime poll entries', realtimePoll.length],
      ];
      renderMetrics('summary-metrics', summaryMetrics);

      var doorRows = [
        ['Left front door', pick(vehicleInfo, ['leftFrontDoor'])],
        ['Right front door', pick(vehicleInfo, ['rightFrontDoor'])],
        ['Left rear door', pick(vehicleInfo, ['leftRearDoor'])],
        ['Right rear door', pick(vehicleInfo, ['rightRearDoor'])],
        ['Trunk lid', pick(vehicleInfo, ['trunkLid'])],
        ['Left front lock', pick(vehicleInfo, ['leftFrontDoorLock'])],
        ['Right front lock', pick(vehicleInfo, ['rightFrontDoorLock'])],
        ['Left rear lock', pick(vehicleInfo, ['leftRearDoorLock'])],
        ['Right rear lock', pick(vehicleInfo, ['rightRearDoorLock'])],
        ['Left front window', pick(vehicleInfo, ['leftFrontWindow'])],
        ['Right front window', pick(vehicleInfo, ['rightFrontWindow'])],
        ['Left rear window', pick(vehicleInfo, ['leftRearWindow'])],
        ['Right rear window', pick(vehicleInfo, ['rightRearWindow'])],
        ['Skylight', pick(vehicleInfo, ['skylight'])],
      ];
      renderRows('doors-content', doorRows);

      var chargeHour = pick(vehicleInfo, ['remainingHours']);
      var chargeMinute = pick(vehicleInfo, ['remainingMinutes']);
      var chargeEta = '';
      if (nonEmpty(chargeHour) || nonEmpty(chargeMinute)) {
        chargeEta = String(nonEmpty(chargeHour) ? chargeHour : '0') + 'h ' + String(nonEmpty(chargeMinute) ? chargeMinute : '0') + 'm';
      }

      var tireRows = [
        ['Left front tire', pick(vehicleInfo, ['leftFrontTirepressure'])],
        ['Right front tire', pick(vehicleInfo, ['rightFrontTirepressure'])],
        ['Left rear tire', pick(vehicleInfo, ['leftRearTirepressure'])],
        ['Right rear tire', pick(vehicleInfo, ['rightRearTirepressure'])],
        ['Tire unit code', pick(vehicleInfo, ['tirePressUnit'])],
        ['Total energy', pick(vehicleInfo, ['totalEnergy'])],
        ['Nearest consumption', pick(vehicleInfo, ['nearestEnergyConsumption'])],
        ['Recent 50km energy', pick(vehicleInfo, ['recent50kmEnergy'])],
        ['Charge ETA', chargeEta],
      ];
      renderRows('tires-content', tireRows);

      var gpsTimeValue = firstDefined([
        pick(gpsData, ['gpsTimeStamp', 'gpsTimestamp', 'gpsTime', 'time', 'uploadTime']),
        pick(gpsInfo, ['gpsTimeStamp', 'gpsTimestamp', 'gpsTime', 'time', 'uploadTime']),
      ]);
      var latitudeValue = pick(gpsData, ['latitude', 'lat', 'gpsLatitude']);
      var longitudeValue = pick(gpsData, ['longitude', 'lng', 'lon', 'gpsLongitude']);
      var latitudeDisplay = nonEmpty(latitudeValue) ? String(latitudeValue) : '';
      var longitudeDisplay = nonEmpty(longitudeValue) ? String(longitudeValue) : '';
      var gpsRows = [
        ['Latitude', latitudeDisplay, true],
        ['Longitude', longitudeDisplay, true],
        ['Direction', pick(gpsData, ['direction', 'heading', 'course'])],
        ['GPS speed', formatSpeed(pick(gpsData, ['speed', 'gpsSpeed']))],
        ['GPS time', formatTimestamp(gpsTimeValue)],
        ['GPS result', firstDefined([pick(gpsInfo, ['res']), gpsWrap.message])],
        ['GPS polls', gpsPoll.length],
      ];
      renderRows('gps-content', gpsRows);

      var sensitiveMaskEnabled = false;
      var sensitivityToggle = document.getElementById('sensitivity-toggle');
      function applySensitiveMask() {
        document.body.classList.toggle('mask-sensitive', sensitiveMaskEnabled);
        if (!sensitivityToggle) {
          return;
        }
        sensitivityToggle.setAttribute('aria-pressed', sensitiveMaskEnabled ? 'true' : 'false');
        sensitivityToggle.title = sensitiveMaskEnabled ? 'Show sensitive values' : 'Blur sensitive values';
      }
      if (sensitivityToggle) {
        sensitivityToggle.addEventListener('click', function () {
          sensitiveMaskEnabled = !sensitiveMaskEnabled;
          applySensitiveMask();
        });
      }
      applySensitiveMask();

      var rawOutput = document.getElementById('raw-output');
      if (rawOutput) {
        rawOutput.textContent = stringifyPretty(data);
      }
      var rawVehicle = document.getElementById('raw-vehicle');
      if (rawVehicle) {
        rawVehicle.textContent = stringifyPretty(vehicleInfo);
      }
      var rawGps = document.getElementById('raw-gps');
      if (rawGps) {
        rawGps.textContent = stringifyPretty(gpsInfo);
      }
    }());
  </script>
</body>
</html>
`;
}

function writeStatusHtml(output, filePath = 'status.html') {
  const html = buildStatusHtml(output);
  fs.writeFileSync(filePath, html, 'utf8');
}

async function main() {
  if (!CONFIG.username || !CONFIG.password) {
    throw new Error('Set BYD_USERNAME and BYD_PASSWORD');
  }

  stepLog('Starting login flow', {
    user: CONFIG.username,
    countryCode: CONFIG.countryCode,
    language: CONFIG.language,
  });

  const loginReq = buildLoginRequest(Date.now());
  const loginOuter = await postSecure('/app/account/login', loginReq.outer);
  if (String(loginOuter.code) !== '0') {
    throw new Error(`Login failed: code=${loginOuter.code} message=${loginOuter.message || ''}`.trim());
  }

  const loginKey = pwdLoginKey(CONFIG.password);
  const loginInner = decryptRespondDataJson(loginOuter.respondData, loginKey);
  const token = loginInner && loginInner.token ? loginInner.token : null;
  const userId = token && token.userId ? String(token.userId) : '';
  const signToken = token && token.signToken ? String(token.signToken) : '';
  const encryToken = token && token.encryToken ? String(token.encryToken) : '';

  if (!userId || !signToken || !encryToken) {
    throw new Error('Login response missing token fields');
  }

  stepLog('Login succeeded', {
    userId,
    hasSignToken: Boolean(signToken),
    hasEncryToken: Boolean(encryToken),
  });

  const session = { userId, signToken, encryToken };

  const listReq = buildListRequest(Date.now(), session);
  const listOuter = await postSecure('/app/account/getAllListByUserId', listReq.outer);
  if (String(listOuter.code) !== '0') {
    throw new Error(`Vehicle list failed: code=${listOuter.code} message=${listOuter.message || ''}`.trim());
  }

  const vehicles = decryptRespondDataJson(listOuter.respondData, listReq.contentKey);
  stepLog('Vehicle list succeeded', {
    vehicleCount: Array.isArray(vehicles) ? vehicles.length : 0,
    vehicles,
  });
  const resolvedVin = CONFIG.vin
    || (Array.isArray(vehicles) && vehicles.length && vehicles[0] && vehicles[0].vin ? String(vehicles[0].vin) : '');
  if (!resolvedVin) {
    throw new Error('Could not resolve VIN (set BYD_VIN or ensure vehicle list contains vin)');
  }

  const realtime = await pollVehicleRealtime(session, resolvedVin);
  const vehicleInfo = realtime.vehicleInfo;
  if (!vehicleInfo) {
    throw new Error('Vehicle realtime poll returned no data');
  }
  stepLog('Vehicle realtime succeeded', {
    vin: resolvedVin,
    onlineState: vehicleInfo && vehicleInfo.onlineState,
    vehicleState: vehicleInfo && vehicleInfo.vehicleState,
    requestSerial: realtime.requestSerial,
  });

  const gpsResult = await pollGpsInfo(session, resolvedVin);
  if (gpsResult.ok) {
    stepLog('GPS info succeeded', {
      vin: resolvedVin,
      requestSerial: gpsResult.requestSerial,
      gps: gpsResult.gpsInfo,
    });
  } else {
    stepLog('GPS info unavailable', {
      vin: resolvedVin,
      code: gpsResult.code,
      message: gpsResult.message,
    });
  }

  const output = {
    userId,
    vin: resolvedVin,
    token: {
      signToken,
      encryToken,
    },
    vehicles,
    realtimePoll: realtime.pollTrace,
    vehicleInfo,
    gps: gpsResult,
  };

  writeStatusHtml(output, 'status.html');
  stepLog('Wrote status HTML', { file: 'status.html' });

  console.log(util.inspect(JSON.parse(JSON.stringify(output)), {
    depth: null,
    colors: true,
    maxArrayLength: null,
    compact: false,
  }));
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
