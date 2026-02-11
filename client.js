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
  // See: https://apkpure.com/byd/com.byd.bydautolink
  appInnerVersion: process.env.BYD_APP_INNER_VERSION || '323',
  appVersion: process.env.BYD_APP_VERSION || '3.2.3',
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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #ebf1f3;
      --bg-accent: #d3e2e8;
      --surface: rgba(255, 255, 255, 0.9);
      --surface-strong: rgba(255, 255, 255, 0.97);
      --ink: #0f2530;
      --muted: #5b727e;
      --line: #c9d8df;
      --accent: #007da0;
      --accent-soft: #e6f4f8;
      --ok: #1f8c63;
      --warn: #b57a12;
      --bad: #b14137;
      --neutral: #4a6778;
      --shadow: 0 16px 36px rgba(18, 42, 55, 0.14);
    }
    * {
      box-sizing: border-box;
    }
    html,
    body {
      min-height: 100%;
    }
    body {
      margin: 0;
      font-family: "Space Grotesk", "Avenir Next", "Helvetica Neue", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 12% 0, var(--bg-accent) 0, transparent 35%),
        radial-gradient(circle at 92% 0, #efe3cc 0, transparent 30%),
        linear-gradient(145deg, #f7fafb 0%, var(--bg) 55%, #e4edf0 100%);
      padding: 14px 14px 20px;
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(4, 53, 77, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(4, 53, 77, 0.04) 1px, transparent 1px);
      background-size: 42px 42px;
      mask-image: radial-gradient(circle at 50% 30%, #000 25%, transparent 70%);
      opacity: 0.35;
      z-index: 0;
    }
    .page {
      max-width: 1460px;
      margin: 0 auto;
      display: grid;
      gap: 14px;
      position: relative;
      z-index: 1;
    }
    .page > * {
      opacity: 0;
      transform: translateY(12px);
      animation: reveal 420ms ease forwards;
    }
    .page > *:nth-child(2) { animation-delay: 70ms; }
    .page > *:nth-child(3) { animation-delay: 120ms; }
    .page > *:nth-child(4) { animation-delay: 170ms; }
    .page > *:nth-child(5) { animation-delay: 220ms; }
    .page > *:nth-child(6) { animation-delay: 270ms; }
    .page > *:nth-child(7) { animation-delay: 320ms; }
    @keyframes reveal {
      from {
        opacity: 0;
        transform: translateY(12px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(4px);
    }
    .card-pad {
      padding: 14px;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      background:
        linear-gradient(130deg, rgba(7, 130, 166, 0.1), transparent 45%),
        var(--surface-strong);
    }
    .kicker {
      margin: 0 0 6px;
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.11em;
      font-size: 0.72rem;
      font-weight: 700;
    }
    .topbar h1 {
      margin: 0;
      font-size: 1.52rem;
      line-height: 1.1;
      letter-spacing: 0.01em;
    }
    .subtitle {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 0.89rem;
    }
    .topbar-right {
      display: grid;
      justify-items: end;
      gap: 8px;
    }
    .generated-at {
      color: var(--muted);
      font-size: 0.86rem;
      text-align: right;
      max-width: 260px;
    }
    .eye-toggle {
      border: 1px solid #a9c4d2;
      background: linear-gradient(180deg, #fefefe, #eef7fb);
      border-radius: 999px;
      padding: 8px 12px;
      font-family: inherit;
      font-size: 0.81rem;
      font-weight: 600;
      letter-spacing: 0.01em;
      color: #13455c;
      white-space: nowrap;
      cursor: pointer;
      box-shadow: 0 4px 12px rgba(18, 53, 70, 0.15);
      transition: transform 120ms ease, box-shadow 120ms ease, border-color 120ms ease;
    }
    .eye-toggle:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 14px rgba(18, 53, 70, 0.17);
    }
    .eye-toggle[aria-pressed="true"] {
      background: linear-gradient(180deg, #f0f6fa, #e2edf3);
      border-color: #88a7b8;
      color: #3f5764;
    }
    .sensitive-value {
      transition: filter 120ms ease;
      display: inline-block;
    }
    .mask-sensitive .sensitive-value {
      filter: blur(0.35em);
      user-select: none;
      pointer-events: none;
    }
    .quick-nav {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .quick-nav a {
      color: #0f3f56;
      text-decoration: none;
      border: 1px solid #c4d6df;
      background: #f9fcfd;
      border-radius: 999px;
      font-size: 0.79rem;
      padding: 6px 12px;
      font-weight: 600;
      transition: background-color 120ms ease, border-color 120ms ease, transform 120ms ease;
    }
    .quick-nav a:hover {
      background: #ecf5f8;
      border-color: #98b8c8;
      transform: translateY(-1px);
    }
    .status-strip {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 10px;
    }
    .status-chip {
      border-radius: 15px;
      border: 1px solid var(--line);
      padding: 10px 11px;
      background: var(--surface-strong);
      box-shadow: 0 8px 18px rgba(16, 38, 53, 0.1);
      display: grid;
      gap: 4px;
    }
    .status-label {
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: #3f6173;
      font-weight: 700;
    }
    .status-value {
      font-size: 1rem;
      line-height: 1.25;
      font-weight: 700;
    }
    .status-detail {
      color: #516d7c;
      font-size: 0.77rem;
      line-height: 1.28;
      min-height: 1.1em;
    }
    .tone-ok {
      border-color: rgba(31, 140, 99, 0.35);
      background: linear-gradient(150deg, rgba(217, 244, 233, 0.82), rgba(255, 255, 255, 0.95));
    }
    .tone-warn {
      border-color: rgba(181, 122, 18, 0.32);
      background: linear-gradient(150deg, rgba(251, 239, 218, 0.84), rgba(255, 255, 255, 0.95));
    }
    .tone-bad {
      border-color: rgba(177, 65, 55, 0.36);
      background: linear-gradient(150deg, rgba(253, 227, 222, 0.82), rgba(255, 255, 255, 0.95));
    }
    .tone-neutral {
      border-color: rgba(74, 103, 120, 0.3);
      background: linear-gradient(150deg, rgba(231, 240, 245, 0.86), rgba(255, 255, 255, 0.96));
    }
    .primary-grid {
      display: grid;
      grid-template-columns: 1.35fr 1fr;
      gap: 14px;
    }
    .hero {
      display: grid;
      grid-template-columns: 0.95fr 1.05fr;
      min-height: 290px;
      overflow: hidden;
    }
    .hero-visual {
      position: relative;
      background:
        radial-gradient(circle at 18% 30%, rgba(24, 157, 190, 0.16), transparent 45%),
        linear-gradient(145deg, #d8e9f0, #edf4f7);
      border-right: 1px solid var(--line);
      min-height: 260px;
    }
    .hero-visual img {
      width: 100%;
      height: 100%;
      object-fit: contain;
      padding: 18px;
      display: none;
      filter: drop-shadow(0 12px 16px rgba(15, 39, 51, 0.25));
    }
    .image-placeholder {
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      color: #4f6d7d;
      font-size: 0.93rem;
      text-align: center;
      padding: 24px;
    }
    .hero-content {
      padding: 16px 16px 15px;
      display: grid;
      gap: 11px;
      align-content: start;
    }
    .hero-content h2 {
      margin: 0;
      font-size: 1.34rem;
      line-height: 1.2;
    }
    .hero-subtitle {
      margin: 0;
      color: var(--muted);
      font-size: 0.9rem;
      line-height: 1.35;
    }
    .badge-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-content: start;
    }
    .badge {
      background: linear-gradient(180deg, var(--accent-soft), #f6fbfd);
      color: #0f3a50;
      border: 1px solid #bfd8e4;
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 0.77rem;
      line-height: 1.2;
      white-space: normal;
      max-width: 100%;
    }
    .section-title {
      margin: 0 0 10px;
      font-size: 0.87rem;
      color: #184157;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
    }
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 9px;
      align-content: start;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      background: #f8fbfd;
      display: grid;
      gap: 4px;
      min-height: 62px;
    }
    .metric-label {
      color: #4f6978;
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      line-height: 1.2;
    }
    .metric-value {
      font-size: 0.95rem;
      font-weight: 700;
      line-height: 1.28;
      word-break: break-word;
    }
    .secondary-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }
    .detail-grid {
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(2, minmax(0, 1fr));
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
      padding: 6px 0;
      border-bottom: 1px dashed #d8e4eb;
      font-size: 0.82rem;
      line-height: 1.2;
    }
    .kv-row:last-child {
      border-bottom: 0;
    }
    .kv-row span {
      color: #516b7a;
    }
    .kv-row strong {
      font-size: 0.86rem;
      text-align: right;
      max-width: 250px;
      word-break: break-word;
      font-weight: 700;
    }
    .link-list {
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .map-link {
      text-decoration: none;
      color: #0f3f55;
      border: 1px solid #b9d0dc;
      border-radius: 999px;
      padding: 5px 11px;
      font-size: 0.77rem;
      font-weight: 600;
      background: linear-gradient(180deg, #f7fbfd, #eef6fa);
      transition: border-color 120ms ease, background-color 120ms ease;
    }
    .map-link:hover {
      border-color: #7eabbf;
      background: #e9f3f8;
    }
    .raw {
      background: var(--surface-strong);
    }
    details {
      border: 1px solid var(--line);
      border-radius: 12px;
      margin-bottom: 9px;
      background: #f7fafc;
    }
    details:last-child {
      margin-bottom: 0;
    }
    summary {
      cursor: pointer;
      list-style: none;
      padding: 10px 12px;
      font-weight: 600;
      font-size: 0.84rem;
      color: #184157;
    }
    summary::-webkit-details-marker {
      display: none;
    }
    pre {
      margin: 0;
      padding: 10px 12px 12px;
      border-top: 1px solid var(--line);
      overflow-x: auto;
      white-space: pre;
      font-size: 0.73rem;
      line-height: 1.35;
      color: #1d3d4f;
      background: #fdfefe;
      font-family: "JetBrains Mono", "Menlo", "Consolas", monospace;
    }
    .empty {
      color: #708799;
      font-size: 0.82rem;
      padding: 6px 0;
    }
    @media (max-width: 1220px) {
      .status-strip {
        grid-template-columns: repeat(3, minmax(0, 1fr));
      }
      .primary-grid {
        grid-template-columns: 1fr;
      }
      .secondary-grid,
      .detail-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .hero {
        grid-template-columns: 1fr;
      }
      .hero-visual {
        border-right: 0;
        border-bottom: 1px solid var(--line);
        min-height: 230px;
      }
    }
    @media (max-width: 860px) {
      .status-strip,
      .secondary-grid,
      .detail-grid {
        grid-template-columns: 1fr;
      }
      .kv-row {
        grid-template-columns: minmax(0, 1fr);
        gap: 4px;
      }
      .kv-row strong {
        text-align: left;
      }
      .topbar-right {
        justify-items: start;
      }
      .generated-at {
        text-align: left;
      }
    }
    @media (max-width: 680px) {
      body {
        padding: 10px;
      }
      .topbar {
        flex-direction: column;
        align-items: flex-start;
      }
      .topbar-right {
        width: 100%;
        grid-template-columns: 1fr;
      }
      .metric-grid {
        grid-template-columns: 1fr;
      }
      .quick-nav {
        gap: 7px;
      }
      .quick-nav a {
        padding: 6px 10px;
      }
      .status-value {
        font-size: 0.95rem;
      }
    }
  </style>
</head>
<body>
  <div class="page">
    <header class="card card-pad topbar" id="top">
      <div>
        <p class="kicker">BYD Telemetry Snapshot</p>
        <h1>Vehicle Live Status</h1>
        <p class="subtitle">Snapshot generated by client.js from current API responses.</p>
      </div>
      <div class="topbar-right">
        <button id="sensitivity-toggle" class="eye-toggle" type="button" aria-label="Toggle sensitive blur" title="Blur sensitive values" aria-pressed="false">Sensitive: visible</button>
        <div class="generated-at" id="generated-at">-</div>
      </div>
    </header>

    <nav class="card card-pad quick-nav" aria-label="Quick navigation">
      <a href="#summary">Summary</a>
      <a href="#highlights">Highlights</a>
      <a href="#location">Location</a>
      <a href="#timeline">Timeline</a>
      <a href="#details">Details</a>
      <a href="#raw">Raw JSON</a>
    </nav>

    <section class="status-strip" id="status-strip"></section>

    <main class="primary-grid">
      <section class="card hero" id="summary">
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

      <section class="card card-pad" id="highlights">
        <h3 class="section-title">Vehicle Highlights</h3>
        <div class="metric-grid" id="summary-metrics"></div>
      </section>
    </main>

    <section class="secondary-grid">
      <section class="card card-pad" id="location">
        <h3 class="section-title">Location</h3>
        <div class="kv" id="location-content"></div>
        <div class="link-list" id="map-links"></div>
      </section>

      <section class="card card-pad" id="timeline">
        <h3 class="section-title">Data Timeline</h3>
        <div class="kv" id="timeline-content"></div>
      </section>
    </section>

    <section class="detail-grid" id="details">
        <section class="card card-pad">
          <h3 class="section-title">Doors / Locks / Windows</h3>
          <div class="kv" id="doors-content"></div>
        </section>
        <section class="card card-pad">
          <h3 class="section-title">Tires / Charge</h3>
          <div class="kv" id="tires-content"></div>
        </section>
    </section>

    <section class="card card-pad raw" id="raw">
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
        var ms = parseTimestampMs(value);
        if (ms === null) {
          return formatValue(value);
        }
        var date = new Date(ms);
        if (!Number.isNaN(date.getTime())) {
          return date.toLocaleString();
        }
        return formatValue(value);
      }

      function parseTimestampMs(value) {
        if (!nonEmpty(value)) {
          return null;
        }

        if (typeof value === 'string') {
          var text = value.trim();
          if (/^\\d+$/.test(text)) {
            var parsedNum = Number(text);
            if (Number.isFinite(parsedNum)) {
              value = parsedNum;
            }
          } else {
            var parsedDate = Date.parse(text);
            if (!Number.isNaN(parsedDate)) {
              return parsedDate;
            }
            return null;
          }
        }

        var num = asNumber(value);
        if (num === null) {
          return null;
        }
        if (num > 9999999999999) {
          return null;
        }
        if (num > 9999999999) {
          return Math.round(num);
        }
        if (num > 1000000000) {
          return Math.round(num * 1000);
        }
        return null;
      }

      function formatAge(msDiff) {
        if (!Number.isFinite(msDiff)) {
          return 'unknown';
        }
        var future = msDiff < 0;
        var absMs = Math.abs(msDiff);
        var seconds = Math.round(absMs / 1000);
        if (seconds < 5) {
          return future ? 'in a few seconds' : 'just now';
        }
        if (seconds < 60) {
          return future ? ('in ' + seconds + 's') : (seconds + 's ago');
        }
        var minutes = Math.round(seconds / 60);
        if (minutes < 60) {
          return future ? ('in ' + minutes + 'm') : (minutes + 'm ago');
        }
        var hours = Math.round(minutes / 60);
        if (hours < 48) {
          return future ? ('in ' + hours + 'h') : (hours + 'h ago');
        }
        var days = Math.round(hours / 24);
        return future ? ('in ' + days + 'd') : (days + 'd ago');
      }

      function formatDistance(value) {
        var num = asNumber(value);
        if (num === null) {
          return formatValue(value);
        }
        return String(Math.round(num)) + ' km';
      }

      function formatPercent(value) {
        var num = asNumber(value);
        if (num === null) {
          return formatValue(value);
        }
        return String(Math.round(num)) + '%';
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

      function toneForOnline(value) {
        var text = String(value || '').toLowerCase();
        if (text === 'online') {
          return 'ok';
        }
        if (text === 'offline') {
          return 'bad';
        }
        return 'neutral';
      }

      function toneForBattery(value) {
        var num = asNumber(value);
        if (num === null) {
          return 'neutral';
        }
        if (num >= 55) {
          return 'ok';
        }
        if (num >= 25) {
          return 'warn';
        }
        return 'bad';
      }

      function toneForCharging(value) {
        if (!nonEmpty(value)) {
          return 'neutral';
        }
        var text = String(value).trim().toLowerCase();
        if (!text || text === '-' || text === '0' || text === 'idle' || text === 'not charging') {
          return 'neutral';
        }
        if (text.indexOf('error') !== -1 || text.indexOf('fault') !== -1) {
          return 'bad';
        }
        if (text === '1' || text.indexOf('charging') !== -1 || text.indexOf('charge') !== -1) {
          return 'ok';
        }
        return 'warn';
      }

      function mapChargingState(value) {
        var num = asNumber(value);
        if (num === -1 || num === 0) {
          return 'not charging';
        }
        if (num === 1 || num === 2) {
          return 'charging';
        }
        return formatValue(value);
      }

      function mapPowerState(value) {
        var num = asNumber(value);
        if (num === 2) {
          return 'on';
        }
        if (num === 0 || num === 1) {
          return 'off';
        }
        return formatValue(value);
      }

      function mapSentryStatus(value) {
        var num = asNumber(value);
        if (num === 2) {
          return 'unlocked';
        }
        if (num === 0 || num === 1) {
          return 'locked';
        }
        return formatValue(value);
      }

      function mapWindowState(value) {
        var num = asNumber(value);
        if (num === 2) {
          return 'open';
        }
        if (num === 1 || num === 0) {
          return 'closed';
        }
        return formatValue(value);
      }

      function mapAirRunState(value) {
        var num = asNumber(value);
        if (num === 2 || num === 0) {
          return 'off';
        }
        if (num === 1) {
          return 'on';
        }
        return formatValue(value);
      }

      function toneForAge(msDiff) {
        if (!Number.isFinite(msDiff)) {
          return 'neutral';
        }
        if (msDiff < 0) {
          return 'warn';
        }
        if (msDiff <= 5 * 60 * 1000) {
          return 'ok';
        }
        if (msDiff <= 30 * 60 * 1000) {
          return 'warn';
        }
        return 'bad';
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
          html += '<strong class="metric-value">' + formatDisplayValue(item[1], Boolean(item[2])) + '</strong>';
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

      function renderStatusStrip(items) {
        var el = document.getElementById('status-strip');
        if (!el) {
          return;
        }
        var html = '';
        for (var i = 0; i < items.length; i += 1) {
          var item = items[i];
          if (!item || !nonEmpty(item.value)) {
            continue;
          }
          var tone = item.tone === 'ok' || item.tone === 'warn' || item.tone === 'bad' ? item.tone : 'neutral';
          html += '<article class="status-chip tone-' + tone + '">';
          html += '<span class="status-label">' + escapeHtml(item.label) + '</span>';
          html += '<strong class="status-value">' + formatDisplayValue(item.value, Boolean(item.sensitive)) + '</strong>';
          html += '<div class="status-detail">' + escapeHtml(nonEmpty(item.detail) ? String(item.detail) : ' ') + '</div>';
          html += '</article>';
        }
        el.innerHTML = html || '<article class="status-chip tone-neutral"><span class="status-label">Status</span><strong class="status-value">No live data</strong><div class="status-detail">Run client.js again to refresh.</div></article>';
      }

      function renderMapLinks(latitude, longitude) {
        var el = document.getElementById('map-links');
        if (!el) {
          return;
        }
        if (!nonEmpty(latitude) || !nonEmpty(longitude)) {
          el.innerHTML = '<div class="empty">Map links appear when GPS coordinates are available.</div>';
          return;
        }
        var lat = String(latitude).trim();
        var lon = String(longitude).trim();
        var q = encodeURIComponent(lat + ',' + lon);
        var googleUrl = 'https://www.google.com/maps?q=' + q;
        var osmUrl = 'https://www.openstreetmap.org/?mlat=' + encodeURIComponent(lat) + '&mlon=' + encodeURIComponent(lon) + '#map=16/' + encodeURIComponent(lat) + '/' + encodeURIComponent(lon);
        el.innerHTML = ''
          + '<a class="map-link" target="_blank" rel="noopener noreferrer" href="' + googleUrl + '">Open in Google Maps</a>'
          + '<a class="map-link" target="_blank" rel="noopener noreferrer" href="' + osmUrl + '">Open in OpenStreetMap</a>';
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

      var realtimeTimestamp = pick(vehicleInfo, ['time']);
      var realtimeMs = parseTimestampMs(realtimeTimestamp);
      var nowMs = Date.now();

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

      var batteryRaw = firstDefined([
        pick(vehicleInfo, ['elecPercent']),
        pick(vehicleInfo, ['powerBattery']),
      ]);
      var rangeRaw = firstDefined([
        pick(vehicleInfo, ['enduranceMileage']),
        pick(vehicleInfo, ['evEndurance']),
      ]);
      var chargeStateRaw = pick(vehicleInfo, ['chargingState', 'chargeState']);
      var chargeState = mapChargingState(chargeStateRaw);
      var speedRaw = pick(vehicleInfo, ['speed']);
      var connectState = pick(vehicleInfo, ['connectState']);
      var onlineLabel = mapOnlineState(pick(vehicleInfo, ['onlineState']));
      var powerState = mapPowerState(pick(vehicleInfo, ['pwr', 'powerSystem']));
      var sentryState = mapSentryStatus(pick(vehicleInfo, ['sentryStatus']));
      var acState = mapAirRunState(pick(vehicleInfo, ['airRunState']));
      var frontRightWindowState = mapWindowState(pick(vehicleInfo, ['rightFrontWindow']));

      var chargeHour = pick(vehicleInfo, ['remainingHours']);
      var chargeMinute = pick(vehicleInfo, ['remainingMinutes']);
      var chargeEta = '';
      if (nonEmpty(chargeHour) || nonEmpty(chargeMinute)) {
        chargeEta = String(nonEmpty(chargeHour) ? chargeHour : '0') + 'h ' + String(nonEmpty(chargeMinute) ? chargeMinute : '0') + 'm';
      }

      var gpsTimeValue = firstDefined([
        pick(gpsData, ['gpsTimeStamp', 'gpsTimestamp', 'gpsTime', 'time', 'uploadTime']),
        pick(gpsInfo, ['gpsTimeStamp', 'gpsTimestamp', 'gpsTime', 'time', 'uploadTime']),
      ]);
      var gpsMs = parseTimestampMs(gpsTimeValue);
      var freshestMs = Number.isFinite(realtimeMs)
        ? realtimeMs
        : (Number.isFinite(gpsMs) ? gpsMs : null);
      var freshnessDiff = Number.isFinite(freshestMs) ? nowMs - freshestMs : NaN;
      var freshnessSource = Number.isFinite(realtimeMs)
        ? 'Source: vehicle realtime'
        : (Number.isFinite(gpsMs) ? 'Source: GPS feed' : '');

      var gpsSummaryText = gpsWrap.ok ? 'ready' : firstDefined([gpsWrap.message, pick(gpsInfo, ['res']), 'unavailable']);
      var gpsTone = gpsWrap.ok ? 'ok' : (nonEmpty(gpsSummaryText) ? 'warn' : 'bad');

      renderStatusStrip([
        {
          label: 'Connectivity',
          value: onlineLabel,
          detail: nonEmpty(connectState) ? 'Connect state: ' + String(connectState) : '',
          tone: toneForOnline(onlineLabel),
        },
        {
          label: 'Battery',
          value: formatPercent(batteryRaw),
          detail: nonEmpty(rangeRaw) ? ('Range: ' + formatDistance(rangeRaw)) : '',
          tone: toneForBattery(batteryRaw),
        },
        {
          label: 'Charging',
          value: chargeState,
          detail: nonEmpty(chargeEta) ? ('ETA: ' + chargeEta) : 'No ETA reported',
          tone: toneForCharging(chargeState),
        },
        {
          label: 'Cabin AC',
          value: acState,
          detail: 'airRunState=' + formatValue(pick(vehicleInfo, ['airRunState'])),
          tone: acState === 'on' ? 'ok' : 'neutral',
        },
        {
          label: 'Security',
          value: sentryState,
          detail: 'sentryStatus=' + formatValue(pick(vehicleInfo, ['sentryStatus'])),
          tone: sentryState === 'unlocked' ? 'warn' : 'ok',
        },
        {
          label: 'GPS',
          value: gpsSummaryText,
          detail: Number.isFinite(gpsMs) ? ('Timestamp: ' + formatTimestamp(gpsTimeValue)) : '',
          tone: gpsTone,
        },
        {
          label: 'Data Age',
          value: formatAge(freshnessDiff),
          detail: freshnessSource,
          tone: toneForAge(freshnessDiff),
        },
      ]);

      var summaryMetrics = [
        ['Online', onlineLabel],
        ['Connect state', connectState],
        ['Battery', formatPercent(batteryRaw)],
        ['Range', formatDistance(rangeRaw)],
        ['Charge state', chargeState],
        ['Vehicle power', powerState],
        ['Sentry / lock', sentryState],
        ['Front right window', frontRightWindowState],
        ['Cabin AC', acState],
        ['Total power', pick(vehicleInfo, ['totalPower'])],
        ['Inside temp', formatTemp(pick(vehicleInfo, ['tempInCar']))],
        ['Outside temp', formatTemp(pick(vehicleInfo, ['tempOutCar']))],
        ['Speed', formatSpeed(speedRaw)],
        ['Mileage', formatDistance(mileageSummary)],
        ['Realtime timestamp', formatTimestamp(realtimeTimestamp)],
        ['Data age', formatAge(freshnessDiff)],
        ['GPS status', gpsWrap.ok ? 'ok' : (gpsWrap.message || 'unavailable')],
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
        ['Left front window', mapWindowState(pick(vehicleInfo, ['leftFrontWindow']))],
        ['Right front window', frontRightWindowState],
        ['Left rear window', mapWindowState(pick(vehicleInfo, ['leftRearWindow']))],
        ['Right rear window', mapWindowState(pick(vehicleInfo, ['rightRearWindow']))],
        ['Skylight', pick(vehicleInfo, ['skylight'])],
      ];
      renderRows('doors-content', doorRows);

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

      var latitudeValue = pick(gpsData, ['latitude', 'lat', 'gpsLatitude']);
      var longitudeValue = pick(gpsData, ['longitude', 'lng', 'lon', 'gpsLongitude']);
      var latitudeDisplay = nonEmpty(latitudeValue) ? String(latitudeValue) : '';
      var longitudeDisplay = nonEmpty(longitudeValue) ? String(longitudeValue) : '';

      var locationRows = [
        ['Latitude', latitudeDisplay, true],
        ['Longitude', longitudeDisplay, true],
        ['Heading', pick(gpsData, ['direction', 'heading', 'course'])],
        ['GPS speed', formatSpeed(pick(gpsData, ['speed', 'gpsSpeed']))],
        ['GPS result', firstDefined([pick(gpsInfo, ['res']), gpsWrap.message])],
      ];
      renderRows('location-content', locationRows);
      renderMapLinks(latitudeDisplay, longitudeDisplay);

      var generatedMs = parseTimestampMs(generatedAt);
      var realtimeAge = Number.isFinite(realtimeMs) ? nowMs - realtimeMs : NaN;
      var gpsAge = Number.isFinite(gpsMs) ? nowMs - gpsMs : NaN;
      var timelineRows = [
        ['Snapshot generated', formatTimestamp(generatedAt)],
        ['Snapshot age', formatAge(Number.isFinite(generatedMs) ? nowMs - generatedMs : NaN)],
        ['Realtime timestamp', formatTimestamp(realtimeTimestamp)],
        ['Realtime age', formatAge(realtimeAge)],
        ['GPS timestamp', formatTimestamp(gpsTimeValue)],
        ['GPS age', formatAge(gpsAge)],
      ];
      renderRows('timeline-content', timelineRows);

      var sensitiveMaskEnabled = false;
      var sensitivityToggle = document.getElementById('sensitivity-toggle');
      function applySensitiveMask() {
        document.body.classList.toggle('mask-sensitive', sensitiveMaskEnabled);
        if (!sensitivityToggle) {
          return;
        }
        sensitivityToggle.setAttribute('aria-pressed', sensitiveMaskEnabled ? 'true' : 'false');
        sensitivityToggle.textContent = sensitiveMaskEnabled ? 'Sensitive: hidden' : 'Sensitive: visible';
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
