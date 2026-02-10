#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
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
const TRANSPORT_KEY = '9F29BE3E6254AF2C354F265B17C0CDD3';

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

  const encryData = aesEncryptHex(JSON.stringify(inner), TRANSPORT_KEY);

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

  const loginInner = decryptRespondDataJson(loginOuter.respondData, TRANSPORT_KEY);
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
