# 🚗 BYD Reverse Engineering

Reverse engineering of the BYD app HTTP crypto path used in the Android app.

Base hosts:
- Overseas app (`com.byd.bydautolink`): `https://dilinkappoversea-eu.byd.auto`
- CN app (`com.byd.aeri.caranywhere`): `https://dilinksuperappserver-cn.byd.auto`

## 🔗 Related Projects

- [`pyBYD`](https://github.com/jkaberg/pyBYD): full Python library built from these reverse-engineering findings.
- [`hass-byd-vehicle`](https://github.com/jkaberg/hass-byd-vehicle): Home Assistant integration for BYD vehicles.
- [`BYD-re custom_components`](https://github.com/codyc1515/BYD-re/tree/main/custom_components/byd): Home Assistant custom component for BYD.

## 🚀 Quickstart

`client.js` is the main entrypoint. Prerequisite: Node.js 20+.

> **Warning:** Do not commit real credentials, raw personal logs, or decrypted personal data. `.env` and hook logs can contain plaintext identifiers and passwords.

Create `.env`:

```dotenv
BYD_USERNAME=you@example.com
BYD_PASSWORD=your-password
```

Run:

```bash
node client.js
```

The client performs login, resolves the MQTT broker and prints ready-to-use `mosquitto_sub` commands, fetches your vehicle list, polls real-time vehicle status, and retrieves GPS info. It also writes a self-contained dashboard to `status.html`.

![Status dashboard screenshot](screenshot.png)

The client accepts many `BYD_*` environment variable overrides (`BYD_COUNTRY_CODE`, `BYD_LANGUAGE`, `BYD_VIN`, etc.) — see the top of `client.js` for the full list and defaults.

## 🗺️ Project Map

- `client.js`: minimal login + vehicle list + realtime poll + GPS client + MQTT connection info.
- `mqtt_decode.js`: streaming MQTT payload decoder (AES-128-CBC, hex input → JSON output).
- `decompile.js`: decoder/encoder CLI (debugging/analysis).
- `bangcle.js`: Bangcle envelope encode/decode implementation.
- `bangcle_auth_tables.js`: embedded Bangcle auth tables.
- `URLs.md`: discovered API URL inventory (observed in logs + static `class.dex` candidates).
- `scripts/generate_bangcle_auth_tables.js`: table generator.
- `xposed/http.sh`: decode helper for `HTTP method=` log lines.
- `xposed/src/*`: Xposed hook module source (Java hooks, resources, manifest).

## 📱 App & Transport Snapshot

- Apps: BYD overseas Android app (`com.byd.bydautolink`) and CN app: `com.byd.aeri.caranywhere`.
- Hooking compatibility: `2.9.1` is the latest APK version that can be reliably hooked in this setup. Newer versions add Magisk/Zygote/LSPosed/root detection.
- Hookable APK (`2.9.1`): [APKPure download](https://apkpure.com/byd/com.byd.bydautolink/download/2.9.1)
- Client stack: Android + OkHttp (`user-agent: okhttp/4.12.0`).
- API pattern: JSON-over-HTTP POST with encrypted payload wrapper.

Common request characteristics observed in hooks and mirrored by `client.js`:
- `content-type: application/json; charset=UTF-8`
- `accept-encoding: identity`
- `user-agent: okhttp/4.12.0`
- cookie-backed session reuse across calls (client stores and replays returned cookies)

## 🔐 Crypto Pipeline

Every BYD API call uses multiple crypto layers, described from outermost to innermost.

### 1. HTTP wrapper

Request body: `{"request":"<envelope>"}`. Response body: `{"response":"<envelope>"}`.

### 2. Bangcle envelope (`bangcle.js`, overseas app)

- Format: `F` + Base64 ciphertext.
- Table-driven Bangcle white-box AES using embedded auth tables from `bangcle_auth_tables.js`.
- CBC mode, zero IV, PKCS#7 padding.
- Decoding strips the `F` prefix, Base64-decodes, decrypts, and removes PKCS#7.

After decoding, the outer JSON payload typically looks like:

```json
{
  "countryCode": "NL",
  "identifier": "<username-or-userId>",
  "imeiMD5": "<md5-hex>",
  "language": "en",
  "reqTimestamp": "<millis>",
  "sign": "<sha1Mixed>",
  "encryData": "<AES-CBC hex>",
  "checkcode": "<md5-reordered>"
}
```

Response-side decoded outer payload:

```json
{
  "code": "0",
  "message": "SUCCESS",
  "identifier": "<userId-or-countryCode>",
  "respondData": "<AES-CBC hex>"
}
```

For a full field-level description and mapping reference, see [`pyBYD/API_MAPPING.md`](https://github.com/jkaberg/pyBYD/blob/main/API_MAPPING.md).

### 2b. CheckCode envelope (`com.byd.aeri.caranywhere`, CN app)

Observed in CN captures:
- Request wrapper is still `{"request":"<envelope>"}`.
- Envelope text is Base64 without `F` prefix (captured envelope starts with `xo0K...`), produced by `CheckCodeUtil#checkcode`.
- `checkcode`/`decheckcode` logs include `envelope version=... iv=... trailer=15`, indicating a framed format that differs from strict `F`-prefixed `bangcle.js` input.
- `CheckCodeUtil#decheckcode` returns an outer object with fields like `identifier`, `code`, and hex `respondData`; a second AES-CBC decrypt (IV=0) then yields business JSON.
- Some inner hex payloads (`encryData`/`respondData`) start with `F...`; this is not the same as the overseas outer `F`-prefixed envelope format.
- In this CN HTTP path, no overseas-style Bangcle `F` envelope decode path is observed; traffic is handled by `CheckCodeUtil`.

### 3. Inner business payload (`encryData` / `respondData`)

- Fields are uppercase hex AES-128-CBC (zero IV).
- Config endpoints (e.g. `/app/config/getAllBrandCommonConfig`) use static `CONFIG_KEY`.
- `/app/account/getAccountState` uses `MD5(identifier)`.
- CN password-login captures indicate the double-MD5 variant requires uppercasing the inner MD5 before the second MD5.
- Remote control command password (`commandPwd`) uses uppercase `MD5(<operation PIN>)` (e.g. `123456` → `E10ADC3949BA59ABBE56E057F20F883E`), used by `/vehicle/vehicleswitch/verifyControlPassword` and `/control/remoteControl`.
- Token field naming differs by app build:
  - overseas app responses use `token.encryToken`
  - CN responses can use `token.encryptToken`
- Post-login payloads use token-derived keys from `respondData.token`:
  - content key: `MD5(contentToken)` for `encryData` / `respondData` (`contentToken` = `encryToken` or `encryptToken`)
  - sign key: `MD5(signToken)` for `sign`

### 4. Signature and checkcode

- Password-login style flows use raw password-derived sign input (`sha1Mixed(buildSignString(..., md5(password)))`).
- Post-login sign uses token-derived sign key.
- Overseas app `checkcode` is computed from `MD5(JSON.stringify(outerPayload))` with reordered chunks:
  `[24:32] + [8:16] + [16:24] + [0:8]`
- CN app `checkcode` path uses SHA-256 (`CheckCodeUtil#get_obf_sha` → `getSHA256`) over the augmented request JSON before envelope encryption.

## 📡 MQTT Real-Time Vehicle Telemetry

BYD uses an [EMQ](https://www.emqx.io/)-based MQTT broker to push real-time vehicle data to connected clients via MQTTv5 over TLS (port 8883). The broker hostname is fetched after login via `POST /app/emqAuth/getEmqBrokerIp` (response field: `emqBroker` or `emqBorker`).

| Parameter | Value |
|-----------|-------|
| **Client ID** | `oversea_` + uppercase `MD5(IMEI)` (default IMEI MD5: all zeros) |
| **Username** | `userId` from login response token |
| **Password** | `<tsSeconds>` + uppercase `MD5(signToken + clientId + userId + tsSeconds)` |
| **Topic** | `/oversea/res/<userId>` |

All MQTT payloads use the same encryption as `encryData`/`respondData`: hex-encoded AES-128-CBC, zero IV, key = `MD5(contentToken)` (`contentToken` is typically `token.encryToken` or `token.encryptToken`, depending on app build).

`client.js` prints ready-to-use `mosquitto_sub` commands after login. Example:

```bash
mosquitto_sub -V mqttv5 \
  -L 'mqtts://<userId>:<password>@<broker>/oversea/res/<userId>' \
  -i 'oversea_<IMEI_MD5>' \
  -F '%p' \
  | node ./mqtt_decode.js '<MD5(contentToken)>'
```

## 🧪 Debugging / Offline Decode (`decompile.js`)

Decode one payload:

```bash
node decompile.js http-dec '<payload>'
```

Accepted input:
- raw Bangcle envelope ciphertext (`F` + Base64/Base64URL payload, overseas format)
- full JSON body such as `{"request":"..."}` or `{"response":"..."}`
- raw inner hex ciphertext

Note for CN app logs: request envelopes generated by `CheckCodeUtil#checkcode` are Base64 without `F` prefix, so `decompile.js http-dec` does not currently auto-decode those outer envelopes directly.

Common options:

```bash
node decompile.js http-dec '<payload>' --debug
node decompile.js http-dec '<payload>' --state-file /tmp/byd_state.json
```

Encrypt inner JSON with `md5(identifier)` key:

```bash
node decompile.js http-enc '{"k":"v"}' --identifier <id>
```

Decode full hook flow:

```bash
./xposed/http.sh /path/to/raw_hooks.log
```

`xposed/http.sh` creates a temporary per-run decode-state file so keys learned from login are reused for later calls in the same flow.

## 🧩 Internals

### Decoder Key Strategy

`http-dec` inner-field decryption order:
1. static AES keys (`CONFIG_KEY`)
2. learned state keys
3. `md5(identifier)` when identifier is known from parsed outer payload

State behavior:
- default file: `/tmp/byd_http_dec_state.json`
- override: `BYD_DECODE_STATE_FILE` or `--state-file`
- auto-learns `contentKey = MD5(token.encryToken)` from decoded login `respondData` (overseas app field name)
- CN app login payloads can use `token.encryptToken`; current `decompile.js` state learning still expects `token.encryToken`

### Bangcle Tables

Runtime uses embedded tables only — `bangcle.js` does not read `.so` files at runtime.

`bangcle_auth_tables.js` is generated from `byd/libencrypt.so.mem.so`:

```bash
node scripts/generate_bangcle_auth_tables.js
```
