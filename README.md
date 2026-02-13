# 🚗 BYD Reverse Engineering

Reverse engineering of the BYD app HTTP crypto path used in the Android app.

Base host: `https://dilinkappoversea-eu.byd.auto`

## 🔗 Related Projects

- [`pyBYD`](https://github.com/jkaberg/pyBYD): full Python library built from these reverse-engineering findings.
- [`hass-byd-vehicle`](https://github.com/jkaberg/hass-byd-vehicle): Home Assistant integration for BYD vehicles.
- [`BYD-re custom_components`](https://github.com/codyc1515/BYD-re/tree/main/custom_components/byd): Home Assistant custom component for BYD.

## 📱 App & Transport Snapshot

- App: BYD overseas Android app (`com.byd.bydautolink`).
- ⚠️ Hooking compatibility: `2.9.1` is the latest APK version that can be reliably hooked in this setup. Newer versions add Magisk/Zygote/LSPosed/root detection.
- 🔓 Hookable APK (`2.9.1`): [APKPure download](https://apkpure.com/byd/com.byd.bydautolink/download/2.9.1)
- Primary API host: `https://dilinkappoversea-eu.byd.auto`.
- Client stack: Android + OkHttp (`user-agent: okhttp/4.12.0`).
- API pattern: JSON-over-HTTP POST with encrypted payload wrapper.

Common request characteristics observed in hooks and mirrored by `client.js`:
- `content-type: application/json; charset=UTF-8`
- `accept-encoding: identity`
- `user-agent: okhttp/4.12.0`
- cookie-backed session reuse across calls (client stores and replays returned cookies)

## 📦 HTTP Envelope & Payload Shape

All API calls use an outer wrapper:

```json
{ "request": "<F-prefixed Bangcle envelope>" }
```

Server responses mirror the structure:

```json
{ "response": "<F-prefixed Bangcle envelope>" }
```

After Bangcle envelope decode, the outer JSON payload typically looks like:

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

Response-side decoded outer payload usually includes:

```json
{
  "code": "0",
  "message": "SUCCESS",
  "identifier": "<userId-or-countryCode>",
  "respondData": "<AES-CBC hex>"
}
```

For a full field-level description and mapping reference, see [`pyBYD/API_MAPPING.md`](https://github.com/jkaberg/pyBYD/blob/main/API_MAPPING.md).

## 🔐 Crypto Pipeline (How Encryption Works)

Every BYD app call in this repo uses multiple crypto layers:

1. HTTP wrapper
- Request body is JSON: `{"request":"<envelope>"}`.
- Response body is JSON: `{"response":"<envelope>"}`.

2. Bangcle envelope layer (`bangcle.js`)
- Envelope format is `F` + Base64 ciphertext.
- Ciphertext is table-driven Bangcle white-box AES flow using embedded auth tables from `bangcle_auth_tables.js`.
- Mode is CBC with zero IV and PKCS#7 padding.
- Decoding requires and strips the `F` prefix, Base64-decodes, decrypts, and removes PKCS#7.

3. Inner business payload layer (`encryData` / `respondData`)
- Fields are uppercase hex AES-128-CBC (zero IV).
- Config endpoints (e.g. `/app/config/getAllBrandCommonConfig`) use static `CONFIG_KEY`.
- `/app/account/getAccountState` uses `MD5(identifier)`.
- Login (`pwdLogin`) uses `MD5(MD5(signKey))` where `signKey` is the plaintext password sent in the outer payload.
- Remote control command password (`commandPwd`) uses uppercase `MD5(<operation PIN>)` (e.g. `123456` → `E10ADC3949BA59ABBE56E057F20F883E`), used by `/vehicle/vehicleswitch/verifyControlPassword` and `/control/remoteControl`.
- Post-login payloads use token-derived keys from `respondData.token`:
  - content key: `MD5(encryToken)` (for `encryData` / `respondData`)
  - sign key: `MD5(signToken)` (for `sign`)

4. Signature and checkcode fields
- Login sign key input is raw password; sign uses `sha1Mixed(buildSignString(..., md5(password)))`.
- Post-login sign uses token-derived sign key.
- `checkcode` is computed from `MD5(JSON.stringify(outerPayload))` with reordered chunks:
  - `[24:32] + [8:16] + [16:24] + [0:8]`

## 📡 MQTT Real-Time Vehicle Telemetry

BYD uses an [EMQ](https://www.emqx.io/)-based MQTT broker to push real-time vehicle data (telemetry, status updates) to connected clients. The connection uses MQTT v5 over TLS (`mqtts://`, port 8883).

### Connection Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| **Protocol** | MQTTv5 over TLS | `mqtts://` (port 8883) |
| **Broker** | Dynamic, per-region | API: `/app/emqAuth/getEmqBrokerIp` |
| **Client ID** | `oversea_<IMEI_MD5>` | `IMEI_MD5` uppercased, prefixed with `oversea_` |
| **Username** | `<userId>` | From login response `token.userId` |
| **Password** | `<tsSeconds><MD5(signToken + clientId + userId + tsSeconds)>` | Computed at connect time |
| **Topic** | `/oversea/res/<userId>` | Subscribe to receive vehicle push messages |

### Broker Discovery

The broker hostname is not hardcoded — it is fetched after login via the API:

```
POST /app/emqAuth/getEmqBrokerIp
```

The decrypted response contains the broker address in the `emqBroker` (or `emqBorker`) field.

### Authentication

MQTT credentials are derived from the login session tokens:

1. **Client ID**: `oversea_` + uppercase `MD5(IMEI)`. The default IMEI MD5 is `00000000000000000000000000000000`.
2. **Username**: The `userId` string returned in the login response token.
3. **Password**: Built as `<tsSeconds><hash>` where:
   - `tsSeconds` = current Unix timestamp in seconds
   - `hash` = `MD5(signToken + clientId + userId + tsSeconds)` (lowercase hex)

### Payload Encryption

All MQTT message payloads are **hex-encoded AES-128-CBC** ciphertext with a **zero IV** (same scheme as `encryData`/`respondData` in the HTTP API).

The decryption key is `MD5(encryToken)` — the same content key used for HTTP response decryption, derived from the login response token.

### Subscribing with mosquitto

`client.js` prints ready-to-use `mosquitto_sub` commands after login. Example:

```bash
# Connect and decrypt payloads in real time:
mosquitto_sub -V mqttv5 \
  -L 'mqtts://<userId>:<password>@<broker>/oversea/res/<userId>' \
  -i 'oversea_<IMEI_MD5>' \
  -F '%p' \
  | node ./mqtt_decode.js '<MD5(encryToken)>'
```

### `mqtt_decode.js`

Streaming decoder: reads hex-encoded MQTT payloads from stdin, decrypts with `MD5(encryToken)` as AES key.

## 🚀 Use This First: Minimal Client

`client.js` is the main entrypoint (most useful path).

Prerequisite: Node.js 20+.

Create `.env`:

```dotenv
BYD_USERNAME=you@example.com
BYD_PASSWORD=your-password
```

Run:

```bash
node client.js
```

Current client flow:
- `/app/account/login`
- `/app/account/getAllListByUserId`
- `/vehicleInfo/vehicle/vehicleRealTimeRequest` (single trigger)
- `/vehicleInfo/vehicle/vehicleRealTimeResult` (poll until populated)
- `/control/getGpsInfo` (single trigger)
- `/control/getGpsInfoResult` (poll until populated)

The client also writes a self-contained dashboard to `status.html`.

![Status dashboard screenshot](screenshot.png)

Optional `BYD_*` overrides:
- `BYD_COUNTRY_CODE`
- `BYD_LANGUAGE`
- `BYD_VIN`
- `BYD_IMEI_MD5`
- `BYD_APP_VERSION`
- `BYD_APP_INNER_VERSION`
- `BYD_OS_TYPE`
- `BYD_OS_VERSION`
- `BYD_TIME_ZONE`
- `BYD_DEVICE_TYPE`
- `BYD_NETWORK_TYPE`
- `BYD_MOBILE_BRAND`
- `BYD_MOBILE_MODEL`
- `BYD_SOFT_TYPE`
- `BYD_TBOX_VERSION`
- `BYD_IS_AUTO`
- `BYD_OSTYPE`
- `BYD_IMEI`
- `BYD_MAC`
- `BYD_MODEL`
- `BYD_SDK`
- `BYD_MOD`

## 🧪 Debugging / Offline Decode (`decompile.js`)

Decode one payload:

```bash
node decompile.js http-dec '<payload>'
```

Accepted input:
- raw Bangcle envelope ciphertext (`F` + Base64/Base64URL payload)
- full JSON body such as `{"request":"..."}` or `{"response":"..."}`
- raw inner hex ciphertext

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
./xposed/http.sh xposed/samples/raw_hooks.log
```

`xposed/http.sh` creates a temporary per-run decode-state file so keys learned from login are reused for later calls in the same flow. This is needed because each `node decompile.js` call is a separate process.

## 🧠 Decoder Key Strategy

`http-dec` inner-field decryption order:
1. static AES keys (`CONFIG_KEY`)
2. learned state keys
3. `md5(identifier)` when identifier is known from parsed outer payload

State behavior:
- default file: `/tmp/byd_http_dec_state.json`
- override: `BYD_DECODE_STATE_FILE` or `--state-file`
- auto-learns `pwdLoginKey = MD5(MD5(signKey))` from login outer payload when present
- auto-learns `contentKey = MD5(token.encryToken)` from decoded login `respondData`

## 🧩 Bangcle Tables

Runtime uses embedded tables only.

- `bangcle.js` does not read `.so` files at runtime.
- `bangcle_auth_tables.js` is generated from `byd/libencrypt.so.mem.so`:

```bash
node scripts/generate_bangcle_auth_tables.js
```

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

## 🛡️ Security

Do not commit real credentials, raw personal logs, or decrypted personal data.
`xposed/samples/raw_hooks.log` can contain plaintext identifiers and passwords.
