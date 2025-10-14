# BYD App Reverse Engineering Notes

This repository has some notes on reverse engineering the BYD overseas (international) mobile car app, [`com.byd.bydautolink`](https://play.google.com/store/apps/details?id=com.byd.bydautolink). The app is used to monitor and control BYD electric vehicles remotely. Unfortunately BYD has no public API documentation, and the app's network traffic is obfuscated/encrypted, so these notes document some of the findings so far.

All calls target the same host, `https://dilinkappoversea-eu.byd.auto`, and were sent over HTTP/2 from an Android client (`okhttp/4.12.0`). There is some additional MQTT traffic going to `mqtts://dilinkpush-eu.byd.auto:8443`, but this has not been analyzed yet.

## Observed Endpoints
- `/app/account/login` — initial authentication call that returns a `JSESSIONID` cookie.
- `/app/config/getAllBrandCommonConfig` — pulls brand-level configuration after login.
- `/vehicleInfo/vehicle/vehicleRealTimeRequest` — appears to fetch vehicle telemetry; also yields a fresh `JSESSIONID`.
- `/control/getStatusNow` — likely queries current control/lock/etc state.
- `/app/banner/getCountryBannerConfig` — retrieves localized marketing banner in the app.

## HTTP Request / Response Details
- All captures are `POST` requests using HTTP/2 with `content-type: application/json; charset=UTF-8`. The endpoint does not seem to support HTTP/1.1.
- The client explicitly forces `accept-encoding: identity`, so responses are uncompressed despite the HTTP/2 transport.
- `user-agent` is consistently `okhttp/4.12.0`, confirming native Android networking.
- Responses include `via: 1.1 google`, suggesting the services sit behind Google Cloud load balancing.
- Authentication appears session-based: successful calls return `Set-Cookie: JSESSIONID=...; path=/`, which subsequent requests can reuse successfully.

## Payload Format
- Each request body is a single-field JSON object: `{"request": "<long token>"}`; responses mirror this with `{"response": "<token>"}`.
- Tokens only contain URL-safe Base64 characters but their lengths are `4n+1`, so they fail standard Base64 decoding even after padding; the data is likely encrypted or encoded with a custom alphabet.
- The repeated structure hints at an encryption/obfuscation layer (probably AES + custom Base64) applied before the payload is sent over TLS.

## Client-Side Encryption Clues
- The APK is SecNeo/Bangcle-protected; the visible `classes.dex` is a bootstrap that loads encrypted code from `libdatajar.so`.
- `dex2jar` confirms that `com/wbsk/CryptoTool` has no implementation in `class.dex`. Only the method table is present: both `laesEncryptStringWithBase64` and `laesDecryptStringWithBase64` have signature `(Ljava/lang/String;Ljava/lang/String;[B)Ljava/lang/String;`, but the third byte-array argument is always passed as `null` from the smali stubs.
- Native library `libwbsk_crypto_tool.so` exposes the JNI entry points (`Java_com_wbsk_CryptoTool_laesEncryptStringWithBase64`, `Java_com_wbsk_CryptoTool_laesDecryptStringWithBase64`, etc.). These functions consume the white-box tables exposed by `jniutil/JniUtil` and execute the actual AES rounds.
- `libencrypt.so` and `libwbsk_crypto_tool.so` reference `CSecFunctProvider::AES128_EncryptCBC`, `AES_EncryptOneBlock`, and white-box tables (`WBACRAES_*`), confirming the app uses a white-box **AES-128** implementation (ECB/CBC helpers present) prior to Base64 encoding.
- The `JniUtil` native stub returns literal hex blobs for `getPriKey()`, `getPubKey()`, and “new” key variants. These strings are 512 hex chars (256 bytes) and should be passed untouched to the JNI layer; they are not raw AES keys but white-box key tables. Additional helpers (`getUrlEncrypt()`, `getSecondHandCarKey()`, etc.) expose other static secrets used by ancillary modules.
- Because the white-box logic lives in native code, reimplementing the transport encryption requires calling into `libwbsk_crypto_tool.so` (e.g., loading the `.so` and invoking `Java_com_wbsk_CryptoTool_laesDecryptStringWithBase64`) or instrumenting the running app to capture plaintext at the JNI boundary—simple key derivation from the dumped hex strings is insufficient.

## Replay Check
- Replaying `/app/config/getAllBrandCommonConfig` with a captured `JSESSIONID` and the original `request` blob succeeds; the server returns a structured `{"response": "...<ciphertext>..."}` payload rather than rejecting the session.
- Sample command:
  ```bash
  curl --http2-prior-knowledge \
    'https://dilinkappoversea-eu.byd.auto/app/config/getAllBrandCommonConfig' \
    -H 'content-type: application/json; charset=UTF-8' \
    -H 'accept-encoding: identity' \
    -H 'user-agent: okhttp/4.12.0' \
    -H 'cookie: JSESSIONID=<captured-session-id>' \
    --data-raw '{"request":"<captured-request-blob>"}'
  ```
- The replayed response remains encrypted/encoded, so deeper decoding still hinges on uncovering the client-side codec.

## Potential Next Steps
1. **Call the native white-box directly** by loading `libwbsk_crypto_tool.so` (either via Frida or a small JNI harness) and invoking `Java_com_wbsk_CryptoTool_laesDecryptStringWithBase64` / `laesEncryptStringWithBase64` with the hex tables from `JniUtil`. This should yield exact plaintext/ciphertext pairs for the outer transport envelope.
2. **Hook the JNI boundary** in a running app (Frida/Xposed) to log the strings passed into `CryptoTool` and capture plaintext JSON before it is wrapped.
3. **Reverse the inner payload** by feeding decrypted envelopes into the existing AES-128-CBC routine (MD5(identifier) key) to fully unwrap `encryData` and inspect business objects.
4. **Collect wider coverage** of endpoints (vehicle commands, firmware updates, user profile) to understand the full API surface once decryption is in place.
5. **Expand replay testing** with other endpoints and fresh sessions to confirm how long `JSESSIONID` remains valid and whether additional headers/tokens ever appear.

These notes should serve as a starting point for deeper protocol analysis and automation tooling.
