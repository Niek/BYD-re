# BYD App Reverse Engineering Notes

This repository has some notes on reverse engineering the BYD overseas (international) mobile car app, [`com.byd.bydautolink`](https://play.google.com/store/apps/details?id=com.byd.bydautolink). The app is used to monitor and control BYD electric vehicles remotely. Unfortunately BYD has no public API documentation, and the app's network traffic is obfuscated/encrypted, so these notes document some of the findings so far.

All calls target the same host, `https://dilinkappoversea-eu.byd.auto`, and were sent over HTTP/2 from an Android client (`okhttp/4.12.0`). There is some additional MQTT traffic going to `mqtts://dilinkpush-eu.byd.auto:8443`, but this has not been analyzed yet.

## Observed Endpoints
- `/app/account/login` — initial authentication call that returns a `JSESSIONID` cookie.
- `/app/config/getAllBrandCommonConfig` — pulls brand-level configuration after login.
- `/vehicleInfo/vehicle/vehicleRealTimeRequest` — appears to fetch vehicle telemetry; also yields a fresh `JSESSIONID`.
- `/control/getStatusNow` — likely queries current control/lock/etc state.
- `/app/banner/getCountryBannerConfig` — retrieves localized marketing banner in the app.

See more endpoints here: https://github.com/jkaberg/byd-react-app-reverse/issues/1

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
- Because the white-box logic lives in native code, reimplementing the transport encryption requires calling into `libwbsk_crypto_tool.so` (e.g., loading the `.so` and invoking `Java_com_wbsk_CryptoTool_laesDecryptStringWithBase64`) or instrumenting the running app to capture plaintext at the JNI boundary—simple key derivation from the dumped hex strings is insufficient. Hooking `com.wbsk.CryptoTool` at runtime confirms that the white-box tables work as expected when paired with the corresponding `getPriKey()` / `getPubKey()` material.

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

## Xposed Module

An LSPosed/Xposed module (`xposed/`) hooks the Java `com.wbsk.CryptoTool` wrappers to log plaintext, ciphertext, and the associated white-box hex material during live app usage.

### Building the module

```
cd xposed
# Ensure the Android SDK path is configured (either via ANDROID_HOME or local.properties)
./gradlew assembleRelease
```

The built APK will be located under `xposed/build/outputs/apk/release/`.

### Deploying to a test device

```
adb install -r xposed/build/outputs/apk/release/xposed-release.apk
```

After installation, enable the module inside LSPosed Manager and scope it to the `com.byd.bydautolink` app. Reboot if LSPosed requests it.

### Gathering logs

```
adb logcat -s BYD-Xposed
```

Log lines include the plaintext/ciphertext pairs and the 512-character key blobs needed for the white-box analysis.

## JRuby/JNI Experiment: Not Viable
We experimented with loading `libwbsk_crypto_tool.so` from a regular Linux environment (via Go + cgo) to call the JNI exports directly. This path dead-ends:

- The shared object pulls in Android-specific dependencies (`liblog.so`, `libart.so`, etc.). Without bundling the entire Android runtime or providing symbol-compatible stubs, `dlopen` fails.
- Even if those dependencies were satisfied, the exports expect a real `JNIEnv*` and associated Dalvik data structures; providing them outside Android requires reimplementing large parts of the VM.

Conclusion: invoking the library natively is only practical inside an actual Android environment (or with Frida/Xposed instrumentation).

## Current Reverse-Engineering Strategy
Given the JNI approach is impractical on desktop Linux/macOS, we focus on reimplementing the transport encryption by studying the decompiled native code (`libwbsk_crypto_tool.so.c`, included in this repo).

### High-Level Flow
1. **Xposed hook** (`xposed/` module) logs the plaintext, ciphertext, and the 512-character white-box hex blobs (`JniUtil.getPriKey()` / `getPubKey()`). Representative captures are kept private because they contain sensitive user data.
2. **Blob decode** (`FUN_00101888`): strip the 4-byte header, XOR-unmask the blob, determine mode/direction flags.
3. **Table expansion** (`wbsk_skb_decrypt` → `wbsk_internal_crypto`): chunk the decoded blob into lookup tables (`LAES_encrypt_te*`, `LAES_encrypt_xor*`, etc.) that encode both the AES round keys and the affine encodings of the white-box.
4. **White-box AES rounds** (`wbsk_WB_LAES_encrypt` / `wbsk_WB_LAES_decrypt`): process each 16-byte block through 10+ rounds of nibble-mixing with the tables above.
5. **CBC + PKCS#7** (`wbsk_CRYPTO_cbc128_*` + JNI wrapper): wrap the block cipher in standard AES-128-CBC with zero IV (when `null`), apply padding, Base64 encode the result.

These notes should serve as a starting point for deeper protocol analysis and automation tooling.
