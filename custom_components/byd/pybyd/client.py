"""Async BYD API client."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import aiohttp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .config import BydConfig
from .exceptions import BydApiError, BydAuthenticationError, BydError, BydRemoteControlError
from .models import AuthToken, GpsInfo, RemoteCommand, RemoteControlResult, Vehicle, VehicleRealtimeData
from .bangcle import decode_envelope, encode_envelope

_REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(slots=True)
class _Session:
    user_id: str
    sign_token: str
    encry_token: str


class BydClient:
    """Async BYD client with the API surface needed by the HA integration."""

    def __init__(self, config: BydConfig, *, session: aiohttp.ClientSession | None = None) -> None:
        self._config = config
        self._session = session
        self._external = session is not None
        self._auth: _Session | None = None

    async def __aenter__(self) -> "BydClient":
        if self._session is None:
            self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if not self._external and self._session is not None:
            await self._session.close()
            self._session = None

    @property
    def is_logged_in(self) -> bool:
        return self._auth is not None

    async def login(self) -> AuthToken:
        outer = self._build_login_request()
        response = await self._post_secure("/app/account/login", outer)
        if str(response.get("code")) != "0":
            raise BydAuthenticationError(f"Login failed: {response.get('message', '')}")

        key = self._pwd_login_key(self._config.password)
        decoded = json.loads(self._aes_dec(response["respondData"], key))
        token = decoded.get("token") or {}

        user_id = str(token.get("userId") or "")
        sign_token = str(token.get("signToken") or "")
        encry_token = str(token.get("encryToken") or "")
        if not user_id or not sign_token or not encry_token:
            raise BydAuthenticationError("Login token missing fields")

        self._auth = _Session(user_id=user_id, sign_token=sign_token, encry_token=encry_token)
        return AuthToken(user_id=user_id, sign_token=sign_token, encry_token=encry_token)

    async def get_vehicles(self) -> list[Vehicle]:
        auth = self._require_auth()
        outer, key = self._build_token_envelope(
            {
                "deviceType": self._config.device.device_type,
                "imeiMD5": self._config.device.imei_md5,
                "networkType": self._config.device.network_type,
                "random": self._random_hex16(),
                "timeStamp": str(self._now_ms()),
                "version": self._config.app_inner_version,
            }
        )
        response = await self._post_secure("/app/account/getAllListByUserId", outer)
        if str(response.get("code")) != "0":
            raise BydApiError(f"Vehicle list failed: {response.get('message', '')}")
        rows = json.loads(self._aes_dec(response["respondData"], key))
        vehicles: list[Vehicle] = []
        for row in rows or []:
            vehicles.append(
                Vehicle(
                    vin=str(row.get("vin") or ""),
                    model_name=row.get("modelName"),
                    brand_name=row.get("brandName"),
                    energy_type=row.get("energyType"),
                    auto_alias=row.get("autoAlias"),
                    auto_plate=row.get("autoPlate"),
                    raw=row,
                )
            )
        return [v for v in vehicles if v.vin]

    async def get_vehicle_realtime(self, vin: str, *, poll_attempts: int = 10, poll_interval: float = 1.5) -> VehicleRealtimeData:
        return await self._poll_realtime_endpoint(
            vin,
            "/vehicleInfo/vehicle/vehicleRealTimeRequest",
            "/vehicleInfo/vehicle/vehicleRealTimeResult",
            poll_attempts,
            poll_interval,
        )

    async def get_gps_info(self, vin: str, *, poll_attempts: int = 10, poll_interval: float = 1.5) -> GpsInfo:
        data = await self._poll_realtime_endpoint(
            vin,
            "/control/getGpsInfo",
            "/control/getGpsInfoResult",
            poll_attempts,
            poll_interval,
            gps=True,
        )
        return data

    async def remote_control(
        self,
        vin: str,
        command: RemoteCommand,
        *,
        command_pwd: str | None = None,
        control_params_map: dict[str, Any] | str | None = None,
        poll_attempts: int = 10,
        poll_interval: float = 1.5,
    ) -> RemoteControlResult:
        resolved_command_pwd = self._resolve_command_pwd(command_pwd)
        payload = {
            "commandType": command.value,
            "deviceType": self._config.device.device_type,
            "imeiMD5": self._config.device.imei_md5,
            "networkType": self._config.device.network_type,
            "random": self._random_hex16(),
            "timeStamp": str(self._now_ms()),
            "version": self._config.app_inner_version,
            "vin": vin,
        }
        if resolved_command_pwd:
            # Match app behavior: only include commandPwd when non-empty.
            payload["commandPwd"] = resolved_command_pwd
        if control_params_map is not None:
            if isinstance(control_params_map, str):
                payload["controlParamsMap"] = control_params_map
            else:
                payload["controlParamsMap"] = json.dumps(
                    {k: control_params_map[k] for k in sorted(control_params_map)}
                )
        data = await self._poll_data(
            "/control/remoteControl",
            "/control/remoteControlResult",
            payload,
            poll_attempts,
            poll_interval,
        )
        state = int(float(data.get("controlState", 0) or 0))
        if state == 2:
            raise BydRemoteControlError(f"Remote control failed for command={command}")
        return RemoteControlResult(control_state=state, success=state == 1, request_serial=data.get("requestSerial"), raw=data)

    async def lock(self, vin: str, **kwargs: Any) -> RemoteControlResult:
        return await self.remote_control(vin, RemoteCommand.LOCK, **kwargs)

    async def unlock(self, vin: str, **kwargs: Any) -> RemoteControlResult:
        return await self.remote_control(vin, RemoteCommand.UNLOCK, **kwargs)

    async def flash_lights(self, vin: str, **kwargs: Any) -> RemoteControlResult:
        return await self.remote_control(vin, RemoteCommand.FLASH_LIGHTS, **kwargs)

    async def honk_horn(self, vin: str, **kwargs: Any) -> RemoteControlResult:
        return await self.remote_control(vin, RemoteCommand.HORN, **kwargs)

    async def close_windows(self, vin: str, **kwargs: Any) -> RemoteControlResult:
        return await self.remote_control(vin, RemoteCommand.CLOSE_WINDOWS, **kwargs)

    async def start_climate(self, vin: str, **kwargs: Any) -> RemoteControlResult:
        return await self.remote_control(vin, RemoteCommand.START_CLIMATE, **kwargs)

    async def stop_climate(self, vin: str, **kwargs: Any) -> RemoteControlResult:
        return await self.remote_control(vin, RemoteCommand.STOP_CLIMATE, **kwargs)

    def _resolve_command_pwd(self, command_pwd: str | None) -> str:
        """Resolve command password to MD5 uppercase hash expected by remote control API."""
        if command_pwd is not None:
            value = str(command_pwd).strip()
            if not value:
                return ""
            if len(value) == 32 and all(ch in "0123456789abcdefABCDEF" for ch in value):
                return value.upper()
            return self._md5(value)

        configured = (self._config.control_pin or "").strip()
        if configured:
            return self._md5(configured)
        return ""

    async def _poll_realtime_endpoint(
        self,
        vin: str,
        request_endpoint: str,
        result_endpoint: str,
        poll_attempts: int,
        poll_interval: float,
        gps: bool = False,
    ) -> VehicleRealtimeData | GpsInfo:
        payload = {
            "deviceType": self._config.device.device_type,
            "imeiMD5": self._config.device.imei_md5,
            "networkType": self._config.device.network_type,
            "random": self._random_hex16(),
            "timeStamp": str(self._now_ms()),
            "version": self._config.app_inner_version,
            "vin": vin,
        }
        if not gps:
            payload["energyType"] = "0"
            payload["tboxVersion"] = self._config.tbox_version

        ready_check = self._is_gps_ready if gps else self._is_realtime_ready
        data = await self._poll_data(
            request_endpoint,
            result_endpoint,
            payload,
            poll_attempts,
            poll_interval,
            ready_check=ready_check,
        )

        if gps:
            src = data.get("data") if isinstance(data.get("data"), dict) else data
            return GpsInfo(
                latitude=self._to_float(src.get("latitude") or src.get("lat") or src.get("gpsLatitude")),
                longitude=self._to_float(src.get("longitude") or src.get("lon") or src.get("lng") or src.get("gpsLongitude")),
                speed=self._to_float(src.get("speed") or src.get("gpsSpeed")),
                direction=self._to_float(src.get("direction") or src.get("heading")),
                gps_timestamp=str(src.get("gpsTimeStamp") or src.get("gpsTimestamp") or src.get("time") or "") or None,
                raw=data,
            )

        return VehicleRealtimeData(
            elec_percent=self._to_float(data.get("elecPercent")),
            endurance_mileage=self._to_float(data.get("enduranceMileage")),
            charging_state=str(data.get("chargingState") or data.get("chargeState") or "") or None,
            trunk_lid=str(data.get("trunkLid") or data.get("backCover") or "") or None,
            raw=data,
        )

    async def _poll_data(
        self,
        request_endpoint: str,
        result_endpoint: str,
        payload: dict[str, Any],
        poll_attempts: int,
        poll_interval: float,
        *,
        ready_check: Callable[[dict[str, Any]], bool] | None = None,
    ) -> dict[str, Any]:
        is_ready = ready_check or self._is_ready
        first = await self._fetch_payload(request_endpoint, payload)
        if is_ready(first):
            return first
        serial = first.get("requestSerial")
        latest = first
        for _ in range(poll_attempts):
            if not serial:
                break
            await asyncio.sleep(poll_interval)
            poll_payload = dict(payload)
            poll_payload["requestSerial"] = serial
            latest = await self._fetch_payload(result_endpoint, poll_payload)
            serial = latest.get("requestSerial") or serial
            if is_ready(latest):
                return latest
        return latest

    @staticmethod
    def _is_realtime_ready(payload: dict[str, Any]) -> bool:
        if not payload or not isinstance(payload, dict):
            return False
        if set(payload.keys()) == {"requestSerial"}:
            return False
        online_state = BydClient._to_float(payload.get("onlineState"))
        if online_state == 2:
            return False

        tire_fields = (
            "leftFrontTirepressure",
            "rightFrontTirepressure",
            "leftRearTirepressure",
            "rightRearTirepressure",
        )
        for field in tire_fields:
            pressure = BydClient._to_float(payload.get(field))
            if pressure is not None and pressure > 0:
                return True

        if (BydClient._to_float(payload.get("time")) or 0) > 0:
            return True
        if (BydClient._to_float(payload.get("enduranceMileage")) or 0) > 0:
            return True
        return False

    @staticmethod
    def _is_gps_ready(payload: dict[str, Any]) -> bool:
        if not payload or not isinstance(payload, dict):
            return False
        keys = list(payload.keys())
        if not keys:
            return False
        return not (len(keys) == 1 and keys[0] == "requestSerial")

    async def _fetch_payload(self, endpoint: str, inner_payload: dict[str, Any]) -> dict[str, Any]:
        outer, key = self._build_token_envelope(inner_payload)
        response = await self._post_secure(endpoint, outer)
        if str(response.get("code")) != "0":
            raise BydApiError(f"{endpoint} failed: {response.get('message', '')}")
        return json.loads(self._aes_dec(response["respondData"], key))

    def _is_ready(self, payload: dict[str, Any]) -> bool:
        if not payload:
            return False
        if set(payload.keys()) == {"requestSerial"}:
            return False
        state = payload.get("controlState")
        if state is not None and str(state) == "0":
            return False
        return True

    async def _post_secure(self, endpoint: str, outer_payload: dict[str, Any]) -> dict[str, Any]:
        if self._session is None:
            raise BydError("Client not initialized; use async with BydClient(...)")
        envelope = self._bangcle_encode(json.dumps(outer_payload, separators=(",", ":")))
        headers = {
            "accept-encoding": "identity",
            "content-type": "application/json; charset=UTF-8",
            "user-agent": "okhttp/4.12.0",
        }
        async with self._session.post(
            f"{self._config.base_url}{endpoint}",
            headers=headers,
            json={"request": envelope},
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise BydApiError(f"HTTP {resp.status}: {text[:200]}")
        body = json.loads(text)
        decoded = self._bangcle_decode(body["response"])
        normalized = decoded[1:] if decoded.startswith("F{") else decoded
        return json.loads(normalized)

    def _build_login_request(self) -> dict[str, Any]:
        now_ms = self._now_ms()
        req_ts = str(now_ms)
        inner = {
            "appInnerVersion": self._config.app_inner_version,
            "appVersion": self._config.app_version,
            "deviceName": f"{self._config.device.mobile_brand}{self._config.device.mobile_model}",
            "deviceType": self._config.device.device_type,
            "imeiMD5": self._config.device.imei_md5,
            "isAuto": self._config.is_auto,
            "mobileBrand": self._config.device.mobile_brand,
            "mobileModel": self._config.device.mobile_model,
            "networkType": self._config.device.network_type,
            "osType": self._config.device.os_type,
            "osVersion": self._config.device.os_version,
            "random": self._random_hex16(),
            "softType": self._config.soft_type,
            "timeStamp": req_ts,
            "timeZone": self._config.time_zone,
        }
        encry_data = self._aes_enc(json.dumps(inner, separators=(",", ":")), self._pwd_login_key(self._config.password))
        sign_fields = {
            **inner,
            "countryCode": self._config.country_code,
            "functionType": "pwdLogin",
            "identifier": self._config.username,
            "identifierType": "0",
            "language": self._config.language,
            "reqTimestamp": req_ts,
        }
        outer = {
            "countryCode": self._config.country_code,
            "encryData": encry_data,
            "functionType": "pwdLogin",
            "identifier": self._config.username,
            "identifierType": "0",
            "imeiMD5": self._config.device.imei_md5,
            "isAuto": self._config.is_auto,
            "language": self._config.language,
            "reqTimestamp": req_ts,
            "sign": self._sha1_mixed(self._build_sign_string(sign_fields, self._md5(self._config.password))),
            "signKey": self._config.password,
            **self._common_outer(),
            "serviceTime": str(self._now_ms()),
        }
        outer["checkcode"] = self._checkcode(outer)
        return outer

    def _build_token_envelope(self, inner: dict[str, Any]) -> tuple[dict[str, Any], str]:
        auth = self._require_auth()
        now = self._now_ms()
        req_ts = str(now)
        content_key = self._md5(auth.encry_token)
        sign_key = self._md5(auth.sign_token)
        encry_data = self._aes_enc(json.dumps(inner, separators=(",", ":")), content_key)

        sign_fields = {
            **inner,
            "countryCode": self._config.country_code,
            "identifier": auth.user_id,
            "imeiMD5": self._config.device.imei_md5,
            "language": self._config.language,
            "reqTimestamp": req_ts,
        }
        outer = {
            "countryCode": self._config.country_code,
            "encryData": encry_data,
            "identifier": auth.user_id,
            "imeiMD5": self._config.device.imei_md5,
            "language": self._config.language,
            "reqTimestamp": req_ts,
            "sign": self._sha1_mixed(self._build_sign_string(sign_fields, sign_key)),
            **self._common_outer(),
            "serviceTime": str(self._now_ms()),
        }
        outer["checkcode"] = self._checkcode(outer)
        return outer, content_key

    def _common_outer(self) -> dict[str, str]:
        d = self._config.device
        return {
            "ostype": d.ostype,
            "imei": d.imei,
            "mac": d.mac,
            "model": d.model,
            "sdk": d.sdk,
            "mod": d.mod,
        }

    def _require_auth(self) -> _Session:
        if self._auth is None:
            raise BydError("Not logged in")
        return self._auth

    @staticmethod
    def _to_float(value: Any) -> float | None:
        try:
            if value in (None, ""):
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _random_hex16() -> str:
        return secrets.token_hex(16).upper()

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def _md5(value: str) -> str:
        return hashlib.md5(value.encode("utf-8")).hexdigest().upper()

    @classmethod
    def _pwd_login_key(cls, password: str) -> str:
        return cls._md5(cls._md5(password))

    @staticmethod
    def _sha1_mixed(value: str) -> str:
        digest = hashlib.sha1(value.encode("utf-8")).digest()
        mixed = "".join((f"{b:02X}" if i % 2 == 0 else f"{b:02x}") for i, b in enumerate(digest))
        out = []
        for i, ch in enumerate(mixed):
            if ch == "0" and i % 2 == 0:
                continue
            out.append(ch)
        return "".join(out)

    @staticmethod
    def _build_sign_string(fields: dict[str, Any], password: str) -> str:
        parts = [f"{k}={fields[k]}" for k in sorted(fields)]
        return "&".join(parts) + f"&password={password}"

    @staticmethod
    def _checkcode(payload: dict[str, Any]) -> str:
        digest = hashlib.md5(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()
        return f"{digest[24:32]}{digest[8:16]}{digest[16:24]}{digest[0:8]}"

    @staticmethod
    def _aes_enc(plaintext_utf8: str, key_hex: str) -> str:
        key = bytes.fromhex(key_hex)
        iv = b"\x00" * 16
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext_utf8.encode("utf-8")) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return (cipher.update(padded) + cipher.finalize()).hex().upper()

    @staticmethod
    def _aes_dec(cipher_hex: str, key_hex: str) -> str:
        key = bytes.fromhex(key_hex)
        iv = b"\x00" * 16
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(bytes.fromhex(cipher_hex)) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
        return plain.decode("utf-8")

    @classmethod
    def _bangcle_encode(cls, plaintext: str) -> str:
        return encode_envelope(plaintext)

    @classmethod
    def _bangcle_decode(cls, envelope: str) -> str:
        return decode_envelope(envelope).decode("utf-8")
