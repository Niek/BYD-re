"""Pure-Python Bangcle envelope codec used by BYD API requests."""

from __future__ import annotations

import base64
import re
import struct
from functools import lru_cache

from .bangcle_auth_tables import AUTH_TABLES

_TABLE_SPECS: dict[str, int] = {
    "invRound": 0x28000,
    "invXor": 0x3C000,
    "invFirst": 0x1000,
    "round": 0x28000,
    "xor": 0x3C000,
    "final": 0x1000,
    "permDecrypt": 8,
    "permEncrypt": 8,
}

_ZERO_IV = bytes(16)


@lru_cache(maxsize=1)
def _load_tables() -> dict[str, bytes]:
    tables: dict[str, bytes] = {}
    for name, expected_len in _TABLE_SPECS.items():
        encoded = AUTH_TABLES.get(name)
        if not isinstance(encoded, str) or not encoded:
            raise RuntimeError(f"Missing embedded auth table: {name}")
        raw = base64.b64decode(encoded)
        if len(raw) != expected_len:
            raise RuntimeError(
                f"Embedded auth table {name} has unexpected size {len(raw)} (expected {expected_len})"
            )
        tables[name] = raw
    return tables


def _prepare_aes_matrix(input_block: bytes, output: bytearray) -> None:
    for col in range(4):
        for row in range(4):
            output[col * 8 + row] = input_block[col + row * 4]


def _write_block_from_matrix(input_state: bytearray, output: bytearray) -> None:
    for col in range(4):
        for row in range(4):
            output[col + row * 4] = input_state[col * 8 + row]


def _read_u32_le(buffer: bytes, index: int) -> int:
    return struct.unpack_from("<I", buffer, index)[0]


def _write_u32_le(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 4] = value.to_bytes(4, "little")


def _decrypt_block_auth(block: bytes, scratch: dict[str, bytearray]) -> bytes:
    tables = _load_tables()
    state = scratch["state32"]
    temp64 = scratch["temp64"]
    tmp32 = scratch["tmp32"]
    output = scratch["out"]

    _prepare_aes_matrix(block, state)

    for rnd in range(9, 0, -1):
        l_var21 = rnd * 4
        perm_ptr = 0

        for i in range(4):
            b_var3 = tables["permDecrypt"][perm_ptr]
            l_var16 = i * 8
            base = i * 16

            for j in range(4):
                u_var7 = (b_var3 + j) & 3
                byte_val = state[l_var16 + u_var7]
                idx = byte_val + (i + (l_var21 + u_var7) * 4) * 256
                value = _read_u32_le(tables["invRound"], idx * 4)
                _write_u32_le(temp64, base + j * 4, value)
            perm_ptr += 2

        i_var15 = 1
        for l_var21_xor in range(4):
            pb_var18_offset = l_var21_xor

            for l_var9_xor in range(4):
                local10 = temp64[pb_var18_offset]
                u_var6 = local10 & 0xF
                u_var26 = local10 & 0xF0

                local_f0 = temp64[pb_var18_offset + 0x10]
                local_f1 = temp64[pb_var18_offset + 0x20]
                local_f2 = temp64[pb_var18_offset + 0x30]

                l_var2 = l_var9_xor * 0x18 + rnd * 0x60
                i_var25 = i_var15

                for l_var16 in range(3):
                    b_var3 = local_f0 if l_var16 == 0 else (local_f1 if l_var16 == 1 else local_f2)
                    u_var1 = (b_var3 << 4) & 0xFF
                    u_var27 = u_var6 | u_var1
                    u_var26 = (u_var26 >> 4) | ((b_var3 >> 4) << 4)

                    idx1 = (l_var2 + (i_var25 - 1)) * 0x100 + u_var27
                    u_var6 = tables["invXor"][idx1] & 0xF

                    idx2 = (l_var2 + i_var25) * 0x100 + u_var26
                    b_var3_new = tables["invXor"][idx2]
                    u_var26 = (b_var3_new & 0xF) << 4
                    i_var25 += 2

                state[l_var9_xor + l_var21_xor * 8] = (u_var26 | u_var6) & 0xFF
                pb_var18_offset += 4
            i_var15 += 6

    tmp32[:] = state
    u_var8 = 1
    u_var10 = 3
    u_var12 = 2

    for row in range(4):
        idx0 = tmp32[row] + row * 0x400
        state[row] = tables["invFirst"][idx0]

        row1 = u_var10 & 3
        idx1 = tmp32[8 + row1] + row1 * 0x400 + 0x100
        state[8 + row] = tables["invFirst"][idx1]

        row2 = u_var12 & 3
        idx2 = tmp32[0x10 + row2] + row2 * 0x400 + 0x200
        state[0x10 + row] = tables["invFirst"][idx2]

        row3 = u_var8 & 3
        idx3 = tmp32[0x18 + row3] + row3 * 0x400 + 0x300
        state[0x18 + row] = tables["invFirst"][idx3]

        u_var8 += 1
        u_var10 += 1
        u_var12 += 1

    _write_block_from_matrix(state, output)
    return bytes(output)


def _encrypt_block_auth(block: bytes, scratch: dict[str, bytearray]) -> bytes:
    tables = _load_tables()
    state = scratch["state32"]
    temp64 = scratch["temp64"]
    tmp32 = scratch["tmp32"]
    output = scratch["out"]

    _prepare_aes_matrix(block, state)

    for rnd in range(9):
        l_var21 = rnd * 4
        perm_ptr = 0

        for i in range(4):
            b_var4 = tables["permEncrypt"][perm_ptr]
            l_var16 = i * 8
            base = i * 16

            for j in range(4):
                u_var8 = (b_var4 + j) & 3
                byte_val = state[l_var16 + u_var8]
                idx = byte_val + (i + (l_var21 + u_var8) * 4) * 256
                value = _read_u32_le(tables["round"], idx * 4)
                _write_u32_le(temp64, base + j * 4, value)
            perm_ptr += 2

        i_var16 = 1
        for l_var22 in range(4):
            pb_var19_offset = l_var22
            for l_var10 in range(4):
                local10 = temp64[pb_var19_offset]
                u_var7 = local10 & 0xF
                u_var26 = local10 & 0xF0

                local_f0 = temp64[pb_var19_offset + 0x10]
                local_f1 = temp64[pb_var19_offset + 0x20]
                local_f2 = temp64[pb_var19_offset + 0x30]

                l_var2 = l_var10 * 0x18 + rnd * 0x60
                i_var25 = i_var16

                for l_var17 in range(3):
                    b_var4 = local_f0 if l_var17 == 0 else (local_f1 if l_var17 == 1 else local_f2)
                    u_var1 = (b_var4 << 4) & 0xFF
                    u_var27 = u_var7 | u_var1
                    u_var26 = (u_var26 >> 4) | ((b_var4 >> 4) << 4)

                    idx1 = (l_var2 + (i_var25 - 1)) * 0x100 + u_var27
                    u_var7 = tables["xor"][idx1] & 0xF

                    idx2 = (l_var2 + i_var25) * 0x100 + u_var26
                    b_var4_new = tables["xor"][idx2]
                    u_var26 = (b_var4_new & 0xF) << 4
                    i_var25 += 2

                state[l_var10 + l_var22 * 8] = (u_var26 | u_var7) & 0xFF
                pb_var19_offset += 4
            i_var16 += 6

    tmp32[:] = state
    u_var13 = 3
    u_var9 = 2
    u_var11 = 1
    u_var8 = 0

    for row in range(4):
        row0 = u_var8 & 3
        state[row] = tables["final"][tmp32[row0] + row0 * 0x400]

        row1 = u_var11 & 3
        state[8 + row] = tables["final"][tmp32[8 + row1] + row1 * 0x400 + 0x100]

        row2 = u_var9 & 3
        state[0x10 + row] = tables["final"][tmp32[0x10 + row2] + row2 * 0x400 + 0x200]

        row3 = u_var13 & 3
        state[0x18 + row] = tables["final"][tmp32[0x18 + row3] + row3 * 0x400 + 0x300]

        u_var8 += 1
        u_var11 += 1
        u_var9 += 1
        u_var13 += 1

    _write_block_from_matrix(state, output)
    return bytes(output)


def _xor_into(target: bytearray, source: bytes) -> None:
    for idx, src in enumerate(source):
        target[idx] ^= src


def _create_scratch() -> dict[str, bytearray]:
    return {
        "state32": bytearray(32),
        "tmp32": bytearray(32),
        "temp64": bytearray(64),
        "out": bytearray(16),
    }


def _decrypt_cbc(data: bytes, iv: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("Bangcle ciphertext length must be multiple of 16")
    if len(iv) != 16:
        raise ValueError("Bangcle CBC IV must be 16 bytes")

    scratch = _create_scratch()
    result = bytearray(len(data))
    prev = iv

    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        decrypted = bytearray(_decrypt_block_auth(block, scratch))
        _xor_into(decrypted, prev)
        result[offset : offset + 16] = decrypted
        prev = block

    return bytes(result)


def _encrypt_cbc(data: bytes, iv: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("Bangcle plaintext length must be multiple of 16")
    if len(iv) != 16:
        raise ValueError("Bangcle CBC IV must be 16 bytes")

    scratch = _create_scratch()
    result = bytearray(len(data))
    prev = iv

    for offset in range(0, len(data), 16):
        block = bytearray(data[offset : offset + 16])
        _xor_into(block, prev)
        encrypted = _encrypt_block_auth(bytes(block), scratch)
        result[offset : offset + 16] = encrypted
        prev = encrypted

    return bytes(result)


def _strip_pkcs7(buffer: bytes) -> bytes:
    if not buffer:
        return buffer
    pad = buffer[-1]
    if pad == 0 or pad > 16:
        return buffer
    if buffer[-pad:] != bytes([pad]) * pad:
        return buffer
    return buffer[:-pad]


def _add_pkcs7(buffer: bytes, block_size: int = 16) -> bytes:
    remainder = len(buffer) % block_size
    pad = block_size if remainder == 0 else block_size - remainder
    return buffer + bytes([pad]) * pad


def _normalise_checkcode_input(value: str) -> str:
    cleaned = re.sub(r"\s+", "", str(value or "")).strip()
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    if not cleaned:
        raise ValueError("Bangcle input is empty")
    if not cleaned.startswith("F"):
        raise ValueError('Bangcle envelope must start with "F"')
    cleaned = cleaned[1:]
    remainder = len(cleaned) % 4
    if remainder:
        cleaned = f"{cleaned}{'=' * (4 - remainder)}"
    return cleaned


def decode_envelope(envelope: str) -> bytes:
    payload = _normalise_checkcode_input(envelope)
    ciphertext = base64.b64decode(payload)
    if not ciphertext:
        raise ValueError("Bangcle ciphertext is empty")
    if len(ciphertext) % 16 != 0:
        raise ValueError(
            f"Bangcle ciphertext length {len(ciphertext)} is incompatible with 16-byte blocks"
        )
    plaintext = _decrypt_cbc(ciphertext, _ZERO_IV)
    return _strip_pkcs7(plaintext)


def encode_envelope(plaintext: str | bytes) -> str:
    plain_bytes = plaintext if isinstance(plaintext, bytes) else str(plaintext).encode("utf-8")
    padded = _add_pkcs7(plain_bytes)
    ciphertext = _encrypt_cbc(padded, _ZERO_IV)
    return f"F{base64.b64encode(ciphertext).decode('ascii')}"
