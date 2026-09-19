"""Escritor de zips con cifrado AES — kit de pruebas.

Existe por una razón concreta de metodología: **antes de gastar horas de GPU hay que
validar que el emisor de hash produce lo que corresponde**. La forma de hacerlo es
construir un archivo con contraseña *conocida* y comprobar de punta a punta que el
flujo (detectar -> emitir -> verificar -> descifrar) devuelve esa contraseña.

Tener el escritor dentro del paquete hace que las pruebas sean herméticas: no dependen
de 7-Zip ni de ninguna herramienta externa.

No está pensado para producir archivos de producción: implementa el subconjunto
necesario (`store` y `deflate`, un disco, sin zip64, sin data descriptor).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import zlib

from .crypto import derive_keys, keystream
from .format import (
    AUTH_CODE_LEN,
    EXTRA_AES,
    KEYLEN_BY_STRENGTH,
    METHOD_AES,
    METHOD_DEFLATE,
    METHOD_STORE,
    SIG_CENTRAL,
    SIG_EOCD,
    SIG_LOCAL,
    VENDOR_AE,
    salt_len_for,
)

__all__ = ["write_aes_zip", "press_entry", "build_extra"]

VERSION_NEEDED_AES = 51
DOS_DATE = (0x5A << 9) | (1 << 5) | 1  # 2025-01-01
DOS_TIME = 0


def press_entry(data: bytes, compression: int) -> bytes:
    """Comprime según el método pedido (0 = store, 8 = deflate)."""
    if compression == METHOD_DEFLATE:
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        return compressor.compress(data) + compressor.flush()
    if compression == METHOD_STORE:
        return data
    raise ValueError(f"método de compresión no soportado: {compression}")


def build_extra(aes_version: int, strength: int, compression: int) -> bytes:
    """Construye el extra field 0x9901 que marca la entrada como AES."""
    payload = struct.pack("<H2sBH", aes_version, VENDOR_AE, strength, compression)
    return struct.pack("<HH", EXTRA_AES, len(payload)) + payload


def write_aes_zip(
    path: str,
    entries: dict[str, bytes] | list[tuple[str, bytes]],
    password: str,
    *,
    strength: int = 3,
    aes_version: int = 2,
    compression: int = METHOD_STORE,
    salt: bytes | None = None,
) -> str:
    """Escribe un zip AES y devuelve la ruta.

    ``aes_version`` selecciona AE-1 (1 byte de verificación, CRC real) o AE-2
    (2 bytes, CRC en cero). ``salt`` permite fijar el salt para pruebas reproducibles.
    """
    if isinstance(entries, dict):
        entries = list(entries.items())
    if strength not in KEYLEN_BY_STRENGTH:
        raise ValueError("strength debe ser 1, 2 o 3")
    if aes_version not in (1, 2):
        raise ValueError("aes_version debe ser 1 (AE-1) o 2 (AE-2)")

    keylen = KEYLEN_BY_STRENGTH[strength]
    pv_len = 1 if aes_version == 1 else 2
    salt_bytes = salt_len_for(strength)
    fixed_salt = salt
    if fixed_salt is not None and len(fixed_salt) != salt_bytes:
        raise ValueError(
            f"el salt debe medir {salt_bytes} bytes para AES-{keylen * 8}, mide {len(fixed_salt)}"
        )

    out = bytearray()
    directory = bytearray()

    for name, data in entries:
        name_bytes = name.encode("utf-8")
        compressed = press_entry(data, compression)
        crc = zlib.crc32(data) & 0xFFFFFFFF

        entry_salt = fixed_salt or os.urandom(salt_bytes)
        enc_key, mac_key, pv = derive_keys(password, entry_salt, keylen, pv_len)

        stream = keystream(enc_key, len(compressed))
        ciphertext = bytes(a ^ b for a, b in zip(compressed, stream, strict=True))
        auth_code = hmac.new(mac_key, ciphertext, hashlib.sha1).digest()[:AUTH_CODE_LEN]

        blob = entry_salt + pv + ciphertext + auth_code
        csize = len(blob)
        extra = build_extra(aes_version, strength, compression)
        offset = len(out)
        # AE-2 exige CRC en cero; AE-1 conserva el CRC real.
        stored_crc = crc if aes_version == 1 else 0

        out += struct.pack(
            "<IHHHHHIIIHH",
            SIG_LOCAL,
            VERSION_NEEDED_AES,
            0x0001,  # bit 0: cifrado
            METHOD_AES,
            DOS_TIME,
            DOS_DATE,
            stored_crc,
            csize,
            len(data),
            len(name_bytes),
            len(extra),
        )
        out += name_bytes + extra + blob

        directory += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            SIG_CENTRAL,
            VERSION_NEEDED_AES,
            VERSION_NEEDED_AES,
            0x0001,
            METHOD_AES,
            DOS_TIME,
            DOS_DATE,
            stored_crc,
            csize,
            len(data),
            len(name_bytes),
            len(extra),
            0,  # comentario
            0,  # disco
            0,  # atributos internos
            0,  # atributos externos
            offset,
        )
        directory += name_bytes + extra

    directory_offset = len(out)
    out += directory
    out += struct.pack(
        "<IHHHHIIH",
        SIG_EOCD,
        0,
        0,
        len(entries),
        len(entries),
        len(directory),
        directory_offset,
        0,
    )

    with open(path, "wb") as handle:
        handle.write(bytes(out))
    return path
