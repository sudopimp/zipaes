"""Criptografía de WinZip AES: derivación de claves, keystream, verificación y descifrado.

Resumen del esquema (APPNOTE 6.3.x §4.4.4 y winzip.com/aes_info):

    DK        = PBKDF2-HMAC-SHA1(password, salt, 1000 iteraciones, 2*keylen + pvlen)
    enc_key   = DK[0 : keylen]
    mac_key   = DK[keylen : 2*keylen]
    pv        = DK[2*keylen : 2*keylen + pvlen]      # valor de verificación de clave

    ciphertext = AES-CTR(enc_key, datos, contador inicial = 1, little-endian)
    auth_code  = HMAC-SHA1(mac_key, ciphertext)[:10]

El ``pv`` se guarda en claro dentro del archivo y sirve como filtro rápido. **No es una
prueba de que la contraseña sea correcta**: con AE-1 mide 1 byte, así que uno de cada
256 candidatos falsos lo supera. La única verificación concluyente es recalcular el
``auth_code`` sobre el ciphertext.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .format import (
    AUTH_CODE_LEN,
    PBKDF2_ITERATIONS,
    AesEntry,
    salt_len_for,
)

__all__ = [
    "derive_keys",
    "keystream",
    "decrypt_ciphertext",
    "verify",
    "verify_auth_code",
    "verify_pv",
    "recover_plaintext",
    "decode_plaintext",
    "salt_is_consistent",
    "WrongPassword",
]

AES_BLOCK = 16


class WrongPassword(Exception):
    """La contraseña candidata no supera la verificación del auth code."""


def derive_keys(
    password: str | bytes,
    salt: bytes,
    keylen: int,
    pv_len: int = 2,
    iterations: int = PBKDF2_ITERATIONS,
) -> tuple[bytes, bytes, bytes]:
    """Devuelve ``(enc_key, mac_key, pv)`` para una contraseña candidata."""
    if isinstance(password, str):
        password = password.encode("utf-8", "ignore")
    derived = hashlib.pbkdf2_hmac("sha1", password, salt, iterations, 2 * keylen + pv_len)
    return derived[:keylen], derived[keylen : 2 * keylen], derived[2 * keylen :]


def keystream(enc_key: bytes, length: int) -> bytes:
    """Genera el keystream AES-CTR de WinZip.

    El contador es de 128 bits en **little-endian** y arranca en 1; por eso no sirve el
    modo CTR estándar de las librerías (que es big-endian sobre el valor completo).
    Se construye bloque a bloque con AES-ECB.
    """
    if length <= 0:
        return b""
    blocks = (length + AES_BLOCK - 1) // AES_BLOCK
    encryptor = Cipher(algorithms.AES(enc_key), modes.ECB()).encryptor()
    counters = b"".join((index + 1).to_bytes(AES_BLOCK, "little") for index in range(blocks))
    return encryptor.update(counters)[:length]


def decrypt_ciphertext(enc_key: bytes, ciphertext: bytes) -> bytes:
    """Aplica el keystream (XOR) para recuperar el texto cifrado en claro."""
    stream = keystream(enc_key, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream, strict=True))


def verify_pv(entry: AesEntry, password: str | bytes) -> bool:
    """Chequeo rápido contra el valor de verificación. Filtro, no prueba."""
    enc_key, _, pv = derive_keys(password, entry.salt, entry.keylen, entry.pv_len)
    del enc_key  # solo hace falta el pv aquí
    return hmac.compare_digest(pv, entry.pv)


def verify_auth_code(entry: AesEntry, password: str | bytes) -> bool:
    """Verificación concluyente: recalcula el auth code sobre el ciphertext."""
    _, mac_key, _ = derive_keys(password, entry.salt, entry.keylen, entry.pv_len)
    expected = hmac.new(mac_key, entry.ciphertext, hashlib.sha1).digest()[:AUTH_CODE_LEN]
    return hmac.compare_digest(expected, entry.auth_code)


def verify(entry: AesEntry, password: str | bytes) -> bool:
    """Verificación completa: pv primero (barato), auth code después (concluyente)."""
    if not verify_pv(entry, password):
        return False
    return verify_auth_code(entry, password)


def decode_plaintext(entry: AesEntry, plaintext: bytes) -> bytes:
    """Descomprime el resultado según el método real declarado en el extra field."""
    from .format import METHOD_DEFLATE

    if entry.compression == METHOD_DEFLATE:
        import zlib

        return zlib.decompress(plaintext, -15)
    return plaintext


def recover_plaintext(entry: AesEntry, password: str | bytes) -> bytes:
    """Descifra y descomprime una entrada, o levanta ``WrongPassword``."""
    enc_key, _, _ = derive_keys(password, entry.salt, entry.keylen, entry.pv_len)
    clear = decrypt_ciphertext(enc_key, entry.ciphertext)
    if not verify_auth_code(entry, password):
        raise WrongPassword(f"contraseña incorrecta para {entry.name!r}")
    return decode_plaintext(entry, clear)


def salt_is_consistent(entry: AesEntry) -> bool:
    """El salt debe medir 4 + 4*fuerza bytes: 8 (AES-128), 12 (AES-192), 16 (AES-256)."""
    try:
        return len(entry.salt) == salt_len_for(entry.strength)
    except ValueError:
        return False
