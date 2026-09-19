"""Constantes y parseo del formato ZIP con cifrado AES (WinZip AES / AE-1 / AE-2).

El módulo estándar ``zipfile`` de Python **no** soporta AES: reporta el método de
compresión 99 y falla con ``RuntimeError: ... is encrypted``. Este módulo extrae
manualmente lo que hace falta para auditar y descifrar esas entradas:

    cabecera local -> salt (16 B) -> valor de verificación -> ciphertext -> auth code

Referencias del formato:
  * PKWARE APPNOTE 6.3.x, sección 4.4.4 (AES Encryption)
  * https://www.winzip.com/en/support/aes-encryption/
"""

from __future__ import annotations

import os
import struct
import zipfile
from dataclasses import dataclass, field

# --- firmas ZIP -------------------------------------------------------------- #
SIG_LOCAL = 0x04034B50
SIG_CENTRAL = 0x02014B50
SIG_EOCD = 0x06054B50

# --- cifrado ----------------------------------------------------------------- #
EXTRA_AES = 0x9901  # extra field que marca una entrada AES
VENDOR_AE = b"AE"  # identificador de vendor WinZip AES
METHOD_AES = 99  # compression method que anuncia AES
METHOD_STORE = 0
METHOD_DEFLATE = 8

AES_VER_AE1 = 1
AES_VER_AE2 = 2

#: bytes de clave por nivel de fuerza (1=128, 2=192, 3=256)
KEYLEN_BY_STRENGTH = {1: 16, 2: 24, 3: 32}

SALT_LEN_BASE = 4  # el salt mide 4 + 4*fuerza bytes: 8, 12 o 16
AUTH_CODE_LEN = 10  # HMAC-SHA1 truncado
PBKDF2_ITERATIONS = 1000  # fijo en la especificación WinZip AES
PV_LEN_BY_VERSION = {AES_VER_AE1: 1, AES_VER_AE2: 2}


def salt_len_for(strength: int) -> int:
    """Longitud del salt según la fuerza: 8 (AES-128), 12 (AES-192), 16 (AES-256)."""
    if strength not in KEYLEN_BY_STRENGTH:
        raise ValueError(f"fuerza AES no válida: {strength}")
    return SALT_LEN_BASE + 4 * strength


class NotAesError(ValueError):
    """La entrada no usa cifrado AES (WinZip)."""


class NotEncryptedError(ValueError):
    """La entrada no está cifrada."""


@dataclass
class AesEntry:
    """Todo lo necesario para verificar o descifrar una entrada AES."""

    name: str
    header_offset: int
    aes_version: int
    strength: int
    compression: int
    crc: int
    csize: int  # tamaño del blob cifrado completo (salt+pv+ct+auth)
    usize: int  # tamaño sin comprimir
    salt: bytes
    pv: bytes
    ciphertext: bytes
    auth_code: bytes
    flags: int = 0

    # --- derivados --------------------------------------------------------- #
    @property
    def keylen(self) -> int:
        return KEYLEN_BY_STRENGTH[self.strength]

    @property
    def keylen_bits(self) -> int:
        return self.keylen * 8

    @property
    def pv_len(self) -> int:
        return len(self.pv)

    @property
    def salt_len(self) -> int:
        return len(self.salt)

    @property
    def ct_len(self) -> int:
        return len(self.ciphertext)

    @property
    def label(self) -> str:
        return f"AE-{self.aes_version}"

    @property
    def is_encrypted(self) -> bool:
        return True

    def summary(self) -> dict:
        return {
            "nombre": self.name,
            "formato": self.label,
            "fuerza": f"AES-{self.keylen_bits}",
            "salt": self.salt.hex(),
            "verificacion_clave": self.pv.hex(),
            "bytes_verificacion": self.pv_len,
            "ciphertext": self.ct_len,
            "auth_code": self.auth_code.hex(),
            "crc": f"{self.crc:08x}",
            "comprimido": self.csize,
            "sin_comprimir": self.usize,
            "metodo_real": self.compression,
        }


@dataclass
class ArchiveReport:
    """Panorama de un archivo .zip: cuántas entradas y con qué cifrado."""

    path: str
    total: int = 0
    aes: list[AesEntry] = field(default_factory=list)
    zipcrypto: list[str] = field(default_factory=list)
    plain: list[str] = field(default_factory=list)
    other_encrypted: list[str] = field(default_factory=list)

    @property
    def encrypted(self) -> bool:
        return bool(self.aes or self.zipcrypto or self.other_encrypted)

    def summary(self) -> dict:
        return {
            "archivo": self.path,
            "entradas": self.total,
            "aes": len(self.aes),
            "zipcrypto": len(self.zipcrypto),
            "sin_cifrar": len(self.plain),
            "otros_cifrados": len(self.other_encrypted),
            "primera_entrada_aes": self.aes[0].name if self.aes else None,
        }


def _parse_aes_extra(extra: bytes) -> tuple[int, int, int] | None:
    """Devuelve (version AES, fuerza, método real) del extra field 0x9901."""
    offset = 0
    while offset + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, offset)
        data = extra[offset + 4 : offset + 4 + size]
        if header_id == EXTRA_AES and len(data) >= 7:
            _version, vendor, strength, method = struct.unpack_from("<H2sBH", data, 0)
            if vendor == VENDOR_AE:
                # Una versión no reconocida se trata como AE-2 (2 bytes de pv),
                # que es la convención de zip2john/hashcat.
                return (_version if _version in (1, 2) else AES_VER_AE2, strength, method)
            raise NotAesError(f"vendor AES desconocido: {vendor!r}")
        offset += 4 + size
    return None


def parse_entry(handle, info: zipfile.ZipInfo) -> AesEntry:
    """Parsea una entrada AES leyendo cabecera local + blob cifrado."""
    handle.seek(info.header_offset)
    raw = handle.read(30)
    if len(raw) < 30:
        raise ValueError("cabecera local truncada")
    (_sig, _ver, flags, declared_method, _t, _d, crc, csize, usize, name_len, extra_len) = (
        struct.unpack("<IHHHHHIIIHH", raw)
    )

    # El orden importa: "no está cifrado" es más informativo que "no es AES".
    if not (flags & 0x1):
        raise NotEncryptedError(f"{info.filename!r} no está cifrado")
    if declared_method != METHOD_AES:
        raise NotAesError(f"método {declared_method} != {METHOD_AES} (no es AES)")

    parsed = _parse_aes_extra(info.extra)
    if parsed is None:
        raise NotAesError(f"{info.filename!r} no declara el extra field AES (0x9901)")
    aes_version, strength, method = parsed
    if strength not in KEYLEN_BY_STRENGTH:
        raise NotAesError(f"fuerza AES inválida: {strength}")
    salt_len = salt_len_for(strength)

    data_offset = info.header_offset + 30 + name_len + extra_len
    handle.seek(data_offset)
    blob = handle.read(csize)
    if len(blob) != csize:
        raise ValueError("blob cifrado truncado")

    pv_len = PV_LEN_BY_VERSION.get(aes_version, 2)
    if csize <= salt_len + pv_len + AUTH_CODE_LEN:
        raise ValueError("tamaño cifrado incompatible con una entrada AES")

    return AesEntry(
        name=info.filename,
        header_offset=info.header_offset,
        aes_version=aes_version,
        strength=strength,
        compression=method,
        crc=crc,
        csize=csize,
        usize=usize,
        salt=blob[:salt_len],
        pv=blob[salt_len : salt_len + pv_len],
        ciphertext=blob[salt_len + pv_len : csize - AUTH_CODE_LEN],
        auth_code=blob[csize - AUTH_CODE_LEN :],
        flags=flags,
    )


def inspect(path: str) -> ArchiveReport:
    """Clasifica todas las entradas de un zip: AES, ZipCrypto, planas u otras."""
    report = ArchiveReport(path=path)
    with zipfile.ZipFile(path) as archive, open(path, "rb") as handle:
        for info in archive.infolist():
            if info.is_dir():
                continue
            report.total += 1
            try:
                report.aes.append(parse_entry(handle, info))
                continue
            except NotEncryptedError:
                report.plain.append(info.filename)
                continue
            except NotAesError:
                pass
            # cifrado, pero no AES -> ZipCrypto tradicional (método 1)
            if info.flag_bits & 0x1:
                if (info.compress_type or 0) <= 1:
                    report.zipcrypto.append(info.filename)
                else:
                    report.other_encrypted.append(info.filename)
            else:
                report.plain.append(info.filename)
    return report


def looks_like_zip(path: str) -> bool:
    """Comprueba la firma sin abrir el archivo completo."""
    if not os.path.isfile(path):
        return False
    with open(path, "rb") as handle:
        return handle.read(4) in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
