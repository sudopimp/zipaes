"""Cifrado tradicional de PKWARE (ZipCrypto).

Hasta ahora el paquete detectaba ZipCrypto y derivaba a hashcat ``--mode 17200``. Ese
desvío dejaba un hueco real: no había forma de *verificar* ni de *atacar* esos archivos
con las mismas garantías que los AES. Este módulo lo cierra.

ZipCrypto no es AES: usa un generador pseudoaleatorio propio de 3 claves de 32 bits, sin
KDF y sin autenticación. Eso tiene dos consecuencias prácticas:

* es **enormemente más rápido** de probar (no hay 1000 iteraciones de PBKDF2);
* su "valor de verificación" es **1 byte**, así que un filtro rápido deja pasar 1 de cada
  256 candidatos falsos. La comprobación concluyente es descifrar el contenido y comparar
  el CRC, que es lo que hace :func:`verify` cuando el filtro da positivo.

Referencia: APPNOTE de PKWARE 6.3.x §4.4.5 y el clásico ``pkcrack``.
"""

from __future__ import annotations

import os
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ._search import find_first

__all__ = [
    "ZipCryptoEntry",
    "ZipCryptoKeys",
    "parse_zipcrypto_entry",
    "derive_keys",
    "decrypt",
    "verify",
    "crack",
    "header_check_byte",
]

MULT = 134775813
CRYPT_HEADER_LEN = 12
FLAG_ENCRYPTED = 0x1
FLAG_DATA_DESCRIPTOR = 0x8


def _build_crc_table() -> list[int]:
    """Tabla CRC-32 de PKWARE (polinomio 0xEDB88320)."""
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        table.append(value & 0xFFFFFFFF)
    return table


#: Tabla CRC-32 de PKWARE. Se usa explícitamente y **no** `zlib.crc32`:
#: la función de zlib aplica el acondicionamiento previo y posterior del CRC estándar,
#: así que `zlib.crc32(un_byte, anterior)` NO es la actualización cruda de PKWARE.
_CRC_TABLE = _build_crc_table()


def _crc32_update(crc: int, byte: int) -> int:
    """Actualización CRC-32 cruda de PKWARE para un byte."""
    return ((crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]) & 0xFFFFFFFF


@dataclass
class ZipCryptoKeys:
    """Estado de las tres claves del generador de ZipCrypto."""

    key0: int = 0x12345678
    key1: int = 0x23456789
    key2: int = 0x34567890

    def update(self, byte: int) -> None:
        self.key0 = _crc32_update(self.key0, byte)
        self.key1 = (self.key1 + (self.key0 & 0xFF)) & 0xFFFFFFFF
        self.key1 = (self.key1 * MULT + 1) & 0xFFFFFFFF
        self.key2 = _crc32_update(self.key2, (self.key1 >> 24) & 0xFF)

    def stream_byte(self) -> int:
        """Siguiente byte del keystream (no avanza el estado por sí solo)."""
        temp = (self.key2 | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    def peek(self) -> int:
        return self.stream_byte()


def derive_keys(password: str | bytes) -> ZipCryptoKeys:
    """Inicializa las claves a partir de la contraseña."""
    if isinstance(password, str):
        password = password.encode("utf-8", "ignore")
    keys = ZipCryptoKeys()
    for byte in password:
        keys.update(byte)
    return keys


def _decrypt_block(keys: ZipCryptoKeys, data: bytes) -> bytes:
    """Descifra un bloque avanzando el estado de claves dado."""
    out = bytearray(len(data))
    for index, byte in enumerate(data):
        plain = byte ^ keys.stream_byte()
        keys.update(plain)
        out[index] = plain
    return bytes(out)


def _decrypt_bytes(data: bytes, password: str | bytes) -> bytes:
    """Descifra un bloque completo desde el estado inicial de la contraseña."""
    return _decrypt_block(derive_keys(password), data)


def decrypt(entry: ZipCryptoEntry, password: str | bytes) -> bytes:
    """Descifra el contenido de la entrada (sin descomprimir).

    Importante: hay que **consumir primero la cabecera de cifrado de 12 bytes** para
    avanzar el estado de claves. Descifrar los datos desde el estado inicial de la
    contraseña produce basura, aunque el chequeo de la cabecera dé bien.
    """
    keys = derive_keys(password)
    _decrypt_block(keys, entry.crypt_header)
    return _decrypt_block(keys, entry.data)


@dataclass
class ZipCryptoEntry:
    """Una entrada cifrada con ZipCrypto."""

    name: str
    header_offset: int
    flags: int
    compression: int
    crc: int
    csize: int  # incluye los 12 bytes de cabecera de cifrado
    usize: int
    dos_time: int
    crypt_header: bytes
    data: bytes  # ciphertext, sin la cabecera de 12 bytes

    @property
    def has_data_descriptor(self) -> bool:
        return bool(self.flags & FLAG_DATA_DESCRIPTOR)

    @property
    def ct_len(self) -> int:
        return len(self.data)

    def check_byte(self) -> int:
        """Byte esperado al final de la cabecera de cifrado.

        Con el bit 3 activo (data descriptor) el CRC de la cabecera local puede ser cero,
        así que la convención es usar el byte alto de la hora DOS.
        """
        return header_check_byte(self.flags, self.crc, self.dos_time)

    def summary(self) -> dict:
        return {
            "nombre": self.name,
            "formato": "ZipCrypto",
            "flags": f"0x{self.flags:04x}",
            "data_descriptor": self.has_data_descriptor,
            "metodo_real": self.compression,
            "crc": f"{self.crc:08x}",
            "cifrado": self.csize,
            "sin_comprimir": self.usize,
        }


def header_check_byte(flags: int, crc: int, dos_time: int) -> int:
    """Byte de verificación de la cabecera de cifrado, según el bit 3."""
    if flags & FLAG_DATA_DESCRIPTOR:
        return (dos_time >> 8) & 0xFF
    return (crc >> 24) & 0xFF


def parse_zipcrypto_entry(handle, info, *, csize: int, usize: int) -> ZipCryptoEntry:
    """Parsea una entrada ZipCrypto.

    ``csize`` y ``usize`` se pasan explícitamente porque conviene tomarlos del directorio
    central: con el bit 3 activo (data descriptor) la cabecera local los tiene en cero.
    """
    handle.seek(info.header_offset)
    raw = handle.read(30)
    if len(raw) < 30:
        raise ValueError("cabecera local truncada")
    import struct

    (_sig, _ver, flags, method, dos_time, _dos_date, crc, _lc, _lu, name_len, extra_len) = (
        struct.unpack("<IHHHHHIIIHH", raw)
    )

    if not (flags & FLAG_ENCRYPTED):
        raise ValueError(f"{info.filename!r} no está cifrado")
    if csize < CRYPT_HEADER_LEN:
        raise ValueError("tamaño cifrado menor que la cabecera de cifrado")

    data_offset = info.header_offset + 30 + name_len + extra_len

    # Igual que en el parser AES: el tamaño declarado no se cree sin más.
    disponible = os.fstat(handle.fileno()).st_size - data_offset
    if csize > disponible:
        raise ValueError(
            f"el tamaño declarado ({csize}) excede lo que queda del archivo ({disponible})"
        )

    handle.seek(data_offset)
    blob = handle.read(csize)
    if len(blob) != csize:
        raise ValueError("blob cifrado truncado")

    return ZipCryptoEntry(
        name=info.filename,
        header_offset=info.header_offset,
        flags=flags,
        compression=method,
        crc=crc or info.CRC,
        csize=csize,
        usize=usize,
        dos_time=dos_time,
        crypt_header=blob[:CRYPT_HEADER_LEN],
        data=blob[CRYPT_HEADER_LEN:],
    )


def _inflate(data: bytes, method: int) -> bytes:
    if method == 8:
        return zlib.decompress(data, -15)
    if method == 0:
        return data
    raise ValueError(f"método de compresión no soportado: {method}")


def passes_header_check(entry: ZipCryptoEntry, password: str | bytes) -> bool:
    """Filtro rápido de 1 byte. **No** es prueba de que la contraseña sea correcta."""
    clear = _decrypt_bytes(entry.crypt_header, password)
    return clear[-1] == entry.check_byte()


def verify(entry: ZipCryptoEntry, password: str | bytes) -> bool:
    """Verificación concluyente: descifra y compara el CRC del contenido.

    El filtro de 1 byte va primero porque es mucho más barato; sólo si pasa se hace el
    trabajo completo. Un falso positivo del filtro no sobrevive a la comparación del CRC,
    salvo colisión de 32 bits.
    """
    if not passes_header_check(entry, password):
        return False
    try:
        plain = _inflate(decrypt(entry, password), entry.compression)
    except Exception:  # noqa: BLE001 — un candidato falso suele romper el inflate
        return False
    return zlib.crc32(plain) & 0xFFFFFFFF == entry.crc & 0xFFFFFFFF


def _coincide(entry: ZipCryptoEntry, candidato: str) -> bool:
    """Predicado de nivel de módulo (``multiprocessing`` necesita serializarlo).

    Filtro barato primero; sólo si pasa se hace el trabajo completo.
    """
    return passes_header_check(entry, candidato) and verify(entry, candidato)


def _iter_candidates(words: Iterable[str], min_len: int, max_len: int) -> Iterator[str]:
    for word in words:
        candidate = word.rstrip("\r\n")
        if candidate and min_len <= len(candidate) <= max_len:
            yield candidate


def crack(
    entry: ZipCryptoEntry,
    wordlist_path: str | None = None,
    *,
    words: Iterable[str] | None = None,
    jobs: int | None = None,
    min_len: int = 1,
    max_len: int = 256,
) -> str | None:
    """Ataque de diccionario contra una entrada ZipCrypto.

    Es mucho más rápido que contra AES: no hay derivación de claves, así que se pueden
    probar cientos de miles de candidatos por segundo y por núcleo.
    """
    if wordlist_path is None and words is None:
        raise ValueError("hace falta wordlist_path o words")

    if wordlist_path:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as handle:
            candidates = list(_iter_candidates(handle, min_len, max_len))
    else:
        candidates = list(_iter_candidates(iter(words or []), min_len, max_len))

    return find_first(candidates, entry, _coincide, jobs=jobs, minimo_paralelo=5000)
