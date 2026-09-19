"""Emisión de hashes para herramientas externas de recuperación.

El formato ``$zip2$`` es el que consumen **John the Ripper (jumbo)** y
**hashcat modo 13600**. Ni hashcat ni John aceptan un ``.zip`` directamente: hay que
extraer el hash primero.

    $zip2$*0*<fuerza>*0*<salt_hex>*<pv_hex>*<largo_ct_hex>*<ct_hex>*<auth_hex>*$/zip2$

Cada campo, según el parser de hashcat (``module_13600.c``):

    0: literal "$zip2$"
    1: tipo            (fijo 0)
    2: fuerza          (1=AES-128, 2=AES-192, 3=AES-256)  -> define el largo del salt
    3: magic           (fijo 0)
    4: salt            en hex (16/24/32 caracteres según fuerza)
    5: valor de verificación de clave, en hex (1 byte en AE-1, 2 en AE-2)
    6: largo del ciphertext, en hex
    7: ciphertext, en hex
    8: auth code (10 bytes) en hex
    9: literal "$/zip2$"

Nota importante sobre el campo 5: el kernel de hashcat compara **16 bits**, así que
funciona con el ``pv`` de 2 bytes y no con el de 1 byte de AE-1. Para archivos AE-1 el
ataque por GPU no es fiable; conviene usar el verificador propio de este paquete.
"""

from __future__ import annotations

from .format import AUTH_CODE_LEN, KEYLEN_BY_STRENGTH, AesEntry

__all__ = ["emit_hash", "emit_hash_line", "HASHCAT_MODE"]

#: modo de hashcat para WinZip AES
HASHCAT_MODE = 13600

#: modo de hashcat para PKZIP tradicional (ZipCrypto), por referencia
HASHCAT_MODE_ZIPCRYPTO = 17200


def emit_hash(entry: AesEntry, *, prefix_name: bool = False) -> str:
    """Devuelve el hash ``$zip2$`` de una entrada AES.

    Con ``prefix_name=True`` antepone ``nombre:`` como hace ``zip2john``, útil cuando
    se procesan varias entradas a la vez.
    """
    if entry.strength not in KEYLEN_BY_STRENGTH:
        raise ValueError(f"fuerza AES no válida: {entry.strength}")

    body = (
        f"$zip2$*0*{entry.strength}*0*"
        f"{entry.salt.hex()}*"
        f"{entry.pv.hex()}*"
        f"{entry.ct_len:x}*"
        f"{entry.ciphertext.hex()}*"
        f"{entry.auth_code.hex()}*"
        f"$/zip2$"
    )
    return f"{entry.name}:{body}" if prefix_name else body


def emit_hash_line(entry: AesEntry, filename: str | None = None) -> str:
    """Hash con el nombre del archivo al frente, al estilo ``zip2john``."""
    body = emit_hash(entry)
    label = filename or entry.name
    return f"{label}:{body}"


def sanity_check(entry: AesEntry) -> list[str]:
    """Avisos sobre la entrada que afectan la estrategia de recuperación."""
    warnings: list[str] = []
    expected_salt = 4 + 4 * entry.strength
    if len(entry.salt) != expected_salt:
        warnings.append(f"el salt mide {len(entry.salt)} bytes y se esperaban {expected_salt}")
    if len(entry.auth_code) != AUTH_CODE_LEN:
        warnings.append(f"el auth code mide {len(entry.auth_code)} bytes, no 10")
    if entry.aes_version == 1:
        warnings.append(
            "AE-1: el valor de verificación mide 1 byte (1 de cada 256 candidatos "
            "falsos lo supera) y hashcat compara 16 bits, así que el modo 13600 puede "
            "no encontrarlo. Usá el verificador propio."
        )
    return warnings
