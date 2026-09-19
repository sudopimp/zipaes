"""Autocomprobación de punta a punta.

Este módulo es el corazón metodológico del paquete. La regla es simple:

    **Nunca lances un ataque real sin haber validado antes el emisor de hash
    contra un archivo de contraseña conocida.**

Un hash mal formado no falla: simplemente no encuentra nada, y podés dejar la GPU horas
trabajando sobre algo imposible. La autocomprobación construye un zip AES con una
contraseña conocida, recorre el flujo completo y verifica cada paso, incluido que el
hash emitido cumpla el formato que espera hashcat.

Uso::

    zipaes selftest
"""

from __future__ import annotations

import os
import tempfile
import time

from .crack import crack
from .crypto import verify
from .extract import extract_all
from .format import KEYLEN_BY_STRENGTH, METHOD_DEFLATE, inspect, salt_len_for
from .hashfmt import emit_hash
from .testkit import write_aes_zip

__all__ = ["run_selftest", "check_hash_format"]

#: contraseña de la fixture. No protege nada: es material de prueba.
FIXTURE_PASSWORD = "contrasena-de-prueba"

FIXTURE_FILES = {
    "carpeta/nota.txt": b"un archivo de prueba para la autocomprobacion\n",
    "datos.json": b'{"clave": "valor", "numero": 42}\n',
}


def check_hash_format(hash_line: str, strength: int) -> list[str]:
    """Valida el hash ``$zip2$`` campo por campo, según el parser de hashcat."""
    errors: list[str] = []
    tokens = hash_line.split("*")
    if len(tokens) != 10:
        errors.append(f"se esperaban 10 campos separados por '*', hay {len(tokens)}")
        return errors
    if tokens[0] != "$zip2$":
        errors.append("el hash debe empezar con $zip2$")
    if tokens[1] != "0":
        errors.append("el campo tipo (posición 1) debe ser 0")
    if tokens[2] != str(strength):
        errors.append(f"el campo fuerza (posición 2) debe ser {strength}")
    if tokens[3] != "0":
        errors.append("el campo magic (posición 3) debe ser 0")
    # El salt mide 4 + 4*fuerza bytes: 8 (AES-128), 12 (AES-192), 16 (AES-256).
    # hashcat exige exactamente esos largos en hex para cada modo.
    expected_salt = (4 + 4 * strength) * 2
    if len(tokens[4]) != expected_salt:
        errors.append(f"el salt debe medir {expected_salt} caracteres hex, mide {len(tokens[4])}")
    if not tokens[5] or len(tokens[5]) % 2:
        errors.append("el valor de verificación debe ser hex de longitud par")
    try:
        int(tokens[6], 16)
    except ValueError:
        errors.append("el largo del ciphertext (posición 6) debe ser hexadecimal")
    if len(tokens[8]) != 20:
        errors.append(f"el auth code debe ser 20 caracteres hex, tiene {len(tokens[8])}")
    if tokens[9] != "$/zip2$":
        errors.append("el hash debe terminar con $/zip2$")
    return errors


def run_selftest(strength: int = 3, aes_version: int = 2, compression: int = 0) -> dict:
    """Recorre el flujo completo sobre una fixture y devuelve un informe."""
    steps: list[dict] = []

    def step(name: str, ok: bool, detail: str = "") -> None:
        steps.append({"paso": name, "ok": bool(ok), "detalle": detail})

    with tempfile.TemporaryDirectory() as workdir:
        archive = os.path.join(workdir, "prueba.zip")
        write_aes_zip(
            archive,
            FIXTURE_FILES,
            FIXTURE_PASSWORD,
            strength=strength,
            aes_version=aes_version,
            compression=compression,
        )
        step("crear zip AES de prueba", os.path.isfile(archive), os.path.basename(archive))

        report = inspect(archive)
        step(
            "detectar entradas AES",
            len(report.aes) == len(FIXTURE_FILES),
            f"{len(report.aes)} de {len(FIXTURE_FILES)}",
        )
        entry = report.aes[0]
        expected_salt = salt_len_for(strength)
        step(
            "leer salt y verificacion",
            entry.salt_len == expected_salt and entry.pv,
            f"{entry.label}, salt de {entry.salt_len} bytes",
        )

        ok_correct = verify(entry, FIXTURE_PASSWORD)
        ok_wrong = verify(entry, FIXTURE_PASSWORD + "-mal")
        step("aceptar la clave correcta", ok_correct)
        step("rechazar una clave incorrecta", not ok_wrong)

        hash_line = emit_hash(entry)
        problems = check_hash_format(hash_line, strength)
        step("formato $zip2$ valido para hashcat", not problems, "; ".join(problems))

        found = crack(entry, words=["no-es", "tampoco", FIXTURE_PASSWORD], jobs=1)
        step("recuperar por diccionario", found == FIXTURE_PASSWORD, str(found))

        started = time.perf_counter()
        result = extract_all(archive, FIXTURE_PASSWORD, os.path.join(workdir, "salida"))
        elapsed = time.perf_counter() - started
        step(
            "extraer con la clave",
            result.ok and len(result.written) == len(FIXTURE_FILES),
            f"{len(result.written)} archivos en {elapsed:.3f}s",
        )

        restored = os.path.join(workdir, "salida", "carpeta", "nota.txt")
        with open(restored, "rb") as handle:
            recuperado = handle.read()
        step(
            "el contenido coincide byte a byte",
            recuperado == FIXTURE_FILES["carpeta/nota.txt"],
        )

    return {
        "resultado": "ok" if all(item["ok"] for item in steps) else "fallo",
        "fuerza": f"AES-{KEYLEN_BY_STRENGTH[strength] * 8}",
        "variante": f"AE-{aes_version}",
        "compresion": "deflate" if compression == METHOD_DEFLATE else "store",
        "pasos": steps,
    }
