"""Extracción de entradas AES con una contraseña conocida.

El módulo ``zipfile`` de la biblioteca estándar y la mayoría de las herramientas
``unzip`` **no** pueden abrir zips con cifrado AES. Este módulo sí, porque descifra
manualmente cada entrada.
"""

from __future__ import annotations

import os
import zipfile

from .crypto import WrongPassword, recover_plaintext, verify
from .format import AesEntry, inspect, parse_entry

__all__ = ["extract_all", "extract_entry", "safe_join", "ExtractionResult"]


class ExtractionResult:
    """Resultado de una extracción."""

    def __init__(self) -> None:
        self.written: list[str] = []
        self.failed: list[tuple[str, str]] = []
        self.skipped: list[str] = []

    @property
    def ok(self) -> bool:
        return not self.failed

    def summary(self) -> dict:
        return {
            "extraidos": len(self.written),
            "fallidos": len(self.failed),
            "omitidos": len(self.skipped),
            "detalle_fallidos": [{"nombre": n, "motivo": m} for n, m in self.failed],
        }


def safe_join(base: str, member: str) -> str:
    """Une rutas impidiendo que una entrada escape del directorio destino."""
    target = os.path.realpath(os.path.join(base, member))
    root = os.path.realpath(base)
    if target != root and not target.startswith(root + os.sep):
        raise ValueError(f"ruta fuera del destino: {member!r}")
    return target


def extract_entry(entry: AesEntry, password: str, destination: str) -> bytes:
    """Descifra una entrada y la escribe en ``destination``. Devuelve el contenido."""
    plaintext = recover_plaintext(entry, password)
    os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)
    with open(destination, "wb") as handle:
        handle.write(plaintext)
    return plaintext


def extract_all(
    archive_path: str,
    password: str,
    output_dir: str,
    *,
    entries: list[AesEntry] | None = None,
) -> ExtractionResult:
    """Extrae todas las entradas AES de un zip con la contraseña dada."""
    result = ExtractionResult()
    os.makedirs(output_dir, exist_ok=True)

    if entries is None:
        report = inspect(archive_path)
        entries = report.aes
        result.skipped.extend(report.plain)
        result.skipped.extend(report.zipcrypto)
        result.skipped.extend(report.other_encrypted)

    if entries and not verify(entries[0], password):
        raise WrongPassword("la contraseña no supera la verificación")

    for entry in entries:
        try:
            target = safe_join(output_dir, entry.name)
            extract_entry(entry, password, target)
            result.written.append(entry.name)
        except WrongPassword:
            result.failed.append((entry.name, "contraseña incorrecta"))
        except Exception as exc:  # noqa: BLE001 — una entrada rota no corta el resto
            result.failed.append((entry.name, f"{type(exc).__name__}: {exc}"))
    return result


def list_entries(archive_path: str) -> list[AesEntry]:
    """Atajo: todas las entradas AES del archivo."""
    with zipfile.ZipFile(archive_path) as archive, open(archive_path, "rb") as handle:
        found = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            try:
                found.append(parse_entry(handle, info))
            except Exception:  # noqa: BLE001 — entradas no AES se ignoran
                continue
        return found
