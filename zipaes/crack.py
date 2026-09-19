"""Ataque de diccionario con verificación fuerte, en paralelo.

Este es el camino **lento pero correcto**: cada candidato se verifica recalculando el
``auth_code``, así que no hay falsos positivos y no depende de que el valor de verificación
tenga 2 bytes (el caso AE-1, donde el ataque por GPU del modo 13600 de hashcat no es fiable).

Para volúmenes grandes conviene el camino rápido: emitir el hash con
:func:`zipaes.hashfmt.emit_hash` y dejarlo en hashcat o John — ver :mod:`zipaes.backend`,
que se encarga de orquestarlos.
"""

from __future__ import annotations

from ._search import find_first
from .candidates import (  # noqa: F401  (reexportados por compatibilidad)
    build_wordlist,
    iter_candidates,
    mutations,
)
from .crypto import verify
from .format import AesEntry

__all__ = [
    "crack",
    "crack_entry",
    "iter_candidates",
    "mutations",
    "build_wordlist",
]


def _coincide(entry: AesEntry, candidato: str) -> bool:
    """Predicado de nivel de módulo (``multiprocessing`` necesita serializarlo)."""
    return verify(entry, candidato)


def crack_entry(entry: AesEntry, candidates) -> str | None:
    """Prueba candidatos en un solo proceso. Devuelve la contraseña o ``None``."""
    for candidate in candidates:
        if verify(entry, candidate):
            return candidate
    return None


def crack(
    entry: AesEntry,
    wordlist_path: str | None = None,
    *,
    words=None,
    jobs: int | None = None,
    with_mutations: bool = False,
) -> str | None:
    """Ataque de diccionario multiproceso contra una entrada AES.

    Pasá ``wordlist_path`` o ``words``. ``jobs`` por defecto usa todos los núcleos.
    Devuelve la contraseña encontrada o ``None``.
    """
    if wordlist_path is None and words is None:
        raise ValueError("hace falta wordlist_path o words")

    if wordlist_path:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as handle:
            candidates = list(iter_candidates(handle, with_mutations=with_mutations))
    else:
        candidates = list(iter_candidates(words or [], with_mutations=with_mutations))

    return find_first(candidates, entry, _coincide, jobs=jobs)
