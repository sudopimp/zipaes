"""Ataque de diccionario con verificación fuerte, en paralelo.

Este es el camino **lento pero correcto**: cada candidato se verifica recalculando el
``auth_code``, así que no hay falsos positivos y no depende de que el valor de verificación
tenga 2 bytes (el caso AE-1, donde el ataque por GPU del modo 13600 de hashcat no es fiable).

Para volúmenes grandes conviene el camino rápido: emitir el hash con
:func:`zipaes.hashfmt.emit_hash` y dejarlo en hashcat o John — ver
:mod:`zipaes.backend`, que se encarga de orquestarlos.
"""

from __future__ import annotations

import os

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


def _init_worker(entry: AesEntry) -> None:
    global _ENTRY
    _ENTRY = entry


def _worker(candidates: list[str]) -> str | None:
    for candidate in candidates:
        if verify(_ENTRY, candidate):
            return candidate
    return None


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

    if not candidates:
        return None

    jobs = jobs or os.cpu_count() or 1
    if jobs <= 1 or len(candidates) < 2000:
        return crack_entry(entry, candidates)

    from multiprocessing import Pool

    chunks = [candidates[index::jobs] for index in range(jobs)]
    with Pool(jobs, initializer=_init_worker, initargs=(entry,)) as pool:
        for result in pool.imap_unordered(_worker, chunks):
            if result:
                pool.terminate()
                return result
    return None
