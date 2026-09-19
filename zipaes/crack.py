"""Ataque de diccionario con verificación fuerte, en paralelo.

Este es el camino **lento pero correcto**: cada candidato se verifica recalculando el
auth code, así que no hay falsos positivos ni depende de que el ``pv`` tenga 2 bytes.

Para volúmenes grandes conviene el camino rápido: emitir el hash con ``emit_hash`` y
dejarlo en hashcat (modo 13600) o John. La regla práctica es validar primero el emisor
con el kit de pruebas, atacar por GPU, y confirmar el candidato con este verificador.
"""

from __future__ import annotations

import itertools
import os
import string
from collections.abc import Iterable, Iterator

from .crypto import verify
from .format import AesEntry

__all__ = ["crack", "crack_entry", "mutations", "iter_candidates", "build_wordlist"]

DEFAULT_MUTATIONS = (
    "",
    "1",
    "12",
    "123",
    "1234",
    "12345",
    "2024",
    "2025",
    "2026",
    "!",
    "!!",
    "@",
    "#",
    ".",
    "_",
)


def mutations(word: str, suffixes: Iterable[str] = DEFAULT_MUTATIONS) -> Iterator[str]:
    """Variantes simples de una palabra: mayúsculas, capitalizada y sufijos."""
    seen = set()
    for base in (word, word.lower(), word.upper(), word.capitalize()):
        if base and base not in seen:
            seen.add(base)
            yield base
        for suffix in suffixes:
            candidate = f"{base}{suffix}"
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def iter_candidates(
    words: Iterable[str], *, with_mutations: bool = False, min_len: int = 1, max_len: int = 256
) -> Iterator[str]:
    """Recorre las palabras aplicando (o no) mutaciones y filtros de longitud."""
    for word in words:
        word = word.rstrip("\r\n")
        if not word:
            continue
        stream = mutations(word) if with_mutations else (word,)
        for candidate in stream:
            if min_len <= len(candidate) <= max_len:
                yield candidate


def build_wordlist(
    bases: Iterable[str],
    *,
    with_mutations: bool = True,
    extra_digits: bool = True,
) -> list[str]:
    """Genera una lista de candidatos a partir de palabras base.

    Útil para armar listas dirigidas: nombres de proyecto, apodos, dominios, fechas.
    No es un crackeador por fuerza bruta; es preparación de diccionario.
    """
    out: list[str] = []
    seen: set[str] = set()
    for base in bases:
        stream = mutations(base) if with_mutations else (base,)
        for candidate in stream:
            if candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
    if extra_digits:
        for size in (2, 4):
            for digits in itertools.product(string.digits, repeat=size):
                candidate = "".join(digits)
                if candidate not in seen:
                    seen.add(candidate)
                    out.append(candidate)
    return out


def _init_worker(entry: AesEntry) -> None:
    global _ENTRY
    _ENTRY = entry


def _worker(candidates: list[str]) -> tuple[str, int] | None:
    for index, candidate in enumerate(candidates):
        if verify(_ENTRY, candidate):
            return candidate, index
    return None


def crack_entry(entry: AesEntry, candidates: Iterable[str]) -> str | None:
    """Prueba candidatos en un solo proceso. Devuelve la contraseña o ``None``."""
    for candidate in candidates:
        if verify(entry, candidate):
            return candidate
    return None


def crack(
    entry: AesEntry,
    wordlist_path: str | None = None,
    *,
    words: Iterable[str] | None = None,
    jobs: int | None = None,
    with_mutations: bool = False,
    progress: bool = False,
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
        candidates = list(iter_candidates(iter(words or []), with_mutations=with_mutations))

    if not candidates:
        return None

    jobs = jobs or os.cpu_count() or 1
    if jobs <= 1 or len(candidates) < 2000:
        found = crack_entry(entry, candidates)
        return found

    from multiprocessing import Pool

    chunks = [candidates[index::jobs] for index in range(jobs)]
    with Pool(jobs, initializer=_init_worker, initargs=(entry,)) as pool:
        for result in pool.imap_unordered(_worker, chunks):
            if result:
                pool.terminate()
                return result[0]
    return None
