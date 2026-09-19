"""Búsqueda paralela del primer candidato que satisface un predicado.

Lo usan los dos motores de ataque —AES y ZipCrypto—, que hasta ahora repetían el mismo
bloque de reparto entre procesos. El predicado tiene que ser una función de nivel de
módulo que reciba ``(entry, candidato)``: es lo que exige ``multiprocessing`` para poder
serializarlo.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence

__all__ = ["find_first", "MINIMO_PARA_PARALELIZAR"]

#: por debajo de esta cantidad de candidatos, el costo de repartir supera la ganancia
MINIMO_PARA_PARALELIZAR = 2000

Predicado = Callable[[object, str], bool]

_ENTRY = None
_PREDICADO: Predicado | None = None


def _init_worker(entry: object, predicado: Predicado) -> None:
    global _ENTRY, _PREDICADO
    _ENTRY, _PREDICADO = entry, predicado


def _worker(candidatos: list[str]) -> str | None:
    for candidato in candidatos:
        if _PREDICADO(_ENTRY, candidato):
            return candidato
    return None


def find_first(
    candidatos: Sequence[str],
    entry: object,
    predicado: Predicado,
    *,
    jobs: int | None = None,
    minimo_paralelo: int = MINIMO_PARA_PARALELIZAR,
) -> str | None:
    """Devuelve el primer candidato que satisface ``predicado``, o ``None``.

    El reparto es por franjas (``candidatos[i::jobs]``) y se corta en cuanto un proceso
    encuentra algo. Con pocos candidatos corre en un solo proceso: repartir costaría más
    que buscar.
    """
    if not candidatos:
        return None

    jobs = jobs or os.cpu_count() or 1
    if jobs <= 1 or len(candidatos) < minimo_paralelo:
        for candidato in candidatos:
            if predicado(entry, candidato):
                return candidato
        return None

    from multiprocessing import Pool

    franjas = [list(candidatos[index::jobs]) for index in range(jobs)]
    with Pool(jobs, initializer=_init_worker, initargs=(entry, predicado)) as pool:
        try:
            for resultado in pool.imap_unordered(_worker, franjas):
                if resultado is not None:
                    return resultado
        finally:
            pool.terminate()
    return None
