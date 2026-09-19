"""Búsqueda paralela compartida por los dos motores de ataque."""

from __future__ import annotations

import pytest

from zipaes._search import MINIMO_PARA_PARALELIZAR, find_first


def _es_objetivo(entry, candidato: str) -> bool:
    """Predicado de nivel de módulo, como exige multiprocessing."""
    return candidato == entry


def test_lista_vacia_devuelve_none():
    assert find_first([], "x", _es_objetivo) is None


def test_encuentra_en_un_solo_proceso():
    assert find_first(["a", "b", "objetivo"], "objetivo", _es_objetivo) == "objetivo"


def test_devuelve_none_si_no_esta():
    assert find_first(["a", "b", "c"], "z", _es_objetivo) is None


def test_jobs_uno_no_paraleliza():
    assert find_first(["a", "objetivo"], "objetivo", _es_objetivo, jobs=1) == "objetivo"


def test_encuentra_por_encima_del_umbral():
    candidatos = [f"relleno-{i}" for i in range(MINIMO_PARA_PARALELIZAR + 500)]
    candidatos.append("objetivo")
    assert find_first(candidatos, "objetivo", _es_objetivo, jobs=4) == "objetivo"


def test_no_encuentra_por_encima_del_umbral():
    candidatos = [f"relleno-{i}" for i in range(MINIMO_PARA_PARALELIZAR + 500)]
    assert find_first(candidatos, "objetivo", _es_objetivo, jobs=4) is None


def test_el_umbral_es_configurable():
    assert find_first(["a", "objetivo"], "objetivo", _es_objetivo, minimo_paralelo=1) == "objetivo"


def test_encuentra_la_primera_coincidencia():
    """El orden importa: devuelve la primera del recorrido en un proceso."""
    assert find_first(["objetivo", "otro objetivo"], "objetivo", _es_objetivo) == "objetivo"


def test_el_predicado_recibe_la_entry():
    assert find_first(["x"], ("clave", "x"), lambda e, c: c == e[1]) == "x"


def test_el_predicado_que_falla_propaga_la_excepcion():
    def explota(entry, candidato):
        raise RuntimeError("predicado roto")

    with pytest.raises(RuntimeError):
        find_first(["a"], "x", explota)
