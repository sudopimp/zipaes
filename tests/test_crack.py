"""Ataque de diccionario y generación de candidatos."""

from __future__ import annotations

import pytest

from zipaes import build_wordlist, crack, crack_entry, inspect
from zipaes.crack import iter_candidates, mutations
from zipaes.testkit import write_aes_zip

CLAVE = "zebra-91"


@pytest.fixture
def zip_zebra(tmp_path):
    ruta = str(tmp_path / "zebra.zip")
    write_aes_zip(ruta, {"a.txt": b"contenido"}, CLAVE)
    return ruta


def test_encuentra_la_clave_en_un_diccionario(zip_zebra):
    entry = inspect(zip_zebra).aes[0]
    assert crack(entry, words=["alfa", "beta", CLAVE, "gamma"], jobs=1) == CLAVE


def test_devuelve_none_si_no_esta(zip_zebra):
    entry = inspect(zip_zebra).aes[0]
    assert crack(entry, words=["alfa", "beta"], jobs=1) is None


def test_funciona_con_varios_procesos(zip_zebra):
    entry = inspect(zip_zebra).aes[0]
    candidatos = [f"relleno-{i}" for i in range(5000)] + [CLAVE]
    assert crack(entry, words=candidatos, jobs=4) == CLAVE


def test_funciona_desde_archivo(tmp_path, zip_zebra):
    lista = tmp_path / "lista.txt"
    lista.write_text("alfa\nbeta\n" + CLAVE + "\n", encoding="utf-8")
    entry = inspect(zip_zebra).aes[0]
    assert crack(entry, wordlist_path=str(lista), jobs=1) == CLAVE


def test_las_mutaciones_encuentran_la_variante(tmp_path):
    ruta = str(tmp_path / "mut.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "zebra123")
    entry = inspect(ruta).aes[0]
    assert crack(entry, words=["zebra"], jobs=1) is None
    assert crack(entry, words=["zebra"], jobs=1, with_mutations=True) == "zebra123"


def test_crack_entry_en_un_solo_proceso(zip_zebra):
    entry = inspect(zip_zebra).aes[0]
    assert crack_entry(entry, ["alfa", CLAVE]) == CLAVE


def test_sin_fuente_de_candidatos_levanta_error(zip_zebra):
    entry = inspect(zip_zebra).aes[0]
    with pytest.raises(ValueError):
        crack(entry)


def test_mutations_genera_variantes_previsibles():
    generadas = list(mutations("fer"))
    assert "fer" in generadas
    assert "FER" in generadas
    assert "Fer" in generadas
    assert "fer123" in generadas
    assert "FER!" in generadas


def test_mutations_no_repite():
    generadas = list(mutations("abc"))
    assert len(generadas) == len(set(generadas))


def test_iter_candidates_filtra_por_largo():
    palabras = ["a", "abcdef", ""]
    assert list(iter_candidates(palabras, min_len=2)) == ["abcdef"]


def test_iter_candidates_ignora_vacias():
    assert list(iter_candidates(["", "\n", "ok"])) == ["ok"]


def test_build_wordlist_incluye_las_variantes():
    lista = build_wordlist(["fer"], extra_digits=False)
    assert "fer" in lista
    assert "FER" in lista
    assert "Fer123" in lista
    assert len(lista) == len(set(lista))


def test_build_wordlist_puede_agregar_numeros():
    con = build_wordlist(["x"], extra_digits=True)
    sin = build_wordlist(["x"], extra_digits=False)
    assert len(con) > len(sin)
    assert "42" in con


def test_crack_no_encuentra_con_ae1_si_la_lista_no_la_tiene(tmp_path):
    """AE-1 responde al verificador propio, que no depende del largo del pv."""
    ruta = str(tmp_path / "ae1.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "secreta", aes_version=1)
    entry = inspect(ruta).aes[0]
    assert crack(entry, words=["otra", "secreta"], jobs=1) == "secreta"
