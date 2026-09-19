"""Tests del arnés de evaluación.

El arnés decide qué números se publican, así que sus propias reglas de conteo tienen que estar
fijadas por tests: si el conteo de intentos, el de aciertos o la curva por subconjunto
cambian sin querer, la tabla publicada deja de significar lo que dice.
"""

from __future__ import annotations

import pytest

from eval import dataset, harness

# --- dataset --------------------------------------------------------------- #


def test_dedupe_conserva_el_orden_de_frecuencia():
    assert dataset.dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


def test_split_no_solapa():
    corpus = [f"palabra{i}" for i in range(1000)]
    train, test = dataset.split(corpus, test_size=100, seed=7)
    assert len(test) == 100
    assert len(train) == 900
    assert not set(train) & set(test)


def test_split_es_reproducible():
    corpus = [f"p{i}" for i in range(500)]
    assert dataset.split(corpus, test_size=50, seed=3) == dataset.split(
        corpus, test_size=50, seed=3
    )


def test_split_con_semilla_distinta_da_otro_test():
    corpus = [f"p{i}" for i in range(500)]
    _, t1 = dataset.split(corpus, test_size=50, seed=1)
    _, t2 = dataset.split(corpus, test_size=50, seed=2)
    assert t1 != t2


def test_split_el_train_conserva_el_orden_original():
    corpus = [f"p{i}" for i in range(200)]
    train, _ = dataset.split(corpus, test_size=20, seed=5)
    assert train == sorted(train, key=lambda p: int(p[1:]))


def test_split_rechaza_un_test_mas_grande_que_el_corpus():
    with pytest.raises(ValueError):
        dataset.split(["a", "b"], test_size=5)


def test_load_corpus_filtra_por_longitud_y_deduplica(tmp_path):
    archivo = tmp_path / "c.txt"
    archivo.write_text("ab\nabcd\nabcd\nabcde\n" + "x" * 50 + "\n", encoding="latin-1")
    assert dataset.load_corpus(str(archivo), min_len=4, max_len=40) == ["abcd", "abcde"]


def test_load_corpus_respeta_el_limite(tmp_path):
    archivo = tmp_path / "c.txt"
    archivo.write_text("\n".join(f"palabra{i}" for i in range(100)), encoding="latin-1")
    assert len(dataset.load_corpus(str(archivo), limit=10)) == 10


def test_load_corpus_falla_si_no_existe(tmp_path):
    with pytest.raises(FileNotFoundError):
        dataset.load_corpus(str(tmp_path / "no-esta.txt"))


def test_load_corpus_sobrevive_a_bytes_no_utf8(tmp_path):
    """Las contraseñas son bytes: un corpus con latin-1 crudo no debe romper la lectura."""
    archivo = tmp_path / "c.txt"
    archivo.write_bytes(b"clave\x81rara\nvalida\n")
    assert dataset.load_corpus(str(archivo)) == ["clave\x81rara", "valida"]


# --- harness: conteo ------------------------------------------------------- #


def test_encuentra_y_registra_el_rango():
    resultado = harness.medir("t", ["a", "b", "c"], ["c"], presupuesto=10)
    assert resultado.encontradas == 1
    assert resultado.rangos == [3]
    assert resultado.hallazgos == [(3, "c")]


def test_respeta_el_presupuesto():
    resultado = harness.medir("t", (str(i) for i in range(1000)), ["999"], presupuesto=100)
    assert resultado.intentos == 100
    assert resultado.encontradas == 0


def test_detiene_al_encontrar_todo():
    resultado = harness.medir("t", ["a", "b", "c", "d"], ["b"], presupuesto=100)
    assert resultado.intentos == 2


def test_los_repetidos_gastan_presupuesto_pero_no_cuentan_como_unicos():
    resultado = harness.medir("t", ["x", "x", "x", "y"], ["y"], presupuesto=100)
    assert resultado.intentos == 4
    assert resultado.unicos == 2
    assert resultado.desperdicio == pytest.approx(0.5)


def test_un_test_vacio_no_consume_nada():
    resultado = harness.medir("t", ["a", "b"], [], presupuesto=10)
    assert resultado.intentos == 0
    assert resultado.encontradas == 0


def test_no_cuenta_dos_veces_la_misma_contrasena():
    resultado = harness.medir("t", ["a", "a", "a"], ["a"], presupuesto=10)
    assert resultado.encontradas == 1


# --- harness: curva -------------------------------------------------------- #


def test_la_curva_es_el_porcentaje_sobre_el_test():
    # 4 objetivos; aparecen en las posiciones 1, 3, 7 y 20
    candidatos = [str(i) for i in range(50)]
    objetivos = ["0", "2", "6", "19"]
    resultado = harness.medir("t", candidatos, objetivos, presupuesto=50, puntos=(1, 3, 10, 20))
    assert resultado.curva[1] == pytest.approx(25.0)
    assert resultado.curva[3] == pytest.approx(50.0)
    assert resultado.curva[10] == pytest.approx(75.0)
    assert resultado.curva[20] == pytest.approx(100.0)


def test_la_curva_se_completa_aunque_el_flujo_sea_corto():
    resultado = harness.medir("t", ["a"], ["z"], presupuesto=10, puntos=(1, 5, 10))
    assert set(resultado.curva) == {1, 5, 10}
    assert resultado.curva[10] == 0.0


def test_curva_por_subconjunto_usa_su_propio_denominador():
    """Es lo que permite comparar generadores que no cubren todas las longitudes."""
    cortas = {"ab", "cd"}
    largas = {"claveLargaUno", "claveLargaDos"}
    resultado = harness.medir("t", ["ab", "claveLargaUno"], cortas | largas, presupuesto=10)

    assert resultado.a_presupuesto(10) == 2
    assert resultado.residuo(10) == pytest.approx(50.0)
    assert resultado.residuo_en(10, cortas) == pytest.approx(50.0)
    assert resultado.residuo_en(10, largas) == pytest.approx(50.0)


def test_subconjunto_vacio_no_divide_por_cero():
    resultado = harness.medir("t", ["a"], ["a"], presupuesto=10)
    assert resultado.residuo_en(10, set()) == 0.0


def test_el_resumen_es_serializable():
    import json

    resultado = harness.medir("t", ["a", "b"], ["b"], presupuesto=10)
    assert json.loads(json.dumps(resultado.summary()))["generador"] == "t"


# --- harness: cierre del generador ----------------------------------------- #


def test_cierra_el_generador_al_cortar_por_presupuesto():
    """Un generador cortado a mitad deja su proceso vivo si no se lo cierra.

    Es el bug que hizo que hashcat emitiera cero candidatos en las mediciones siguientes.
    """
    cerrado = {"valor": False}

    def generador():
        try:
            for i in range(1000):
                yield str(i)
        finally:
            cerrado["valor"] = True

    harness.medir("t", generador(), ["z"], presupuesto=10)
    assert cerrado["valor"], "el arnés tiene que cerrar el generador al salir"


def test_cierra_el_generador_al_encontrar_todo():
    cerrado = {"valor": False}

    def generador():
        try:
            yield "a"
            yield "b"
        finally:
            cerrado["valor"] = True

    harness.medir("t", generador(), ["a"], presupuesto=100)
    assert cerrado["valor"]


def test_acepta_una_lista_sin_metodo_close():
    assert harness.medir("t", ["a"], ["a"], presupuesto=5).encontradas == 1
