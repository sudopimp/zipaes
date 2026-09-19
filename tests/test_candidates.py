"""Generación de candidatos: mangleo, composición y modelo de Markov."""

from __future__ import annotations

import itertools
import random

import pytest

from zipaes.candidates import (
    END,
    START,
    MarkovModel,
    build_candidates,
    build_wordlist,
    compose,
    iter_candidates,
    leet,
    mangle,
    mutations,
    train,
    years,
)

# --- utilidades ------------------------------------------------------------ #


def test_years_incluye_dos_y_cuatro_digitos():
    lista = years(2024, 2026)
    assert "2024" in lista
    assert "24" in lista
    assert len(lista) == 6


def test_leet_sustituye_las_letras_habituales():
    variantes = leet("fer")
    assert "f3r" in variantes


def test_leet_no_devuelve_nada_si_no_hay_sustituciones():
    assert leet("qxw") == []


def test_leet_completo_agrega_variantes_de_un_caracter():
    simples = set(leet("casa"))
    completas = set(leet("casa", full=True))
    assert simples <= completas
    assert len(completas) > len(simples)


def test_mangle_genera_variantes_previsibles():
    generadas = list(mangle("fer"))
    assert "fer" in generadas
    assert "FER" in generadas
    assert "Fer" in generadas
    assert "fer123" in generadas
    assert "fer2025" in generadas
    assert "ref" in generadas  # invertida
    assert "ferfer" in generadas  # duplicada
    assert "f3r" in generadas  # leet


def test_mangle_no_repite():
    generadas = list(mangle("abc"))
    assert len(generadas) == len(set(generadas))


def test_mangle_puede_omitir_los_anios():
    sin_anios = set(mangle("fer", con_anios=False))
    assert "fer2025" not in sin_anios
    assert "fer123" in sin_anios


def test_compose_usa_separadores():
    generadas = set(compose(["uno"], ["dos"]))
    assert "unodos" in generadas
    assert "uno_dos" in generadas
    assert "uno-dos" in generadas
    assert "uno.dos" in generadas
    assert "Unodos" in generadas  # capitalize() sólo toca el primero
    assert "unoDos" in generadas


def test_compose_ignora_vacios():
    assert list(compose([""], ["dos"])) == []
    assert list(compose(["uno"], [""])) == []


def test_mutations_mantiene_compatibilidad():
    generadas = list(mutations("fer", suffixes=("", "1")))
    assert generadas == ["fer", "fer1", "FER", "FER1", "Fer", "Fer1"]


def test_iter_candidates_filtra_por_largo_y_vacios():
    assert list(iter_candidates(["", "\n", "ok", "larguisimo"], max_len=3)) == ["ok"]


def test_build_wordlist_con_y_sin_digitos():
    con = build_wordlist(["x"], extra_digits=True)
    sin = build_wordlist(["x"], extra_digits=False)
    assert len(con) > len(sin)
    assert "42" in con
    assert len(con) == len(set(con))


# --- modelo de Markov ------------------------------------------------------ #


def test_el_modelo_necesita_orden_positivo():
    with pytest.raises(ValueError):
        MarkovModel(order=0)


def test_entrenar_registra_contextos_y_vocabulario():
    modelo = train(["secreto", "secreto", "otra"], order=2)
    assert modelo.contexts() > 0
    assert modelo.vocabulary > 0
    assert modelo.corpus_size == 3


def test_un_corpus_uniforme_genera_esa_palabra():
    """Con un corpus de una sola palabra, la generación es determinista."""
    modelo = train(["secreto"] * 300, order=2)
    assert modelo.generate(5, seed=1) == ["secreto"]


def test_generacion_reproducible_con_semilla():
    modelo = train([f"palabra{i}" for i in range(200)], order=2)
    a = modelo.generate(50, seed=7)
    b = modelo.generate(50, seed=7)
    assert a == b


def test_generacion_distinta_sin_semilla_distinta():
    modelo = train([f"palabra{i}" for i in range(200)], order=2)
    assert modelo.generate(30, seed=1) != modelo.generate(30, seed=2)


def test_generacion_respeta_longitudes():
    modelo = train([f"palabra{i}" for i in range(200)], order=2)
    generadas = modelo.generate(80, min_len=6, max_len=10, seed=3)
    assert generadas
    assert all(6 <= len(c) <= 10 for c in generadas)


def test_generacion_sin_repetidos():
    modelo = train([f"palabra{i}" for i in range(200)], order=2)
    generadas = modelo.generate(100, seed=5)
    assert len(generadas) == len(set(generadas))


def test_modelo_vacio_no_genera():
    with pytest.raises(ValueError):
        MarkovModel(order=2).generate(10)


def test_guardar_y_cargar_conserva_el_modelo(tmp_path):
    modelo = train(["alpha", "beta", "gamma"], order=3)
    ruta = str(tmp_path / "modelo.json")
    modelo.save(ruta)
    recuperado = MarkovModel.load(ruta)
    assert recuperado.order == 3
    assert recuperado.corpus_size == modelo.corpus_size
    assert recuperado.generate(10, seed=1) == modelo.generate(10, seed=1)


def test_el_orden_cambia_el_modelo():
    """Más orden = más contexto = más estados distintos (con un corpus variado)."""
    corpus = [f"palabra{i}" for i in range(60)]
    poco = train(corpus, order=1).contexts()
    mucho = train(corpus, order=3).contexts()
    assert mucho > poco

    # y la diferencia se nota en lo que generan
    assert train(corpus, order=1).generate(20, seed=4) != train(corpus, order=3).generate(
        20, seed=4
    )


def test_los_marcadores_estan_en_los_contextos():
    modelo = train(["hola"], order=2)
    assert any(START in contexto for contexto in modelo.counts)
    assert any(END in caracter for contador in modelo.counts.values() for caracter in contador)


def test_el_corpus_se_puede_limitar(tmp_path):
    modelo = train(["uno", "dos", "tres", "cuatro"], order=1, max_lines=2)
    assert modelo.corpus_size == 2


# --- construcción combinada ------------------------------------------------ #


def test_build_candidates_combina_estrategias():
    candidatos = build_candidates(bases=["fer", "gomez"], model_count=0, seed=1)
    assert "fer" in candidatos
    assert "fergomez" in candidatos
    assert "gomezfer" in candidatos


def test_build_candidates_sin_bases_ni_modelo_es_vacio():
    assert build_candidates() == []


def test_build_candidates_con_modelo_agrega_generados():
    modelo = train(["secreto"] * 50, order=2)
    candidatos = build_candidates(bases=["otra"], model=modelo, model_count=5, seed=1)
    assert "secreto" in candidatos


def test_build_candidates_sin_repetidos():
    candidatos = build_candidates(bases=["fer", "fer"], seed=1)
    assert len(candidatos) == len(set(candidatos))


def test_build_candidates_es_reproducible():
    a = build_candidates(bases=["fer"], model=train(["x"] * 50), model_count=20, seed=9)
    b = build_candidates(bases=["fer"], model=train(["x"] * 50), model_count=20, seed=9)
    assert a == b


def test_build_candidates_entrena_desde_archivo(tmp_path):
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("\n".join(["secreto"] * 60), encoding="utf-8")
    candidatos = build_candidates(bases=["x"], corpus_path=str(corpus), model_count=5)
    assert "secreto" in candidatos


def test_build_candidates_con_corpus_inexistente_levanta_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_candidates(corpus_path=str(tmp_path / "no-existe.txt"))


def test_build_candidates_puede_incluir_digitos():
    con = build_candidates(bases=["x"], digits=True, seed=1)
    sin = build_candidates(bases=["x"], digits=False, seed=1)
    assert len(con) > len(sin)
    assert "42" in con


def test_la_semilla_no_afecta_lo_determinista():
    a = build_candidates(bases=["fer"], seed=1)
    b = build_candidates(bases=["fer"], seed=999)
    assert a == b


def test_markov_alcanza_candidatos_que_el_mangleo_no_produce():
    """El argumento del módulo, medido.

    El mangleo sólo puede transformar una palabra que le des. El modelo aprende la
    estructura de un corpus y llega a candidatos que *no* son derivables de las palabras
    base: acá, variantes del patrón que no están en el corpus ni salen de mutarlo.
    """
    corpus = [f"zxq7{letra}" for letra in "abcdefghijklmnopqrstuvw"]
    modelo = train(corpus, order=3)

    bases = ["zxq7"]
    por_mutacion = set(build_wordlist(bases, with_mutations=True, extra_digits=False))
    por_modelo = set(modelo.generate(200, min_len=5, max_len=5, seed=11))

    alcanzables = por_modelo - por_mutacion
    assert alcanzables, "el modelo debería generar algo que el mangleo no alcanza"
    # y lo que genera respeta el patrón aprendido
    assert all(c.startswith("zxq7") for c in por_modelo)


def test_el_rng_es_el_estandar():
    """El modelo usa random.Random sembrado: reproducible entre plataformas."""
    rng = random.Random(1234)
    assert rng.random() == random.Random(1234).random()


# --- enumeración ordenada por probabilidad --------------------------------- #
#
# Es la respuesta al hallazgo de la evaluación: los generadores por muestreo pierden contra la
# enumeración determinista porque no ordenan sus extracciones. Acá se fija que el orden sea el
# correcto, que es lo único que hace útil a este generador.


def test_el_entrenamiento_guarda_contextos_de_todos_los_largos():
    """Sin contextos cortos no hay retroceso, y sin retroceso la búsqueda se corta."""
    modelo = train(["abcd"], order=3)
    for largo in (1, 2, 3):
        assert any(len(ctx) == largo for ctx in modelo.counts), f"falta el nivel {largo}"


def test_la_distribucion_es_una_distribucion():
    modelo = train(["aaa"] * 50 + ["aab"] * 30, order=2)
    pares = modelo.distribucion("^^")
    assert pares
    assert sum(p for _, p in pares) == pytest.approx(1.0)


def test_la_distribucion_esta_ordenada_de_mayor_a_menor():
    modelo = train(["aaa"] * 50 + ["aab"] * 30 + ["aac"], order=2)
    probabilidades = [p for _, p in modelo.distribucion("^^")]
    assert probabilidades == sorted(probabilidades, reverse=True)


def test_la_distribucion_usa_retroceso_en_un_contexto_nunca_visto():
    """Un contexto de largo completo desconocido igual tiene que tener respuesta."""
    modelo = train(["abcd"] * 10, order=3)
    pares = modelo.distribucion("zzz")  # trigrama nunca visto
    assert pares, "el retroceso debería responder con los niveles más generales"
    assert sum(p for _, p in pares) == pytest.approx(1.0)


def test_la_enumeracion_ordenada_respeta_la_frecuencia():
    """Con un corpus donde el orden es evidente, tiene que salir en ese orden."""
    modelo = train(["aaa"] * 100 + ["aab"] * 50 + ["aba"] * 10 + ["bbb"], order=2)
    primeros = list(itertools.islice(modelo.iter_ordenado(min_len=3, max_len=3), 4))
    assert primeros == ["aaa", "aab", "aba", "bbb"]


def test_la_enumeracion_ordenada_generaliza_fuera_del_corpus():
    """Lo que el muestreo no puede: alcanzar combinaciones que no están en el corpus."""
    del_corpus = {"aaa", "aab", "aba"}
    modelo = train(["aaa"] * 100 + ["aab"] * 50 + ["aba"] * 10, order=2)
    generados = set(itertools.islice(modelo.iter_ordenado(min_len=3, max_len=3), 30))
    compuestos = generados - del_corpus
    assert compuestos, "debería componer del patrón aprendido, no sólo repetir el corpus"


def test_la_enumeracion_ordenada_es_determinista():
    modelo = train(["uno", "dos", "tres"] * 20, order=2)
    a = list(itertools.islice(modelo.iter_ordenado(min_len=3, max_len=4), 25))
    b = list(itertools.islice(modelo.iter_ordenado(min_len=3, max_len=4), 25))
    assert a == b


def test_la_enumeracion_ordenada_respeta_los_largos():
    modelo = train(["aaaa", "bbbbb", "cccccc", "ddddddd"] * 10, order=2)
    generados = list(itertools.islice(modelo.iter_ordenado(min_len=5, max_len=6), 60))
    assert generados
    assert all(5 <= len(c) <= 6 for c in generados), sorted({len(c) for c in generados})


def test_la_enumeracion_ordenada_no_repite():
    modelo = train(["alfa", "beta", "gama"] * 30, order=2)
    generados = list(itertools.islice(modelo.iter_ordenado(min_len=4, max_len=5), 60))
    assert len(generados) == len(set(generados))


def test_la_enumeracion_ordenada_se_agota():
    modelo = train(["ab", "cd"], order=1)
    generados = list(modelo.iter_ordenado(min_len=2, max_len=2))
    assert generados, "debería emitir algo"
    assert len(generados) == len(set(generados))


def test_la_enumeracion_ordenada_falla_con_modelo_vacio():
    with pytest.raises(ValueError):
        list(MarkovModel(order=2).iter_ordenado())


def test_la_memoizacion_no_da_resultados_viejos_tras_reentrenar():
    """Si el corpus cambia, lo memoizado tiene que dejar de valer."""
    modelo = train(["aaa"] * 50, order=2)
    antes = dict(modelo.distribucion("^^"))
    modelo.train(["bbb"] * 50)
    despues = dict(modelo.distribucion("^^"))
    assert antes != despues
    assert despues.get("b", 0) > antes.get("b", 0)


def test_el_ordenado_llega_antes_que_el_muestreo_a_la_cabeza():
    """La garantía del cambio, comprobada de forma determinista.

    En vez de comparar contra una corrida de muestreo —que depende de la suerte de la
    semilla, como se vio al escribir esto— se verifica **la propiedad que define el
    generador**: que las puntuaciones del flujo ordenado no suban. El beneficio medido
    (cuántos intentos ahorra) es lo que mide la evaluación, sobre contraseñas reales.

    Y se comprueba además que el primero del flujo es el candidato más probable entre los
    del corpus, que es exactamente lo que el muestreo no garantiza.
    """
    cabeza = ["alfa"] * 30 + ["beta"] * 20 + ["gama"] * 10
    cola = [f"cola{i:03d}" for i in range(300)]
    modelo = train(cabeza + cola, order=2)

    generados = list(itertools.islice(modelo.iter_ordenado(min_len=4, max_len=4), 150))
    assert generados

    puntajes = [modelo.logprobabilidad(c) for c in generados]
    assert puntajes == sorted(puntajes, reverse=True), (
        "el flujo tiene que venir en orden decreciente de probabilidad"
    )

    mas_probable_del_corpus = max(set(cabeza + cola), key=modelo.logprobabilidad)
    assert generados[0] == mas_probable_del_corpus


def test_la_logprobabilidad_castiga_lo_imposible():
    modelo = train(["abcd"] * 10, order=2)
    assert modelo.logprobabilidad("abcd") > float("-inf")
    assert modelo.logprobabilidad("zzzz") == float("-inf") or (
        modelo.logprobabilidad("zzzz") < modelo.logprobabilidad("abcd")
    )


def test_un_modelo_guardado_y_cargado_conserva_el_piso():
    """El piso del retroceso va derivado, así que tiene que sobrevivir al guardado."""
    import tempfile

    modelo = train(["abcd"] * 10, order=3)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        ruta = tmp.name
    modelo.save(ruta)
    recuperado = MarkovModel.load(ruta)

    assert recuperado.unigram, "el piso tiene que reconstruirse al cargar"
    assert recuperado.distribucion("zzz"), "y responder a un contexto nunca visto"
