"""Corre la evaluación completa y emite la tabla y el JSON.

    python eval/run_eval.py --presupuesto 1000000 --salida eval/results

Compara generadores de candidatos a **presupuesto igual**: cada uno recibe la misma cantidad
de intentos y se mide qué porcentaje del conjunto de test recupera dentro de ese presupuesto.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from collections.abc import Iterator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval import dataset, generators, harness  # noqa: E402

PRESUPUESTOS = (10**2, 10**3, 10**4, 10**5, 10**6, 10**7)


def _log(mensaje: str) -> None:
    print(mensaje, file=sys.stderr, flush=True)


def construir_generadores(
    train_path: str,
    train: list[str],
    test_le10: set[str],
    presupuesto: int,
    *,
    entrenar_markov: bool,
    orden_markov: int = 2,
    tope_train_markov: int | None = None,
    con_passgpt: bool = False,
    ruta_modelo: str | None = None,
) -> list[tuple[str, Iterator[str]]]:
    """Arma la lista de (nombre, iterador de candidatos)."""
    trabajo: list[tuple[str, Iterator[str]]] = []

    trabajo.append(("diccionario", generators.generar_diccionario(train)))

    busqueda = generators.BusquedaHashcat()
    if busqueda.existe():
        trabajo.append(
            ("reglas:best64", generators.generar_reglas(busqueda, train_path, ("best64.rule",)))
        )
        trabajo.append(
            ("reglas:dive", generators.generar_reglas(busqueda, train_path, ("dive.rule",)))
        )
        trabajo.append(("mascaras:rockyou", generators.generar_mascaras(busqueda)))
    else:
        _log("aviso: sin hashcat, se saltean reglas y máscaras")

    if entrenar_markov:
        from zipaes.candidates import train as entrenar

        corpus = train[:tope_train_markov] if tope_train_markov else train
        _log(f"entrenando Markov orden {orden_markov} sobre {len(corpus):,} palabras...")
        t0 = time.perf_counter()
        modelo = entrenar(corpus, order=orden_markov)
        _log(
            f"  listo en {time.perf_counter() - t0:.1f}s "
            f"({modelo.contexts():,} contextos, vocab {modelo.vocabulary})"
        )
        trabajo.append(
            (
                f"markov:orden{orden_markov}:muestreo",
                generators.generar_markov(modelo, presupuesto),
            )
        )
        trabajo.append(
            (
                f"markov:orden{orden_markov}:ordenado",
                generators.generar_markov_ordenado(modelo, presupuesto),
            )
        )

    if con_passgpt:
        from eval.neural import generar_passgpt, generar_passgpt_ordenado

        ruta = ruta_modelo or "javirandor/passgpt-10characters"
        # el modelo de 10 caracteres sólo produce longitudes <= 10, así que su curva se mide
        # sobre el subconjunto comparable
        trabajo.append(("passgpt", generar_passgpt(presupuesto, modelo=ruta)))
        # y el mismo modelo, pero enumerando su distribución en vez de samplearla
        trabajo.append(("passgpt:ordenado", generar_passgpt_ordenado(presupuesto, modelo=ruta)))

    return trabajo


def _tabla(
    resultados: list[harness.Resultado],
    puntos: tuple[int, ...],
    presupuesto: int,
    *,
    subconjunto: set[str] | None = None,
    titulo: str = "",
) -> str:
    """Tabla markdown con la curva de cada generador, hasta el presupuesto usado.

    Con ``subconjunto`` la curva se calcula sólo sobre esa parte del test, que es lo que
    permite comparar contra un modelo que no puede producir todas las longitudes.
    """
    puntos_utiles = [p for p in puntos if p <= presupuesto]
    if subconjunto is None:

        def valor(resultado: harness.Resultado, punto: int) -> float:
            return resultado.residuo(punto)

        dominio = f"{resultados[0].tamano_test:,} contraseñas"
    else:

        def valor(resultado: harness.Resultado, punto: int) -> float:
            return resultado.residuo_en(punto, subconjunto)

        dominio = f"{len(subconjunto):,} contraseñas con esa característica"

    lineas = []
    if titulo:
        lineas.append(f"### {titulo}")
        lineas.append("")
    lineas.append(f"Test: {dominio}. Presupuesto: {presupuesto:,} intentos.")
    lineas.append("")
    lineas.append(
        "| generador | " + " | ".join(f"{p:,} intentos" for p in puntos_utiles) + " | desperdicio |"
    )
    lineas.append("|---" * (len(puntos_utiles) + 2) + "|")
    for resultado in sorted(resultados, key=lambda r: -valor(r, puntos_utiles[-1])):
        celdas = " | ".join(f"{valor(resultado, p):.2f}%" for p in puntos_utiles)
        lineas.append(
            f"| `{resultado.generador}` | {celdas} | {100 * resultado.desperdicio:.1f}% |"
        )
    return "\n".join(lineas)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluación de generadores de candidatos")
    parser.add_argument("--corpus", default=dataset.RUTA_ROCKYOU)
    parser.add_argument("--presupuesto", type=int, default=10**6)
    parser.add_argument("--test-size", type=int, default=20_000)
    parser.add_argument(
        "--ventana-cabeza",
        type=int,
        default=None,
        help="muestrea el test de las N contraseñas más frecuentes (las que la gente usa) "
        "en vez de uniformemente sobre todas las únicas",
    )
    parser.add_argument("--semilla", type=int, default=20260919)
    parser.add_argument("--salida", default="eval/results")
    parser.add_argument(
        "--dir-trabajo",
        default=os.path.join(tempfile.gettempdir(), "zipaes-eval"),
        help="dónde dejar la wordlist de train (es grande; fuera del repo)",
    )
    parser.add_argument("--limit-corpus", type=int, default=None, help="para pruebas rápidas")
    parser.add_argument("--sin-markov", action="store_true")
    parser.add_argument("--orden-markov", type=int, default=2)
    parser.add_argument("--tope-train-markov", type=int, default=None)
    parser.add_argument("--passgpt", action="store_true")
    parser.add_argument("--modelo", default=None, help="ruta o id del modelo PassGPT")
    args = parser.parse_args(argv)

    os.makedirs(args.salida, exist_ok=True)

    _log(f"cargando corpus {args.corpus}...")
    t0 = time.perf_counter()
    corpus = dataset.load_corpus(args.corpus, limit=args.limit_corpus)
    _log(f"  {len(corpus):,} contraseñas únicas en {time.perf_counter() - t0:.1f}s")

    train, test = dataset.split(
        corpus,
        test_size=args.test_size,
        seed=args.semilla,
        ventana_cabeza=args.ventana_cabeza,
    )
    test_le10 = {p for p in test if len(p) <= 10}
    _log(f"  train {len(train):,} / test {len(test):,} (<=10 chars: {len(test_le10):,})")
    if args.ventana_cabeza:
        _log(
            f"  el test sale de las {args.ventana_cabeza:,} contraseñas más frecuentes "
            "(persona al azar, no contraseña única al azar)"
        )

    train_path = os.path.join(args.dir_trabajo, "train_wordlist.txt")
    _log(f"escribiendo wordlist de train en {train_path}...")
    generators.ruta_wordlist_de(train, train_path)

    _log("armando generadores...")
    trabajo = construir_generadores(
        train_path,
        train,
        test_le10,
        args.presupuesto,
        entrenar_markov=not args.sin_markov,
        orden_markov=args.orden_markov,
        tope_train_markov=args.tope_train_markov,
        con_passgpt=args.passgpt,
        ruta_modelo=args.modelo,
    )

    resultados: list[harness.Resultado] = []
    for nombre, candidatos in trabajo:
        _log(f"midiendo {nombre} (presupuesto {args.presupuesto:,})...")
        # todos se miden contra el test completo; las curvas por subconjunto se derivan
        # después de la misma corrida, así nadie corre con un denominador distinto
        resultado = harness.medir(
            nombre, candidatos, set(test), presupuesto=args.presupuesto, puntos=PRESUPUESTOS
        )
        resultados.append(resultado)
        _log(
            f"  {resultado.encontradas}/{resultado.tamano_test} en {resultado.intentos:,} "
            f"intentos ({resultado.por_segundo:,.0f}/s, "
            f"desperdicio {100 * resultado.desperdicio:.1f}%)"
        )

    tabla = _tabla(
        resultados,
        PRESUPUESTOS,
        args.presupuesto,
        titulo="Todo el conjunto de test",
    )
    if args.passgpt:
        tabla += "\n\n" + _tabla(
            resultados,
            PRESUPUESTOS,
            args.presupuesto,
            subconjunto=test_le10,
            titulo="Sólo contraseñas de hasta 10 caracteres (la comparación justa con PassGPT)",
        )
    metadatos = {
        "corpus": args.corpus,
        "corpus_unico": len(corpus),
        "train": len(train),
        "test": len(test),
        "test_le10": len(test_le10),
        "ventana_cabeza": args.ventana_cabeza,
        "presupuesto": args.presupuesto,
        "semilla": args.semilla,
        "orden_markov": args.orden_markov,
        "tope_train_markov": args.tope_train_markov,
        "passgpt": args.passgpt,
    }

    with open(os.path.join(args.salida, "resultados.json"), "w", encoding="utf-8") as handle:
        json.dump(
            {"metadatos": metadatos, "resultados": [r.summary() for r in resultados]},
            handle,
            ensure_ascii=False,
            indent=2,
        )
    with open(os.path.join(args.salida, "tabla.md"), "w", encoding="utf-8") as handle:
        handle.write(tabla + "\n")

    print(tabla)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
