"""Interfaz de línea de comandos.

    zipaes info     archivo.zip
    zipaes verify   archivo.zip -p CLAVE
    zipaes hash     archivo.zip [--todos] [--avisos]
    zipaes crack    archivo.zip -w lista.txt [--backend auto|hashcat|john|python]
    zipaes extract  archivo.zip -p CLAVE -o destino/
    zipaes wordlist -o lista.txt [bases...] [--train corpus.txt] [--model m.json]
    zipaes backend
    zipaes selftest [--fuerza 3] [--ae1] [--deflate]

Los comandos que operan sobre un archivo detectan solos si el cifrado es AES o
ZipCrypto. Todos aceptan ``--json``.

Códigos de salida:

    0  todo bien (incluye "no encontrado" en crack)
    1  error de uso, archivo inexistente o archivo ilegible
    2  la contraseña provista no verifica
    3  se encontró la contraseña pero falló la extracción
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
from typing import Any

from . import __version__
from .backend import detect_tools, recover
from .candidates import MarkovModel, build_candidates, train
from .crack import crack as crack_python
from .crypto import WrongPassword, verify
from .extract import extract_all, extract_zipcrypto_all
from .format import inspect, looks_like_zip
from .hashfmt import (
    HASHCAT_MODE,
    HASHCAT_MODE_ZIPCRYPTO,
    emit_hash_line,
    emit_pkzip2,
    sanity_check,
)
from .selftest import run_selftest
from .zipcrypto import crack as crack_zipcrypto
from .zipcrypto import verify as zipcrypto_verify

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_BAD_PASSWORD = 2
EXIT_EXTRACT_FAILED = 3


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, list):
                if not value:
                    continue
                print(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        print("  - " + ", ".join(f"{k}={v}" for k, v in item.items()))
                    else:
                        print(f"  - {item}")
            elif isinstance(value, bool):
                print(f"{key}: {'si' if value else 'no'}")
            else:
                print(f"{key}: {value}")
    elif isinstance(payload, list):
        for item in payload:
            print(item)
    else:
        print(payload)


def _load_target(path: str):
    """Devuelve ``(informe, tipo, entradas)`` o ``None`` imprimiendo el motivo.

    ``tipo`` es ``"aes"`` o ``"zipcrypto"``; ``entradas`` la lista correspondiente.
    """
    if not os.path.isfile(path):
        print(f"no existe el archivo: {path}", file=sys.stderr)
        return None
    if not looks_like_zip(path):
        print(f"no parece un zip: {path}", file=sys.stderr)
        return None
    try:
        report = inspect(path)
    except Exception as exc:  # noqa: BLE001 — un archivo corrupto no debe reventar
        print(f"no se pudo leer el archivo: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None

    if report.aes:
        return report, "aes", report.aes
    if report.zipcrypto_entries:
        return report, "zipcrypto", report.zipcrypto_entries
    if report.other_encrypted:
        print(
            "hay entradas cifradas con un método no soportado (ni AES ni ZipCrypto)",
            file=sys.stderr,
        )
        return None
    if not report.encrypted:
        print(
            "el archivo no esta cifrado: se puede abrir con unzip normal",
            file=sys.stderr,
        )
        return None
    print("no se encontraron entradas cifradas reconocibles", file=sys.stderr)
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zipaes",
        description="Auditoria y recuperacion de zips con cifrado AES y ZipCrypto.",
    )
    parser.add_argument("--version", action="version", version=f"zipaes {__version__}")
    parser.add_argument("--json", action="store_true", help="salida legible por maquina")
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("info", help="panorama del archivo y sus entradas")
    p.add_argument("archivo")
    p.add_argument("--entradas", type=int, default=3, help="cuantas entradas listar")

    p = sub.add_parser("verify", help="verificar una contrasena (concluyente)")
    p.add_argument("archivo")
    p.add_argument("-p", "--password", required=True)

    p = sub.add_parser("hash", help=f"emitir el hash $zip2$ (hashcat -m {HASHCAT_MODE})")
    p.add_argument("archivo")
    p.add_argument("--todos", action="store_true", help="una linea por entrada")
    p.add_argument("--avisos", action="store_true", help="incluye avisos de estrategia")

    p = sub.add_parser("crack", help="ataque de diccionario")
    p.add_argument("archivo")
    p.add_argument("-w", "--wordlist", help="ruta de la lista de palabras")
    p.add_argument("--palabras", nargs="*", default=[], help="candidatos sueltos")
    p.add_argument("-j", "--jobs", type=int, default=None, help="procesos")
    p.add_argument("--mutaciones", action="store_true", help="generar variantes")
    p.add_argument(
        "--backend",
        default="auto",
        choices=["auto", "hashcat", "john", "python"],
        help="motor a usar (auto prefiere la GPU, salvo en AE-1)",
    )
    p.add_argument("--rules", help="archivo de reglas para hashcat")
    p.add_argument("--timeout", type=int, default=None, help="limite en segundos")

    p = sub.add_parser("extract", help="extraer el contenido con la contrasena")
    p.add_argument("archivo")
    p.add_argument("-p", "--password", required=True)
    p.add_argument("-o", "--output", required=True)

    p = sub.add_parser("wordlist", help="generar una lista de candidatos")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("base", nargs="*", help="palabras base (mangleo tipo PACK)")
    p.add_argument("--train", metavar="CORPUS", help="entrenar un modelo de Markov")
    p.add_argument("--model", metavar="ARCHIVO", help="usar un modelo ya entrenado")
    p.add_argument("--save-model", metavar="ARCHIVO", help="guardar el modelo entrenado")
    p.add_argument("--count", type=int, default=0, help="candidatos del modelo")
    p.add_argument("--seed", type=int, default=None, help="semilla reproducible")
    p.add_argument("--no-compose", action="store_true", help="no componer las bases")
    p.add_argument("--digits", action="store_true", help="agregar numeros de 2 y 4 digitos")
    p.add_argument("--order", type=int, default=2, help="orden del modelo de Markov (1-4)")
    p.add_argument("--max-lines", type=int, default=None, help="tope de lineas a entrenar")
    p.add_argument(
        "--ordenado",
        action="store_true",
        help="enumerar el modelo por probabilidad decreciente en vez de samplear (mejor a "
        "presupuesto bajo; determinista)",
    )
    p.add_argument("--min-len", type=int, default=4, help="largo minimo con --ordenado")
    p.add_argument("--max-len", type=int, default=24, help="largo maximo con --ordenado")

    sub.add_parser("backend", help="herramientas externas detectadas")

    p = sub.add_parser("selftest", help="autocomprobacion de punta a punta")
    p.add_argument("--fuerza", type=int, default=3, choices=[1, 2, 3])
    p.add_argument("--ae1", action="store_true", help="usar la variante AE-1")
    p.add_argument("--deflate", action="store_true", help="usar compresion deflate")
    return parser


def _cmd_selftest(args) -> int:
    report = run_selftest(
        strength=args.fuerza,
        aes_version=1 if args.ae1 else 2,
        compression=8 if args.deflate else 0,
    )
    if args.json:
        _emit(report, True)
    else:
        print(f"autocomprobacion: {report['resultado'].upper()}")
        print(f"  variante   : {report['variante']} / {report['fuerza']} / {report['compresion']}")
        for step in report["pasos"]:
            mark = "ok  " if step["ok"] else "FALLA"
            extra = f"  ({step['detalle']})" if step.get("detalle") else ""
            print(f"  [{mark}] {step['paso']}{extra}")
    return EXIT_OK if report["resultado"] == "ok" else EXIT_USAGE


def _cmd_backend(args) -> int:
    tools = detect_tools()
    payload = {
        "detectadas": [tool.summary() for tool in tools.values()],
        "disponibles": sorted(tools),
        "ausentes": sorted({"hashcat", "john"} - set(tools)),
        "nota": (
            "hashcat hace el ataque por GPU; el backend propio es el camino correcto "
            "para AE-1 y para archivos chicos."
        ),
    }
    _emit(payload, args.json)
    return EXIT_OK


def _cmd_wordlist(args) -> int:
    modelo = None
    if args.model:
        modelo = MarkovModel.load(args.model)
    elif args.train:
        if not os.path.isfile(args.train):
            print(f"no existe el corpus: {args.train}", file=sys.stderr)
            return EXIT_USAGE
        with open(args.train, encoding="utf-8", errors="ignore") as handle:
            modelo = train(handle, order=args.order, max_lines=args.max_lines)
        if args.save_model:
            modelo.save(args.save_model)

    if args.ordenado:
        if modelo is None:
            print(
                "--ordenado necesita un modelo: pasá --train o --model",
                file=sys.stderr,
            )
            return EXIT_USAGE
        if not args.count:
            print("--ordenado necesita --count (cuántos candidatos enumerar)", file=sys.stderr)
            return EXIT_USAGE
        candidatos = list(
            itertools.islice(
                modelo.iter_ordenado(min_len=args.min_len, max_len=args.max_len),
                args.count,
            )
        )
    else:
        candidatos = build_candidates(
            bases=args.base,
            model=modelo,
            model_count=args.count,
            seed=args.seed,
            compose_bases=not args.no_compose,
            digits=args.digits,
        )

    if not candidatos:
        print(
            "no se genero ningun candidato: hacen falta palabras base, un corpus o un modelo",
            file=sys.stderr,
        )
        return EXIT_USAGE

    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write("\n".join(candidatos) + "\n")

    payload = {
        "salida": args.output,
        "candidatos": len(candidatos),
        "bases": len(args.base),
    }
    if args.ordenado:
        payload["modo"] = "ordenado por probabilidad decreciente"
        payload["determinista"] = True
    if args.count:
        payload["solicitados_al_modelo"] = args.count
        if len(candidatos) < args.count:
            payload["nota"] = (
                "se generaron menos candidatos que los pedidos: el corpus o el modelo "
                "no dan para más combinaciones únicas"
            )
    if modelo is not None:
        payload["modelo"] = {
            "orden": modelo.order,
            "contextos": modelo.contexts(),
            "vocabulario": modelo.vocabulary,
            "corpus": modelo.corpus_size,
        }
        if args.save_model:
            payload["modelo_guardado"] = args.save_model
    _emit(payload, args.json)
    return EXIT_OK


def _cmd_info(args, report, kind, entries) -> int:
    payload = report.summary()
    payload["tipo"] = kind.upper()
    payload["detalle"] = [item.summary() for item in entries[: args.entradas]]
    if kind == "aes":
        payload["avisos"] = sanity_check(entries[0])
    if report.zip64:
        payload["aviso_zip64"] = (
            "el archivo usa ZIP64 (>4 GB o muchas entradas): el soporte es parcial"
        )
    _emit(payload, args.json)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.comando

    if command == "selftest":
        return _cmd_selftest(args)
    if command == "backend":
        return _cmd_backend(args)
    if command == "wordlist":
        return _cmd_wordlist(args)

    loaded = _load_target(args.archivo)
    if loaded is None:
        return EXIT_USAGE
    report, kind, entries = loaded
    entry = entries[0]

    if command == "info":
        return _cmd_info(args, report, kind, entries)

    if command == "verify":
        ok = (
            zipcrypto_verify(entry, args.password)
            if kind == "zipcrypto"
            else verify(entry, args.password)
        )
        _emit(
            {
                "archivo": args.archivo,
                "entrada": entry.name,
                "tipo": kind.upper(),
                "valida": ok,
            },
            args.json,
        )
        return EXIT_OK if ok else EXIT_BAD_PASSWORD

    if command == "hash":
        if kind == "zipcrypto":
            try:
                lines = (
                    [emit_pkzip2(item, prefix_name=True) for item in entries]
                    if args.todos
                    else [emit_pkzip2(entry)]
                )
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return EXIT_USAGE
            if args.json:
                _emit({"hashcat_modo": HASHCAT_MODE_ZIPCRYPTO, "hashes": lines}, True)
            else:
                for line in lines:
                    print(line)
            return EXIT_OK

        lines = (
            [emit_hash_line(item, args.archivo) for item in entries]
            if args.todos
            else [emit_hash_line(entry, args.archivo)]
        )
        if args.json:
            _emit({"hashcat_modo": HASHCAT_MODE, "hashes": lines}, True)
        else:
            for line in lines:
                print(line)
            if args.avisos:
                avisos = sanity_check(entry)
                if avisos:
                    print("", file=sys.stderr)
                    for aviso in avisos:
                        print(f"aviso: {aviso}", file=sys.stderr)
        return EXIT_OK

    if command == "crack":
        palabras = list(args.palabras) or None
        if not args.wordlist and not palabras:
            print("hace falta --wordlist o --palabras", file=sys.stderr)
            return EXIT_USAGE

        if kind == "zipcrypto":
            encontrada = crack_zipcrypto(
                entry, wordlist_path=args.wordlist, words=palabras, jobs=args.jobs
            )
            usado = "python-zipcrypto"
        elif palabras and not args.wordlist:
            encontrada = crack_python(
                entry, words=palabras, jobs=args.jobs, with_mutations=args.mutaciones
            )
            usado = "python"
        else:
            encontrada, usado = recover(
                entry,
                wordlist=args.wordlist,
                backend=args.backend,
                rules=args.rules,
                timeout=args.timeout,
            )

        _emit(
            {
                "archivo": args.archivo,
                "entrada": entry.name,
                "tipo": kind.upper(),
                "backend": usado,
                "encontrada": bool(encontrada),
                "password": encontrada,
            },
            args.json,
        )
        return EXIT_OK

    if command == "extract":
        try:
            if kind == "zipcrypto":
                result = extract_zipcrypto_all(entries, args.password, args.output)
            else:
                result = extract_all(args.archivo, args.password, args.output, entries=entries)
        except WrongPassword:
            print("la contrasena no verifica", file=sys.stderr)
            return EXIT_BAD_PASSWORD
        _emit(result.summary(), args.json)
        return EXIT_OK if result.ok else EXIT_EXTRACT_FAILED

    return EXIT_USAGE  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
