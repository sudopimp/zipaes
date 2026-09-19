"""Interfaz de línea de comandos.

    zipaes info     archivo.zip
    zipaes verify   archivo.zip -p CLAVE
    zipaes hash     archivo.zip [--todos]
    zipaes crack    archivo.zip -w lista.txt [-j 8] [--mutaciones]
    zipaes extract  archivo.zip -p CLAVE -o destino/
    zipaes wordlist -o lista.txt palabra1 palabra2 ...
    zipaes selftest [--fuerza 3] [--ae1] [--deflate]

Todos los comandos aceptan ``--json``.

Códigos de salida:

    0  todo bien (incluye "no encontrado" en crack)
    1  error de uso, archivo inexistente o archivo ilegible
    2  la contraseña provista no verifica
    3  se encontró la contraseña pero falló la extracción
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import __version__
from .crack import build_wordlist, crack
from .crypto import WrongPassword, verify
from .extract import extract_all
from .format import inspect, looks_like_zip
from .hashfmt import HASHCAT_MODE, HASHCAT_MODE_ZIPCRYPTO, emit_hash_line, sanity_check
from .selftest import run_selftest

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


def _load_entry(path: str):
    """Devuelve ``(informe, entrada)`` con la primera entrada AES, o ``None``.

    Imprime el motivo por stderr y deja que ``main`` devuelva el código de uso:
    el CLI nunca levanta excepciones para señalizar errores.
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
    if not report.aes:
        if report.zipcrypto:
            print(
                "el archivo usa ZipCrypto (cifrado tradicional), no AES. "
                f"Este paquete trabaja con WinZip AES; para ZipCrypto usá hashcat "
                f"--mode {HASHCAT_MODE_ZIPCRYPTO}.",
                file=sys.stderr,
            )
        elif not report.encrypted:
            print(
                "el archivo no esta cifrado: se puede abrir con unzip normal",
                file=sys.stderr,
            )
        else:
            print("no se encontraron entradas AES reconocibles", file=sys.stderr)
        return None
    return report, report.aes[0]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zipaes",
        description="Auditoria y recuperacion de zips con cifrado AES (WinZip).",
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
    p.add_argument("--avisos", action="store_true", help="incluir avisos de estrategia")

    p = sub.add_parser("crack", help="ataque de diccionario en paralelo")
    p.add_argument("archivo")
    p.add_argument("-w", "--wordlist", help="ruta de la lista de palabras")
    p.add_argument("--palabras", nargs="*", default=[], help="candidatos sueltos")
    p.add_argument("-j", "--jobs", type=int, default=None, help="procesos")
    p.add_argument("--mutaciones", action="store_true", help="generar variantes")

    p = sub.add_parser("extract", help="extraer el contenido con la contrasena")
    p.add_argument("archivo")
    p.add_argument("-p", "--password", required=True)
    p.add_argument("-o", "--output", required=True)

    p = sub.add_parser("wordlist", help="generar una lista de candidatos")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("base", nargs="+", help="palabras base")

    p = sub.add_parser("selftest", help="autocomprobacion de punta a punta")
    p.add_argument("--fuerza", type=int, default=3, choices=[1, 2, 3])
    p.add_argument("--ae1", action="store_true", help="usar la variante AE-1")
    p.add_argument("--deflate", action="store_true", help="usar compresion deflate")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.comando

    if command == "selftest":
        report = run_selftest(
            strength=args.fuerza,
            aes_version=1 if args.ae1 else 2,
            compression=8 if args.deflate else 0,
        )
        if args.json:
            _emit(report, True)
        else:
            print(f"autocomprobacion: {report['resultado'].upper()}")
            print(
                f"  variante   : {report['variante']} / {report['fuerza']} / {report['compresion']}"
            )
            for step in report["pasos"]:
                mark = "ok  " if step["ok"] else "FALLA"
                extra = f"  ({step['detalle']})" if step.get("detalle") else ""
                print(f"  [{mark}] {step['paso']}{extra}")
        return EXIT_OK if report["resultado"] == "ok" else EXIT_USAGE

    if command == "wordlist":
        candidates = build_wordlist(args.base)
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write("\n".join(candidates) + "\n")
        _emit({"salida": args.output, "candidatos": len(candidates)}, args.json)
        return EXIT_OK

    loaded = _load_entry(args.archivo)
    if loaded is None:
        return EXIT_USAGE
    report, entry = loaded

    if command == "info":
        payload = report.summary()
        payload["detalle"] = [item.summary() for item in report.aes[: args.entradas]]
        payload["avisos"] = sanity_check(entry)
        _emit(payload, args.json)
        return EXIT_OK

    if command == "verify":
        ok = verify(entry, args.password)
        _emit(
            {"archivo": args.archivo, "entrada": entry.name, "valida": ok},
            args.json,
        )
        return EXIT_OK if ok else EXIT_BAD_PASSWORD

    if command == "hash":
        lines = (
            [emit_hash_line(item, args.archivo) for item in report.aes]
            if args.todos
            else [emit_hash_line(entry, args.archivo)]
        )
        if args.json:
            _emit({"hashcat_modo": HASHCAT_MODE, "hashes": lines}, True)
        else:
            for line in lines:
                print(line)
            if args.avisos:
                warnings = sanity_check(entry)
                if warnings:
                    print("", file=sys.stderr)
                    for warning in warnings:
                        print(f"aviso: {warning}", file=sys.stderr)
        return EXIT_OK

    if command == "crack":
        words = list(args.palabras) or None
        if not args.wordlist and not words:
            print("hace falta --wordlist o --palabras", file=sys.stderr)
            return EXIT_USAGE
        found = crack(
            entry,
            wordlist_path=args.wordlist,
            words=words,
            jobs=args.jobs,
            with_mutations=args.mutaciones,
        )
        _emit(
            {
                "archivo": args.archivo,
                "entrada": entry.name,
                "encontrada": bool(found),
                "password": found,
            },
            args.json,
        )
        return EXIT_OK

    if command == "extract":
        try:
            result = extract_all(args.archivo, args.password, args.output, entries=report.aes)
        except WrongPassword:
            print("la contrasena no verifica", file=sys.stderr)
            return EXIT_BAD_PASSWORD
        _emit(result.summary(), args.json)
        return EXIT_OK if result.ok else EXIT_EXTRACT_FAILED

    return EXIT_USAGE  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
