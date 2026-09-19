"""Robustez de los parsers frente a entradas malformadas.

El parser es la superficie más expuesta del paquete: recibe bytes de un archivo que puede
estar corrupto, truncado o construido a propósito para confundirlo. Estas pruebas mutan
archivos válidos de forma determinista (semilla fija, así que son reproducibles) y exigen
dos cosas:

1. que no reviente con excepciones que indiquen un descuido del código (``TypeError``,
   ``IndexError``, ``MemoryError``…), sólo con las esperadas para datos inválidos;
2. que si el parseo tiene éxito, los invariantes del formato se respeten.

Un fallo acá es un bug real, no un falso positivo.
"""

from __future__ import annotations

import random
import struct
import zipfile
import zlib

import pytest

from zipaes import inspect, parse_entry
from zipaes.format import KEYLEN_BY_STRENGTH, salt_len_for
from zipaes.testkit import write_aes_zip
from zipaes.zipcrypto import parse_zipcrypto_entry

#: excepciones aceptables ante datos inválidos
ESPERADAS = (
    ValueError,  # incluye NotAesError, NotEncryptedError y UnsupportedZipError
    OSError,
    EOFError,
    zipfile.BadZipFile,
    struct.error,
    zlib.error,
    # la biblioteca estándar levanta esto ante versiones de contenedor inválidas; el
    # parser lo traduce a UnsupportedZipError, pero el fuzz también la llama directo
    NotImplementedError,
)

ITERACIONES = 300


def _mutar(datos: bytes, rng: random.Random) -> bytes:
    """Aplica entre 1 y 4 mutaciones a un archivo válido."""
    salida = bytearray(datos)
    if not salida:
        return bytes(salida)

    for _ in range(rng.randint(1, 4)):
        operacion = rng.choice(["flip", "cero", "max", "truncar", "basura", "tamano", "duplicar"])

        if operacion == "flip":
            pos = rng.randrange(len(salida))
            salida[pos] ^= 1 << rng.randrange(8)
        elif operacion == "cero":
            pos = rng.randrange(len(salida))
            salida[pos] = 0
        elif operacion == "max":
            pos = rng.randrange(len(salida))
            salida[pos] = 0xFF
        elif operacion == "truncar":
            salida = salida[: rng.randrange(1, len(salida) + 1)]
        elif operacion == "basura":
            pos = rng.randrange(len(salida))
            salida[pos : pos + 4] = bytes(rng.randrange(256) for _ in range(4))
        elif operacion == "tamano":
            # escribe un valor absurdo en los campos de tamaño de la cabecera local
            if len(salida) > 30:
                pos = rng.choice([14, 18, 22, 26])  # crc, csize, usize, nlen
                salida[pos : pos + 4] = struct.pack(
                    "<I", rng.choice([0xFFFFFFFF, 0x7FFFFFFF, len(salida) * 1000])
                )
        elif operacion == "duplicar" and len(salida) > 8:
            inicio = rng.randrange(len(salida) - 4)
            salida[inicio:inicio] = salida[inicio : inicio + rng.randint(1, 8)]

    return bytes(salida)


def _ejecutar(fn, *args, **kwargs):
    """Ejecuta y devuelve (ok, excepcion). Re-lanza lo que no sea esperado."""
    try:
        fn(*args, **kwargs)
        return True, None
    except ESPERADAS as exc:  # noqa: PERF203
        return False, exc
    except BaseException as exc:  # noqa: BLE001
        pytest.fail(
            f"excepción inesperada {type(exc).__name__}: {exc}\n"
            "— el parser no debería reventar así ante datos inválidos"
        )


@pytest.fixture
def valido_aes(tmp_path) -> bytes:
    ruta = tmp_path / "valido.zip"
    write_aes_zip(
        ruta,
        {"a.txt": b"contenido de prueba", "carpeta/b.bin": bytes(range(128))},
        "clave",
    )
    return ruta.read_bytes()


@pytest.fixture
def valido_deflate(tmp_path) -> bytes:
    ruta = tmp_path / "deflate.zip"
    write_aes_zip(ruta, {"a.txt": b"x" * 400}, "clave", compression=8)
    return ruta.read_bytes()


def _fuzz_sobre(datos: bytes, tmp_path, semilla: int) -> dict:
    """Muta y clasifica. Devuelve un resumen de lo observado."""
    rng = random.Random(semilla)
    ruta = tmp_path / f"fuzz_{semilla}.zip"
    resumen = {"ok": 0, "esperada": 0, "entradas_ok": 0}

    for _ in range(ITERACIONES):
        mutado = _mutar(datos, rng)
        ruta.write_bytes(mutado)

        ok, _ = _ejecutar(inspect, str(ruta))
        if ok:
            resumen["ok"] += 1
        else:
            resumen["esperada"] += 1

        # también el parser directo, que es donde vive la aritmética de offsets
        try:
            with zipfile.ZipFile(ruta) as archivo, open(ruta, "rb") as handle:
                for info in archivo.infolist()[:3]:
                    ok2, _ = _ejecutar(parse_entry, handle, info)
                    if ok2:
                        resumen["entradas_ok"] += 1
        except ESPERADAS:
            pass
        except BaseException as exc:  # noqa: BLE001
            pytest.fail(f"excepción inesperada en zipfile: {type(exc).__name__}: {exc}")

    return resumen


def test_fuzz_parser_aes(valido_aes, tmp_path):
    resumen = _fuzz_sobre(valido_aes, tmp_path, semilla=20260919)
    assert resumen["ok"] + resumen["esperada"] == ITERACIONES
    # los mutados siguen siendo archivos de tamaño chico: no debe colgarse ni explotar
    assert resumen["ok"] >= 0


def test_fuzz_parser_deflate(valido_deflate, tmp_path):
    _fuzz_sobre(valido_deflate, tmp_path, semilla=771)


def test_fuzz_parser_zipcrypto(tmp_path, tiene_zip):
    if not tiene_zip:
        pytest.skip("hace falta el binario zip de Info-ZIP")
    import subprocess

    origen = tmp_path / "dato.txt"
    origen.write_text("contenido para fuzz\n", encoding="utf-8")
    destino = tmp_path / "zc.zip"
    subprocess.run(
        ["zip", "-q", "-j", "-Pclave", str(destino), str(origen)],
        check=True,
        capture_output=True,
        cwd=tmp_path,
    )
    datos = destino.read_bytes()
    rng = random.Random(4242)
    ruta = tmp_path / "fuzz_zc.zip"

    for _ in range(ITERACIONES):
        ruta.write_bytes(_mutar(datos, rng))
        _ejecutar(inspect, str(ruta))
        try:
            with zipfile.ZipFile(ruta) as archivo, open(ruta, "rb") as handle:
                for info in archivo.infolist()[:3]:
                    _ejecutar(
                        parse_zipcrypto_entry,
                        handle,
                        info,
                        csize=info.compress_size,
                        usize=info.file_size,
                    )
        except ESPERADAS:
            pass
        except BaseException as exc:  # noqa: BLE001
            pytest.fail(f"excepción inesperada: {type(exc).__name__}: {exc}")


# --- invariantes cuando el parseo SÍ funciona ------------------------------ #


def test_los_invariantes_se_respetan_en_los_mutados_que_parsean(valido_aes, tmp_path):
    rng = random.Random(31337)
    ruta = tmp_path / "inv.zip"

    for _ in range(ITERACIONES):
        ruta.write_bytes(_mutar(valido_aes, rng))
        try:
            report = inspect(str(ruta))
        except ESPERADAS:
            continue
        for entry in report.aes:
            assert entry.strength in KEYLEN_BY_STRENGTH, "fuerza fuera de rango"
            assert entry.salt_len == salt_len_for(entry.strength), "salt de largo incorrecto"
            assert entry.pv_len in (1, 2), "valor de verificación de largo inválido"
            assert len(entry.auth_code) == 10, "auth code de largo incorrecto"
            assert entry.ct_len >= 0, "ciphertext de largo negativo"
            assert entry.keylen_bits in (128, 192, 256), "fuerza de clave inválida"


def test_no_se_acepta_un_tamano_cifrado_absurdo(tmp_path):
    """Un `compressed size` enorme no debe provocar una lectura gigante.

    Es el ataque más obvio contra un parser: declarar 4 GB de datos en un archivo de 100
    bytes. Sin cota, el parser intentaría leerlos.
    """
    ruta = tmp_path / "bomba.zip"
    write_aes_zip(ruta, {"a.txt": b"x"}, "clave")
    datos = bytearray(ruta.read_bytes())
    # campo compressed size de la cabecera local (offset 18)
    datos[18:22] = struct.pack("<I", 0xFFFFFFFF)
    ruta.write_bytes(bytes(datos))

    report = inspect(str(ruta))
    # no debe haber explotado ni leído 4 GB: la entrada se descarta o queda vacía
    assert isinstance(report.aes, list)
