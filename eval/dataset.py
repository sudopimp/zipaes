"""Carga y partición del corpus para la evaluación.

Protocolo, en lo posible calcado del que usa la literatura de adivinación de contraseñas:

- corpus público (`rockyou.txt`, el que usan los papers del área y hashcat);
- se quitan duplicados exactos;
- se descartan las entradas fuera de un rango de longitud (las de 1-3 caracteres se
  recuperan trivialmente y ensucian cualquier comparación);
- la partición es **por contraseña**, con semilla fija, y se verifica que no quede ninguna
  contraseña de test dentro de train.

Limitación honesta y visible: `rockyou.txt` tal como se distribuye **no trae identificador de
usuario**, así que no se puede particionar por usuario como hacen los trabajos que sí tienen
ese dato. Particionar al azar deja pasar variantes morfológicas de una misma contraseña entre
train y test (p. ej. `veronica1` en train y `veronica2` en test). Eso favorece a todos los
generadores por igual, pero infla los números absolutos respecto de una partición por usuario.
Está declarado en el informe.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Iterator
from pathlib import Path

__all__ = [
    "load_corpus",
    "dedupe",
    "split",
    "RUTA_ROCKYOU",
    "MIN_LEN",
    "MAX_LEN",
]

#: corpus por defecto, el que usa el área
RUTA_ROCKYOU = "/home/fer/opt/rockyou.txt"

#: Las contraseñas son **bytes**, no texto. `rockyou.txt` trae secuencias que no son UTF-8
#: válido, así que se lee y se escribe en latin-1: mapea cada byte a un carácter de forma
#: biyectiva, así que el viaje de ida y vuelta es sin pérdida y no hay que descartar nada.
CODIFICACION = "latin-1"

#: rango de longitudes que entra a la evaluación
MIN_LEN = 4
MAX_LEN = 40


def dedupe(items: Iterable[str], *, preserve_order: bool = True) -> list[str]:
    """Quita duplicados exactos conservando el orden (el orden lleva la frecuencia)."""
    vistos: set[str] = set()
    salida: list[str] = []
    for item in items:
        if item in vistos:
            continue
        vistos.add(item)
        salida.append(item)
    if preserve_order:
        return salida
    return sorted(vistos)


def load_corpus(
    path: str = RUTA_ROCKYOU,
    *,
    min_len: int = MIN_LEN,
    max_len: int = MAX_LEN,
    limit: int | None = None,
) -> list[str]:
    """Lee el corpus, filtra por longitud y quita duplicados.

    ``limit`` corta la lectura a las primeras N líneas válidas **sin** deduplicar antes, así
    que sirve para pruebas rápidas, no para la corrida publicada.
    """
    ruta = Path(path)
    if not ruta.is_file():
        raise FileNotFoundError(f"no existe el corpus: {path}")

    crudas: list[str] = []
    with ruta.open("r", encoding=CODIFICACION) as handle:
        for linea in handle:
            palabra = linea.rstrip("\r\n")
            if not palabra or not (min_len <= len(palabra) <= max_len):
                continue
            crudas.append(palabra)
            if limit and len(crudas) >= limit:
                break

    return dedupe(crudas)


def split(
    corpus: list[str],
    *,
    test_size: int = 20_000,
    seed: int = 20260919,
    ventana_cabeza: int | None = None,
) -> tuple[list[str], list[str]]:
    """Parte el corpus en (train, test) con semilla fija y sin solapamiento exacto.

    ``ventana_cabeza`` cambia **de dónde sale el test**, y no es un detalle menor:

    - sin él (por defecto), el test es una muestra uniforme sobre todas las contraseñas
      únicas. Mide "cuánto tarda en recuperar una contraseña única al azar", que es una
      pregunta dura y que castiga a los modelos por probabilidad: una contraseña que eligen
      un millón de personas cuenta igual que una que eligió una sola.
    - con él, el test se muestrea de las ``ventana_cabeza`` contraseñas más frecuentes, que
      son las que la gente **realmente** usa. Mide "cuánto tarda en recuperar la contraseña de
      una persona al azar", que es la pregunta de un ataque de verdad.

    Las dos son legítimas y responden a cosas distintas; por eso están las dos y se reportan
    por separado. El train es el mismo en ambos casos salvo por la parte del test.
    """
    universo = (
        list(range(min(ventana_cabeza, len(corpus))))
        if ventana_cabeza
        else list(range(len(corpus)))
    )
    if test_size >= len(universo):
        raise ValueError(
            f"test_size ({test_size}) no puede ser mayor o igual al universo de muestreo "
            f"({len(universo)})"
        )

    random.Random(seed).shuffle(universo)
    elegidos = set(universo[:test_size])

    test = [corpus[i] for i in sorted(elegidos)]
    train = [palabra for i, palabra in enumerate(corpus) if i not in elegidos]

    solapan = set(train) & set(test)
    if solapan:
        raise AssertionError(f"train y test se solapan en {len(solapan)} entradas")

    return train, test


def iter_lines(path: str) -> Iterator[str]:
    """Itera las palabras de un archivo sin cargarlo entero en memoria."""
    with open(path, encoding=CODIFICACION) as handle:
        for linea in handle:
            palabra = linea.rstrip("\r\n")
            if palabra:
                yield palabra
