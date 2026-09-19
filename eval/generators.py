"""Generadores de candidatos, todos detrás de la misma interfaz: un iterador de strings.

Se evalúan cuatro familias, de la más básica a la más avanzada:

1. **Diccionario** — la wordlist de train tal cual, sin transformar. Es el piso.
2. **Reglas** — el motor de reglas de hashcat (`best64`, `dive`, `rockyou-30000`) sobre esa
   wordlist. Es lo que hace la práctica real hoy, y por lo tanto el rival a vencer.
3. **Máscaras** — los conjuntos de máscaras de hashcat por rango de frecuencia, que es el
   otro ataque estándar de la práctica.
4. **Markov** — el modelo de n-gramas entrenado sobre la partición de train.
5. **Neuronal** — PassGPT, el modelo publicado del paper (ver `neural.py`).

Ninguno de los generadores ve el conjunto de test: sólo reciben el corpus de train.

El orden importa y es el orden de *prioridad* de cada generador: en las reglas y las máscaras
es el orden del motor (determinista); en los modelos por muestreo es el orden en que se
samplea. Las dos cosas son las que usa la literatura.
"""

from __future__ import annotations

import itertools
import os
import shutil
import subprocess
from collections.abc import Iterator

from eval.dataset import CODIFICACION

#: contador para darle a cada invocación de hashcat su propia sesión
_SESIONES = itertools.count()

__all__ = [
    "BusquedaHashcat",
    "generar_diccionario",
    "generar_reglas",
    "generar_mascaras",
    "generar_markov",
    "encontrar_hashcat",
]

#: reglas estándar, en orden de "barato a caro"
REGLAS_ESTANDAR = ("best64.rule", "dive.rule")

#: máscaras por rango de frecuencia
MASCARAS_ESTANDAR = ("rockyou-1-60.hcmask", "rockyou-2-1800.hcmask", "rockyou-3-3600.hcmask")


def encontrar_hashcat() -> str:
    """Ubica el binario de hashcat; reusa la detección del paquete."""
    from zipaes.backend import find_tool

    ruta = find_tool("hashcat")
    if not ruta:
        for candidato in (
            os.path.expanduser("~/opt/hashcat-6.2.6/hashcat.bin"),
            "/usr/bin/hashcat",
        ):
            if os.access(candidato, os.X_OK):
                return candidato
        raise RuntimeError("hashcat no está instalado")
    return ruta


class BusquedaHashcat:
    """Directorios de rules/ y masks/ dentro de la instalación de hashcat."""

    def __init__(self, binario: str | None = None) -> None:
        self.binario = binario or encontrar_hashcat()
        raiz = os.path.dirname(os.path.abspath(self.binario))
        if raiz.endswith("bin"):
            raiz = os.path.dirname(raiz)
        self.raiz = raiz
        self.rules_dir = os.path.join(raiz, "rules")
        self.masks_dir = os.path.join(raiz, "masks")

    def regla(self, nombre: str) -> str:
        return os.path.join(self.rules_dir, nombre)

    def mascara(self, nombre: str) -> str:
        return os.path.join(self.masks_dir, nombre)

    def existe(self) -> bool:
        return os.path.isfile(self.binario) and os.path.isdir(self.rules_dir)


def _stdout_hashcat(comando: list[str], descripcion: str = "") -> Iterator[str]:
    """Corre hashcat en modo ``--stdout`` y va emitiendo candidatos.

    Dos precauciones que costaron un rato de depuración:

    - **sesión única por invocación**: si no, una corrida anterior que quedó viva compite por
      el estado por defecto de hashcat y la siguiente sale sin emitir nada;
    - **un cero no pasa en silencio**: si el proceso termina sin emitir un solo candidato, se
      levanta un error con su stderr en vez de devolver una lista vacía que el arnés leería
      como "este generador no sirve". Un cero silencioso invalida una comparación sin que
      nadie se entere.
    """
    contador_sesion = next(_SESIONES)
    sesion = f"zipaes-eval-{os.getpid()}-{contador_sesion}"
    completo = [comando[0], "--session", sesion, *comando[1:]]

    proceso = subprocess.Popen(
        completo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding=CODIFICACION,
        bufsize=1,
    )
    assert proceso.stdout is not None

    emitidos = 0
    cerrado_por_el_consumidor = False
    try:
        for linea in proceso.stdout:
            candidato = linea.rstrip("\r\n")
            if candidato:
                emitidos += 1
                yield candidato
    except GeneratorExit:
        cerrado_por_el_consumidor = True
        raise
    finally:
        if proceso.poll() is None:
            proceso.terminate()
            try:
                proceso.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover
                proceso.kill()
                proceso.wait(timeout=15)
        proceso.stdout.close()

    # sólo se evalúa el "cero" cuando el flujo terminó solo, no cuando lo cortaron
    if emitidos == 0 and not cerrado_por_el_consumidor:
        error = ""
        if proceso.stderr is not None:
            error = (proceso.stderr.read() or "").strip()
            proceso.stderr.close()
        detalle = error.splitlines()[-1] if error else "sin salida ni error"
        raise RuntimeError(
            f"hashcat no emitió ningún candidato ({descripcion or ' '.join(comando[1:])}): "
            f"{detalle}"
        )


def generar_diccionario(palabras: list[str]) -> Iterator[str]:
    """El piso: la wordlist de train sin transformar."""
    yield from palabras


def generar_reglas(
    busqueda: BusquedaHashcat,
    wordlist: str,
    reglas: tuple[str, ...] = REGLAS_ESTANDAR,
) -> Iterator[str]:
    """Aplica el motor de reglas de hashcat, una regla por vez, en orden."""
    for nombre in reglas:
        ruta = busqueda.regla(nombre)
        if not os.path.isfile(ruta):
            continue
        yield from _stdout_hashcat(
            [busqueda.binario, "-a", "0", "--stdout", wordlist, "-r", ruta],
            descripcion=f"reglas {nombre} sobre {os.path.basename(wordlist)}",
        )


def generar_mascaras(
    busqueda: BusquedaHashcat,
    mascaras: tuple[str, ...] = MASCARAS_ESTANDAR,
) -> Iterator[str]:
    """Recorre los conjuntos de máscaras de hashcat, uno por vez, en orden de costo."""
    for nombre in mascaras:
        ruta = busqueda.mascara(nombre)
        if not os.path.isfile(ruta):
            continue
        yield from _stdout_hashcat(
            [busqueda.binario, "-a", "3", "--stdout", ruta],
            descripcion=f"máscaras {nombre}",
        )


def generar_markov(modelo, limite: int, *, seed: int = 1234, lote: int = 50_000) -> Iterator[str]:
    """Samplea del modelo de Markov en lotes, hasta ``limite`` candidatos."""
    generados = 0
    while generados < limite:
        cuantos = min(lote, limite - generados)
        for candidato in modelo.generate(cuantos, seed=seed + generados):
            generados += 1
            yield candidato


def generar_markov_ordenado(
    modelo, limite: int, *, min_len: int = 4, max_len: int = 24
) -> Iterator[str]:
    """Enumera del modelo de Markov **en orden decreciente de probabilidad**.

    Es la respuesta al hallazgo de la evaluación: los generadores por muestreo pierden contra
    la enumeración determinista porque no ordenan sus extracciones. Este sí ordena, y además
    usa lo que el modelo aprendió en vez de reglas escritas a mano. Determinista, sin azar.
    """
    for indice, candidato in enumerate(
        modelo.iter_ordenado(min_len=min_len, max_len=max_len), start=1
    ):
        yield candidato
        if indice >= limite:
            return


def ruta_wordlist_de(palabras: list[str], destino: str) -> str:
    """Vuelca una lista de palabras a disco (hashcat necesita un archivo)."""
    if not palabras:
        raise ValueError("la lista de palabras está vacía")
    os.makedirs(os.path.dirname(destino) or ".", exist_ok=True)
    with open(destino, "w", encoding=CODIFICACION) as handle:
        handle.write("\n".join(palabras) + "\n")
    return destino


def hay_herramienta(nombre: str) -> bool:
    return shutil.which(nombre) is not None
