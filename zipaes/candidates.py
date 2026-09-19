"""Generación de candidatos: mutaciones, mangleo tipo PACK y modelo de Markov.

El motor de candidatos decide si una contraseña se recupera, mucho más que el formato.
Las mutaciones fijas (mayúsculas, sufijos numéricos) son la técnica de los 90; esto
agrega las dos familias que sí se usan hoy:

* **Mangleo estructural** al estilo PACK/PRINCE: composición de palabras, leet, inversión,
  separadores, años, sufijos y prefijos. Barato y muy efectivo contra contraseñas humanas.
* **Modelo de Markov** entrenado sobre un corpus (el equivalente a ``hcstat`` en hashcat,
  o a los modelos de n-gramas que usa la literatura de adivinación de contraseñas):
  aprende qué caracteres siguen a cuáles y genera candidatos con esa distribución. Se
  entrena una vez y se guarda en disco.

Ninguna de las dos entrega una contraseña aleatoria de 20 caracteres. Contra eso no hay
estrategia que sirva: es matemática, no perseverancia.
"""

from __future__ import annotations

import itertools
import json
import os
import random
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator

__all__ = [
    "MarkovModel",
    "train",
    "mangle",
    "leet",
    "compose",
    "years",
    "mutations",
    "iter_candidates",
    "build_wordlist",
    "build_candidates",
]

#: marcadores de inicio y fin para el modelo de Markov
START = "^"
END = "$"

#: sustituciones leet habituales
LEET = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "b": "8",
    "g": "9",
    "l": "1",
    "z": "2",
}

SUFIJOS = (
    "",
    "1",
    "12",
    "123",
    "1234",
    "12345",
    "123456",
    "!",
    "!!",
    "@",
    ".",
    "69",
    "99",
    "007",
    "01",
    "00",
    "22",
)

SEPARADORES = ("", "_", "-", ".", "@")


def years(start: int = 1970, end: int = 2030) -> list[str]:
    """Años como cadena, incluidos los de dos dígitos."""
    out: list[str] = []
    for anio in range(start, end + 1):
        out.append(str(anio))
        out.append(str(anio)[-2:])
    return out


def leet(word: str, *, full: bool = False) -> list[str]:
    """Variantes leet de una palabra.

    Con ``full=False`` devuelve sólo la sustitución completa de todas las letras
    sustituibles; con ``full=True`` devuelve además las variantes de un solo carácter,
    que es lo que hace la gente de verdad.
    """
    variantes: set[str] = set()
    completa = "".join(LEET.get(c.lower(), c) for c in word)
    if completa != word:
        variantes.add(completa)

    if full:
        for index, char in enumerate(word):
            sustituto = LEET.get(char.lower())
            if sustituto:
                variantes.add(word[:index] + sustituto + word[index + 1 :])
        # mayúscula inicial de la variante leet
        if completa:
            variantes.add(completa.capitalize())
    return sorted(variantes)


def mangle(word: str, *, con_anios: bool = True) -> Iterator[str]:
    """Mangleo de una palabra al estilo PACK: una sola fuente, muchas variantes."""
    vistas: set[str] = set()

    def emitir(candidato: str) -> Iterator[str]:
        if candidato and len(candidato) <= 64 and candidato not in vistas:
            vistas.add(candidato)
            yield candidato

    palabras = [word, word.capitalize(), word.upper(), word.lower()]
    for base in palabras:
        yield from emitir(base)
        for sufijo in SUFIJOS:
            yield from emitir(base + sufijo)
        for prefijo in ("", "1", "12", "!", "el", "la", "my", "the"):
            yield from emitir(prefijo + base)
        yield from emitir(base + base)
        yield from emitir(base[::-1])

    for variante in leet(word, full=True):
        yield from emitir(variante)
        for sufijo in SUFIJOS:
            yield from emitir(variante + sufijo)

    if con_anios:
        for base in (word, word.capitalize(), word.lower()):
            for anio in years():
                yield from emitir(base + anio)
                yield from emitir(anio + base)


def compose(primera: Iterable[str], segunda: Iterable[str]) -> Iterator[str]:
    """Composición de dos listas de palabras (estilo PRINCE)."""
    for uno in primera:
        if not uno:
            continue
        for dos in segunda:
            if not dos:
                continue
            for separador in SEPARADORES:
                yield f"{uno}{separador}{dos}"
            yield f"{uno.capitalize()}{dos}"
            yield f"{uno}{dos.capitalize()}"


def mutations(word: str, suffixes: Iterable[str] = SUFIJOS) -> Iterator[str]:
    """Variantes simples de una palabra (compatibilidad con versiones anteriores)."""
    vistas: set[str] = set()
    for base in (word, word.lower(), word.upper(), word.capitalize()):
        if base and base not in vistas:
            vistas.add(base)
            yield base
        for sufijo in suffixes:
            candidato = f"{base}{sufijo}"
            if candidato not in vistas:
                vistas.add(candidato)
                yield candidato


def iter_candidates(
    words: Iterable[str],
    *,
    with_mutations: bool = False,
    min_len: int = 1,
    max_len: int = 256,
) -> Iterator[str]:
    """Recorre palabras aplicando (o no) mutaciones y filtros de longitud."""
    for word in words:
        palabra = word.rstrip("\r\n")
        if not palabra:
            continue
        flujo = mutations(palabra) if with_mutations else (palabra,)
        for candidato in flujo:
            if min_len <= len(candidato) <= max_len:
                yield candidato


# --------------------------------------------------------------------------- #
# Modelo de Markov
# --------------------------------------------------------------------------- #
class MarkovModel:
    """Modelo de caracteres de orden *n* entrenado sobre un corpus de contraseñas.

    Es la misma idea que ``hcstat2`` de hashcat o que los modelos de n-gramas de la
    literatura de adivinación: la contraseña no es aleatoria, tiene estructura, y esa
    estructura se puede aprender de un corpus.
    """

    def __init__(self, order: int = 2) -> None:
        if order < 1:
            raise ValueError("el orden debe ser al menos 1")
        self.order = order
        self.counts: dict[str, Counter] = defaultdict(Counter)
        self.corpus_size = 0

    # --- entrenamiento ----------------------------------------------------- #
    def train_line(self, word: str) -> None:
        if not word:
            return
        self.corpus_size += 1
        relleno = START * self.order
        secuencia = relleno + word + END
        for index in range(len(relleno), len(secuencia)):
            contexto = secuencia[index - self.order : index]
            self.counts[contexto][secuencia[index]] += 1

    def train(self, lines: Iterable[str]) -> MarkovModel:
        for linea in lines:
            self.train_line(linea.rstrip("\r\n"))
        return self

    def contexts(self) -> int:
        return len(self.counts)

    @property
    def vocabulary(self) -> int:
        letras: set[str] = set()
        for contador in self.counts.values():
            letras.update(contador)
        return len(letras)

    # --- persistencia ------------------------------------------------------ #
    def to_dict(self) -> dict:
        return {
            "order": self.order,
            "corpus_size": self.corpus_size,
            "counts": {ctx: dict(cont) for ctx, cont in self.counts.items()},
        }

    def save(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, ensure_ascii=False)
        return path

    @classmethod
    def from_dict(cls, data: dict) -> MarkovModel:
        modelo = cls(order=int(data.get("order", 2)))
        modelo.corpus_size = int(data.get("corpus_size", 0))
        for contexto, contador in (data.get("counts") or {}).items():
            modelo.counts[contexto] = Counter(contador)
        return modelo

    @classmethod
    def load(cls, path: str) -> MarkovModel:
        with open(path, encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    # --- generación -------------------------------------------------------- #
    def _siguiente(self, contexto: str, rng: random.Random) -> str | None:
        """Elige el próximo carácter, con retroceso a contextos más cortos."""
        for largo in range(len(contexto), -1, -1):
            clave = contexto[len(contexto) - largo :]
            contador = self.counts.get(clave)
            if contador:
                poblacion = list(contador)
                pesos = list(contador.values())
                return rng.choices(poblacion, weights=pesos, k=1)[0]
        return None

    def generate(
        self,
        count: int,
        *,
        min_len: int = 4,
        max_len: int = 24,
        seed: int | None = None,
        dedupe: bool = True,
    ) -> list[str]:
        """Genera candidatos sampleando el modelo."""
        if not self.counts:
            raise ValueError("el modelo está vacío: entrenalo antes de generar")
        rng = random.Random(seed)
        salida: list[str] = []
        vistas: set[str] = set()
        intentos = 0
        limite = max(count * 50, 1000)

        while len(salida) < count and intentos < limite:
            intentos += 1
            palabra = ""
            contexto = START * self.order
            while len(palabra) <= max_len:
                caracter = self._siguiente(contexto, rng)
                if caracter is None or caracter == END:
                    break
                palabra += caracter
                contexto = (contexto + caracter)[-self.order :]
            if not (min_len <= len(palabra) <= max_len):
                continue
            if dedupe and palabra in vistas:
                continue
            vistas.add(palabra)
            salida.append(palabra)
        return salida


def train(lines: Iterable[str], order: int = 2, max_lines: int | None = None) -> MarkovModel:
    """Entrena un modelo de Markov sobre un corpus (una contraseña por línea)."""
    modelo = MarkovModel(order=order)
    for index, linea in enumerate(lines):
        if max_lines is not None and index >= max_lines:
            break
        modelo.train_line(linea.rstrip("\r\n"))
    return modelo


# --------------------------------------------------------------------------- #
# Construcción de listas
# --------------------------------------------------------------------------- #
def build_wordlist(
    bases: Iterable[str],
    *,
    with_mutations: bool = True,
    extra_digits: bool = True,
) -> list[str]:
    """Lista dirigida a partir de palabras base (compatibilidad hacia atrás)."""
    salida: list[str] = []
    vistas: set[str] = set()
    for base in bases:
        flujo = mutations(base) if with_mutations else (base,)
        for candidato in flujo:
            if candidato not in vistas:
                vistas.add(candidato)
                salida.append(candidato)
    if extra_digits:
        for tamano in (2, 4):
            for digitos in itertools.product("0123456789", repeat=tamano):
                candidato = "".join(digitos)
                if candidato not in vistas:
                    vistas.add(candidato)
                    salida.append(candidato)
    return salida


def build_candidates(
    *,
    bases: Iterable[str] = (),
    extras: Iterable[str] = (),
    corpus_path: str | None = None,
    model: MarkovModel | None = None,
    model_count: int = 0,
    seed: int | None = None,
    mangling: bool = True,
    compose_bases: bool = True,
    digits: bool = False,
) -> list[str]:
    """Construye una lista de candidatos combinando todas las estrategias.

    El orden importa y es deliberado: primero lo dirigido y barato (mangleo de las palabras
    base), después la composición, y al final los candidatos del modelo, que son los más
    numerosos y los menos probables en cada posición individual.
    """
    vistas: set[str] = set()
    salida: list[str] = []

    def agregar(candidato: str) -> None:
        if candidato and candidato not in vistas:
            vistas.add(candidato)
            salida.append(candidato)

    lista_bases = [b for b in bases if b]

    for base in lista_bases:
        if mangling:
            for candidato in mangle(base):
                agregar(candidato)
        else:
            for candidato in mutations(base):
                agregar(candidato)

    for extra in extras:
        agregar(extra)

    if compose_bases and len(lista_bases) > 1:
        for candidato in compose(lista_bases, lista_bases):
            agregar(candidato)

    if digits:
        for candidato in build_wordlist([], extra_digits=True):
            agregar(candidato)

    modelo = model
    if modelo is None and corpus_path:
        if not os.path.isfile(corpus_path):
            raise FileNotFoundError(f"no existe el corpus: {corpus_path}")
        with open(corpus_path, encoding="utf-8", errors="ignore") as handle:
            modelo = train(handle)

    if modelo is not None and model_count > 0:
        for candidato in modelo.generate(model_count, seed=seed):
            agregar(candidato)

    return salida
