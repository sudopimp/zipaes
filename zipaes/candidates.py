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
import math
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

#: peso que se le da al contexto más específico al interpolar con sus respaldos más cortos.
#: 0,8 deja un 20 % al nivel siguiente, y así geométricamente hacia abajo.
LAMBDA_INTERPOLACION = 0.8

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
        #: frecuencia global de cada carácter: el piso del retroceso, para que el modelo
        #: siempre tenga una respuesta aunque ningún sufijo del contexto se haya visto
        self.unigram: Counter = Counter()
        #: memoización de ``distribucion`` por sufijo; la búsqueda ordenada revisita contextos
        self._cache_dist: dict[str, list[tuple[str, float]]] = {}

    # --- entrenamiento ----------------------------------------------------- #
    def train_line(self, word: str) -> None:
        """Registra la palabra bajo contextos de **todos** los largos, de 1 a ``order``.

        Guardar también los contextos cortos es lo que habilita el retroceso. Sin ellos, un
        prefijo cuyo contexto de largo completo no apareció en el corpus no se puede
        continuar: el modelo se corta en seco justo donde más falta hace una estimación
        aproximada. Es además la forma estándar de construir un modelo de n-gramas — nivel
        completo más niveles de respaldo—, no un parche.
        """
        if not word:
            return
        if self._cache_dist:
            # el corpus cambió: lo memoizado deja de valer
            self._cache_dist.clear()
        self.corpus_size += 1
        relleno = START * self.order
        secuencia = relleno + word + END
        for index in range(len(relleno), len(secuencia)):
            caracter = secuencia[index]
            self.unigram[caracter] += 1
            for largo in range(1, self.order + 1):
                self.counts[secuencia[index - largo : index]][caracter] += 1

    def train(self, lines: Iterable[str]) -> MarkovModel:
        for linea in lines:
            self.train_line(linea.rstrip("\r\n"))
        self._cache_dist.clear()
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
        modelo._reconstruir_unigram()
        return modelo

    def _reconstruir_unigram(self) -> None:
        """Recomputa la frecuencia global desde los contextos de largo 1.

        Va derivada y no serializada, así los modelos guardados antes de que existiera el
        piso siguen cargando.
        """
        self.unigram = Counter()
        for contexto, contador in self.counts.items():
            if len(contexto) == 1:
                self.unigram.update(contador)

    def logprobabilidad(self, palabra: str) -> float:
        """Log-probabilidad de una palabra completa bajo el modelo, incluido el fin.

        Es la función de puntuación que define el orden de ``iter_ordenado``: sirve para
        comprobar que ese orden es, en efecto, decreciente.
        """
        secuencia = START * self.order
        total = 0.0
        for caracter in palabra + END:
            probabilidad = dict(self.distribucion(secuencia)).get(caracter, 0.0)
            if probabilidad <= 0.0:
                return float("-inf")
            total += math.log(probabilidad)
            secuencia += caracter
        return total

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

    # --- enumeración ordenada por probabilidad ----------------------------- #

    def distribucion(self, secuencia: str) -> list[tuple[str, float]]:
        """Distribución del próximo carácter, interpolando contextos de largo decreciente.

        Se combinan el contexto completo y sus respaldos más cortos con pesos que decaen
        geométricamente (interpolación estilo Jelinek-Mercer): así un contexto nunca visto se
        estima con los más generales en vez de quedar sin respuesta.

        El resultado se memoiza por el sufijo de largo ``order``: la distribución sólo depende
        de esos caracteres, y la búsqueda ordenada revisita los mismos contextos miles de
        veces.
        """
        clave = secuencia[-self.order :] if self.order else ""
        cacheado = self._cache_dist.get(clave)
        if cacheado is not None:
            return cacheado

        niveles: list[Counter] = []
        for largo in range(min(len(secuencia), self.order), 0, -1):
            contador = self.counts.get(secuencia[len(secuencia) - largo :])
            if contador:
                niveles.append(contador)
        if self.unigram:
            # piso: frecuencia global, para que ningún contexto quede sin respuesta
            niveles.append(self.unigram)
        if not niveles:
            self._cache_dist[clave] = []
            return []

        acumulado: dict[str, float] = {}
        peso = 1.0
        for contador in niveles:
            total = sum(contador.values())
            if not total:
                continue
            for caracter, cuenta in contador.items():
                acumulado[caracter] = acumulado.get(caracter, 0.0) + peso * (cuenta / total)
            peso *= 1 - LAMBDA_INTERPOLACION

        # las interpolaciones dejan masa sin repartir (1 + (1-λ) + (1-λ)² … = 1/λ): se
        # normaliza al final para que las probabilidades sean probabilidades
        masa = sum(acumulado.values())
        if masa > 0:
            acumulado = {caracter: valor / masa for caracter, valor in acumulado.items()}

        resultado = sorted(acumulado.items(), key=lambda par: (-par[1], par[0]))
        self._cache_dist[clave] = resultado
        return resultado

    def iter_ordenado(
        self,
        *,
        min_len: int = 4,
        max_len: int = 24,
        tope_cola: int = 200_000,
        ramas: int = 32,
    ):
        """Enumera candidatos en orden **decreciente de probabilidad**, no por muestreo.

        Es la diferencia que la evaluación dejó en evidencia: muestrear extrae de la
        distribución pero no la ordena, así que a presupuesto chico gasta intentos en la cola
        de su propio modelo, mientras una enumeración determinista recorre primero la zona
        densa. Esto hace lo segundo usando lo que el modelo aprendió.

        El recorrido es mejor-primero sobre el árbol de prefijos: se mantiene una cola de
        prefijos con su log-probabilidad y se expande siempre el más probable. Un prefijo es
        una **cota superior** de todos sus descendientes (la probabilidad sólo baja al
        alargar), así que sacar de la cola en orden de probabilidad garantiza que lo emitido
        sale en ese mismo orden.

        Dos cotas que lo hacen viable, las dos aproximadas y las dos declaradas:

        - ``ramas``: de cada contexto se expanden sólo los ``ramas`` caracteres más probables.
          El vocabulario llega a 214 caracteres y la cola de la distribución aporta una
          fracción despreciable de la masa, así que recortarla no cambia lo que se emite
          primero y multiplica la velocidad.
        - ``tope_cola``: la cola se poda a este tamaño cuando lo duplica, descartando los
          prefijos menos probables. La poda se hace **cada ``tope_cola`` inserciones**, no en
          cada una: hacerla siempre convierte el recorrido en un ordenamiento completo por
          candidato, que es exactamente el error que había antes.

        Con las dos, la enumeración es exacta en la cabeza —la parte que decide una
        recuperación— y aproximada en la cola larga, que casi nunca se consume.

        Es determinista: no usa azar.
        """
        if not self.counts:
            raise ValueError("el modelo está vacío: entrenalo antes de enumerar")

        import heapq

        relleno = START * self.order
        # la clave es -log P, así el heap saca primero el más probable
        cola: list[tuple[float, str]] = [(0.0, relleno)]
        umbral_poda = tope_cola * 2

        while cola:
            neg_log, secuencia = heapq.heappop(cola)
            cuerpo = secuencia[self.order :]

            if cuerpo.endswith(END):
                candidato = cuerpo[:-1]
                if len(candidato) >= min_len:
                    yield candidato
                continue

            if len(cuerpo) > max_len:
                continue

            for caracter, probabilidad in self.distribucion(secuencia)[:ramas]:
                if probabilidad <= 0.0:
                    continue
                if caracter == END:
                    # sólo se cierra si ya tiene el largo mínimo
                    if len(cuerpo) >= min_len:
                        heapq.heappush(cola, (neg_log - math.log(probabilidad), secuencia + END))
                    continue
                if len(cuerpo) >= max_len:
                    continue
                heapq.heappush(cola, (neg_log - math.log(probabilidad), secuencia + caracter))

            if len(cola) > umbral_poda:
                cola = heapq.nsmallest(tope_cola, cola)
                heapq.heapify(cola)


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
