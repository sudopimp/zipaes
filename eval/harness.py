"""Mide cuántas contraseñas de un conjunto de test se recuperan por presupuesto de intentos.

Es el protocolo estándar en adivinación de contraseñas: en vez de una tasa de acierto única
(que depende de cuánto tiempo corras), se mide **qué porcentaje del test se recupera dentro de
los primeros G intentos**, para varios G. Así dos generadores se comparan a presupuesto igual,
que es la única comparación que significa algo.

Detalles de conteo, que importan:

- el presupuesto se gasta en **intentos**, no en candidatos únicos: un generador que repite
  candidatos desperdicia presupuesto, y eso es correcto que se refleje;
- se registra también cuántos **únicos** se probaron, para poder leer cuánto desperdicio hubo;
- la primera aparición de una contraseña gana; se saca del conjunto y no vuelve a contar.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

__all__ = ["Resultado", "medir", "PRESUPUESTOS_POR_DEFECTO"]

#: puntos de la curva donde se reporta
PRESUPUESTOS_POR_DEFECTO = (10**2, 10**3, 10**4, 10**5, 10**6)


@dataclass
class Resultado:
    """Resultado de medir un generador contra un conjunto de test."""

    generador: str
    tamano_test: int
    intentos: int = 0
    unicos: int = 0
    encontradas: int = 0
    segundos: float = 0.0
    #: (posición base 1, contraseña) de cada acierto, en orden de aparición
    hallazgos: list[tuple[int, str]] = field(default_factory=list)
    curva: dict[int, float] = field(default_factory=dict)

    @property
    def rangos(self) -> list[int]:
        """Posiciones donde apareció cada contraseña hallada."""
        return [rango for rango, _ in self.hallazgos]

    @property
    def desperdicio(self) -> float:
        """Fracción del presupuesto gastada en candidatos repetidos."""
        return 0.0 if not self.intentos else 1 - (self.unicos / self.intentos)

    @property
    def por_segundo(self) -> float:
        return self.intentos / self.segundos if self.segundos else 0.0

    def a_presupuesto(self, presupuesto: int) -> int:
        """Cuántas contraseñas se habían recuperado al llegar a ese presupuesto."""
        return sum(1 for r in self.rangos if r <= presupuesto)

    def a_presupuesto_en(self, presupuesto: int, subconjunto: set[str]) -> int:
        """Igual que ``a_presupuesto``, pero contando sólo un subconjunto de la entrada."""
        return sum(
            1
            for rango, palabra in self.hallazgos
            if rango <= presupuesto and palabra in subconjunto
        )

    def residuo(self, presupuesto: int) -> float:
        """Porcentaje recuperado dentro del presupuesto, sobre el total del test."""
        return 100.0 * self.a_presupuesto(presupuesto) / self.tamano_test

    def residuo_en(self, presupuesto: int, subconjunto: set[str]) -> float:
        """Porcentaje recuperado dentro del presupuesto, sobre ese subconjunto del test.

        Sirve para comparar peras con peras: un modelo que sólo produce contraseñas de hasta
        10 caracteres tiene que medirse contra las de hasta 10 caracteres, no contra todas.
        """
        if not subconjunto:
            return 0.0
        return 100.0 * self.a_presupuesto_en(presupuesto, subconjunto) / len(subconjunto)

    def summary(self) -> dict:
        return {
            "generador": self.generador,
            "tamano_test": self.tamano_test,
            "intentos": self.intentos,
            "unicos": self.unicos,
            "encontradas": self.encontradas,
            "desperdicio_pct": round(100 * self.desperdicio, 2),
            "intentos_por_segundo": round(self.por_segundo, 1),
            "segundos": round(self.segundos, 2),
            "curva_pct": {str(k): round(v, 3) for k, v in sorted(self.curva.items())},
        }


def medir(
    generador: str,
    candidatos: Iterable[str],
    test: Sequence[str] | set[str],
    *,
    presupuesto: int = 10**6,
    puntos: Sequence[int] = PRESUPUESTOS_POR_DEFECTO,
    tope_tiempo: float | None = None,
) -> Resultado:
    """Consume ``candidatos`` hasta agotar el presupuesto y devuelve la curva.

    ``test`` es el conjunto de contraseñas a recuperar. El generador no lo ve: sólo se consulta
    la pertenencia, que es exactamente el oráculo de un ataque real.
    """
    objetivo = set(test)
    resultado = Resultado(generador=generador, tamano_test=len(objetivo))
    if not objetivo:
        return resultado

    puntos_ordenados = sorted(puntos)
    siguiente = 0
    vistos: set[str] = set()
    inicio = time.perf_counter()

    try:
        for candidato in candidatos:
            resultado.intentos += 1

            if candidato not in vistos:
                vistos.add(candidato)
                resultado.unicos += 1
                if candidato in objetivo:
                    objetivo.discard(candidato)
                    resultado.encontradas += 1
                    resultado.hallazgos.append((resultado.intentos, candidato))

            while (
                siguiente < len(puntos_ordenados)
                and resultado.intentos >= puntos_ordenados[siguiente]
            ):
                resultado.curva[puntos_ordenados[siguiente]] = resultado.residuo(
                    puntos_ordenados[siguiente]
                )
                siguiente += 1

            if resultado.intentos >= presupuesto or not objetivo:
                break

            if (
                tope_tiempo is not None
                and resultado.intentos % 100_000 == 0
                and time.perf_counter() - inicio > tope_tiempo
            ):
                break
    finally:
        # Cortar el presupuesto deja el generador a mitad de camino: si no se lo cierra, el
        # proceso que tenga detrás (hashcat) sigue vivo y ensucia la medición siguiente.
        cerrar = getattr(candidatos, "close", None)
        if callable(cerrar):
            cerrar()

    resultado.segundos = time.perf_counter() - inicio

    # completar la curva, incluido el caso "se agotaron las contraseñas antes del presupuesto"
    for punto in puntos_ordenados:
        if punto not in resultado.curva:
            resultado.curva[punto] = resultado.residuo(punto)

    return resultado
