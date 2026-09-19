# Evaluación de generadores de candidatos

Esto es el arnés que mide **qué tan bueno es cada generador de candidatos** a presupuesto de
intentos igual. Existe porque, hasta que esto corrió, el proyecto afirmaba cosas sobre su
generador de candidatos sin ninguna medición detrás. El motor de candidatos decide si una
contraseña se recupera mucho más que el formato, así que es la parte que hay que medir.

## El protocolo

El estándar en adivinación de contraseñas no es una tasa de acierto única — eso depende de
cuánto tiempo corras — sino la **curva de recuperación por presupuesto**: qué porcentaje de un
conjunto de contraseñas que el generador **nunca vio** se recupera dentro de los primeros
10², 10³, 10⁴, 10⁵, 10⁶ intentos.

Cada generador recibe exactamente el mismo presupuesto de intentos, y se cuentan **intentos**,
no candidatos únicos: repetir un candidato desperdicia presupuesto real y eso queda reflejado
en la columna de desperdicio.

```
corpus      rockyou.txt (14.344.391 entradas) — el corpus público que usa el área
normalizado se quitan duplicados exactos, y se descartan las de menos de 4 o más de 40
            caracteres (las de 1-3 se recuperan trivialmente y ensucian la comparación)
partición   por contraseña, semilla fija, SIN solapamiento exacto entre train y test
            train 14.319.984 · test 20.000
ventana     de dónde sale el test, y esto cambia la pregunta que responde la evaluación:
              --ventana-cabeza 100000  → de las contraseñas que la gente realmente usa
                                          ("una persona al azar", protocolo principal)
              sin la opción            → uniforme sobre las únicas ("una contraseña
                                          única al azar", más duro, sesga contra los
                                          modelos por probabilidad)
oráculo     pertenencia al conjunto de test, que es exactamente lo que un ataque real consulta
```

El sesgo de la métrica uniforme no es teórico y está medido: el mismo `best64` da **0,34 %** o
**14,79 %** a 10⁵ intentos según de dónde salga el test. Por eso se reportan las dos.

## Los generadores comparados

| generador | qué es |
|---|---|
| `diccionario` | la wordlist de train tal cual. El piso. |
| `reglas:best64` | motor de reglas de hashcat sobre la wordlist. **Lo que hace la práctica real.** |
| `reglas:dive` | ídem con el conjunto de reglas `dive`. |
| `mascaras:rockyou` | los conjuntos de máscaras de hashcat por rango de frecuencia. |
| `markov:ordenN` | el modelo de n-gramas del paquete, entrenado sobre train. |
| `passgpt` | PassGPT (arXiv:2306.01545), el modelo neuronal publicado por sus autores. |
| `passgpt:ordenado` | El mismo modelo, pero **enumerando** su distribución por probabilidad decreciente en vez de samplearla. |

## Cómo correrlo

```bash
pip install -e ".[eval]"          # opcional: sólo para el generador neuronal
python eval/run_eval.py --presupuesto 1000000 --test-size 20000 --salida eval/results
python eval/run_eval.py --passgpt  # agrega la fila del modelo neuronal
```

Deja `eval/results/resultados.json` (todo, máquina-legible) y `eval/results/tabla.md`.
La wordlist de train que necesita hashcat se escribe fuera del repo, en el directorio temporal.

## Limitaciones declaradas

Son reales y afectan la lectura de los números. Van acá y no en una nota al pie:

1. **La partición no es por usuario.** `rockyou.txt` tal como se distribuye no trae identificador
   de usuario, así que no se puede separar por persona como hacen los trabajos que sí lo tienen.
   Particionar al azar deja pasar variantes morfológicas de una misma contraseña entre train y
   test (`veronica1` en train, `veronica2` en test). Eso favorece a todos los generadores, pero
   infla los valores absolutos.
2. **Contaminación del modelo neuronal.** PassGPT fue entrenado sobre datos derivados de
   RockYou, el mismo corpus con el que se evalúa. Su partición de test puede estar parcialmente
   memorizada. Por eso su curva se reporta **sólo sobre el subconjunto de ≤10 caracteres** (el
   modelo no produce longitudes mayores) y con esta advertencia.
3. **Los modelos por muestreo no tienen orden de prioridad intrínseco.** En las reglas y las
   máscaras el orden es el del motor y es determinista; en Markov y PassGPT es el orden en que
   se samplea. Es lo que hace la literatura, pero implica que dos corridas del mismo modelo dan
   curvas ligeramente distintas.
4. **Un solo punto de operación.** Todo se mide sin GPU y con la misma configuración de reglas.
   Un atacante real elegiría la configuración según lo que sepa del objetivo; esta tabla mide
   generadores genéricos, no estrategias dirigidas.

## Resultados

Ver [`docs/EVALUACION.md`](../docs/EVALUACION.md) para la tabla y la lectura.
