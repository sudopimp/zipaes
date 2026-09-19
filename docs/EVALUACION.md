# Evaluación de generadores de candidatos

Esta página existe porque el proyecto afirmaba cosas sobre su generador de candidatos sin
ninguna medición detrás. Ahora está medido, y el resultado no favorece al proyecto.

Lo corre [`eval/run_eval.py`](../eval/README.md). Reproducible: mismo corpus público, misma
semilla, mismo protocolo.

## El resultado

**rockyou.txt** · 14.344.391 entradas → 14.339.984 únicas · train 14.319.984 / test 20.000
held-out, sin solapamiento exacto. Presupuesto **1.000.000 de intentos** para cada generador.

### Todo el conjunto de test (20.000 contraseñas)

| generador | 10² | 10³ | 10⁴ | 10⁵ | 10⁶ | desperdicio |
|---|---|---|---|---|---|---|
| `mascaras:rockyou` | 0.00% | 0.01% | 0.06% | 0.30% | **2.63%** | 0.0% |
| `reglas:best64` | 0.00% | 0.01% | 0.06% | 0.34% | 2.15% | 26.4% |
| `reglas:dive` | 0.00% | 0.01% | 0.04% | 0.24% | 1.36% | 32.0% |
| `markov:ordenado` | 0.00% | 0.00% | **0.06%** | **0.31%** | 0.49% | 0.0% |
| `markov:muestreo` | 0.00% | 0.00% | 0.01% | 0.07% | 0.47% | 6.9% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |

La fila `passgpt` (0,86 % a 10⁶) sale de la corrida aparte que incluye el modelo neuronal; el
resto, de la corrida sin él. Los dos conjuntos de test y el protocolo son idénticos, y los
baselines reprodujeron **exactamente** los mismos números en las dos corridas, así que son
comparables.

### Sólo contraseñas de hasta 10 caracteres (16.674)

Se conserva como **diagnóstico de la limitación de PassGPT**, que no produce longitudes
mayores. Pero ojo: no es la tabla principal. Recortar el test a las longitudes que un
generador sí cubre esconde la limitación en vez de mostrarla, y penaliza a los que sí cubren
todas — por eso la comparación de arriba es sobre el test completo.

| generador | 10⁴ | 10⁵ | 10⁶ |
|---|---|---|---|
| `mascaras:rockyou` | 0.07% | 0.36% | 3.15% |
| `reglas:best64` | 0.07% | 0.40% | 2.48% |
| `reglas:dive` | 0.04% | 0.29% | 2.00% |
| `passgpt` | 0.03% | 0.11% | 1.03% |
| `markov:muestreo` | 0.01% | 0.09% | 0.57% |
| `markov:ordenado` | 0.02% | 0.08% | 0.42% |

## El arreglo: enumerar por probabilidad en vez de samplear

La primera corrida dejó un diagnóstico claro: los generadores por muestreo pierden **porque no
ordenan sus extracciones**. Un modelo por muestreo sabe qué contraseñas son probables, pero las
va soltando en orden arbitrario, así que a presupuesto chico gasta intentos en la cola de su
propia distribución.

La respuesta es `MarkovModel.iter_ordenado` (`zipaes wordlist --ordenado`): un recorrido
**mejor-primero** sobre el árbol de prefijos, con la cola de candidatos ordenada por
log-probabilidad. Un prefijo es cota superior de todos sus descendientes, así que sacar de la
cola en orden de probabilidad garantiza que lo emitido sale en ese orden. Es determinista y usa
lo que el modelo aprendió, no reglas escritas a mano.

El efecto medido, contra la misma versión sampleando:

| presupuesto | muestreo | ordenado | mejora |
|---|---|---|---|
| 10.000 | 0.01% | 0.06% | **6x** |
| 100.000 | 0.07% | 0.31% | **4,4x** |
| 1.000.000 | 0.47% | 0.49% | 1,04x |

A 100.000 intentos el ordenado **le gana a las máscaras de hashcat** (0,31 % contra 0,30 %) y
queda a un pelo de `best64`. A 10.000 empata con los dos. **La ventaja se diluye a medida que
crece el presupuesto**: con suficientes extracciones, el muestreo termina sacando lo mismo que
la enumeración ordenada, sólo que más tarde.

Costo: unos 3.000-4.800 candidatos por segundo, 166 MB de memoria, **un solo núcleo de CPU y
cero GPU**. Un millón de candidatos ordenados son ~3,5 minutos de CPU.

## Qué dice esto, sin adornos

1. **No alcanza para decir que es el estado del arte.** A 10⁶ el orden de la tabla lo siguen
   encabezando las máscaras y las reglas de hashcat: la enumeración diseñada a mano le gana al
   modelo aprendido cuando el presupuesto es grande.
2. **Pero el diagnóstico era correcto y el arreglo funciona.** Ordenar vale 4-6× a los
   presupuestos donde una recuperación se decide de verdad (10⁴-10⁵ intentos), y ahí el modelo
   aprendido empata o supera a la enumeración hecha a mano.
3. **PassGPT (el modelo publicado) sigue por delante de los dos Markov a 10⁶** (0,86 % contra
   0,49 %), y lo hace aun teniendo prohibido producir contraseñas de más de 10 caracteres. Su
   problema no es la calidad del modelo: es que samplea.
4. **El paso que falta es evidente y está sin hacer: aplicar el mismo orden a la distribución
   del modelo neuronal.** PassGPT sabe puntuar; lo que no hace es enumerar en orden. Un
   decodificado por haz o por top-k sobre sus probabilidades debería juntar lo mejor de los dos,
   y es exactamente lo que la variante guiada del paper propone. Requiere GPU, pero acotada
   (minutos, no horas) porque no hace falta samplear millones: hace falta puntuar.

## Lo que sí sale bien parado

- **Las máscaras ganan con 0 % de desperdicio.** Enumerar sin repetir, en orden de probabilidad,
  es lo que más rinde por intento.
- `reglas:best64` gasta un **26,4 %** de su presupuesto repitiendo candidatos y aun así queda
  segunda: deduplicar antes de atacar es una mejora gratis que quedó sin hacer.
- El conjunto de test es held-out de verdad: por eso el `diccionario` saca exactamente 0 %.

## Limitaciones (afectan la lectura de los números)

1. **La partición no es por usuario.** `rockyou.txt` no trae identificador de usuario, así que
   no se puede separar por persona como hacen los trabajos que sí lo tienen. Particionar al azar
   deja pasar variantes morfológicas entre train y test. Eso favorece a todos por igual, pero
   infla los valores absolutos.
2. **Contaminación de PassGPT.** Fue entrenado sobre datos derivados de RockYou, el mismo corpus
   con el que se evalúa: su partición de test puede estar parcialmente memorizada. Su número
   podría estar *inflado* por memorización, y **aun así pierde**. Eso hace la conclusión más
   fuerte, no más débil.
3. **Los modelos por muestreo no tienen orden de prioridad intrínseco.** Dos corridas del mismo
   modelo dan curvas algo distintas. Las reglas y las máscaras son deterministas.
4. **Un solo punto de operación.** Todo sin GPU y con una configuración fija de reglas. Un
   atacante real elegiría la configuración según lo que sepa del objetivo; esto mide generadores
   genéricos, no estrategias dirigidas.
5. **Los valores absolutos son bajos a propósito.** El test es una muestra al azar de las
   14,3 millones de contraseñas únicas de rockyou, o sea que incluye una cola enorme de
   contraseñas irrepetibles. Un objetivo real (una persona concreta) es mucho más fácil que una
   muestra al azar de una filtración. Esta tabla mide **calidad relativa de generadores**, no la
   probabilidad de abrir un zip cualquiera.

## Cómo reproducirlo

```bash
python eval/run_eval.py --presupuesto 1000000 --test-size 20000 --salida eval/results
python eval/run_eval.py --presupuesto 1000000 --test-size 20000 --salida eval/results --passgpt
```

Los crudos quedan en `eval/results/resultados.json` (la curva agregada de cada generador, con
intentos, únicos, desperdicio y velocidad) y la tabla en `eval/results/tabla.md`.

Dentro de una corrida, el medidor conserva la posición exacta de cada acierto, que es lo que
permite derivar la curva de un subconjunto —como la de ≤10 caracteres— sin volver a correr
nada. Esas posiciones no se persisten en el JSON, para no volcar al repositorio las contraseñas
del corpus.
