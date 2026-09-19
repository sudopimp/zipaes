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
| `reglas:dive` | 0.00% | 0.01% | 0.04% | 0.26% | 1.76% | 27.4% |
| `passgpt` | 0.00% | 0.00% | 0.03% | 0.10% | 0.86% | 0.7% |
| `markov:orden2` | 0.00% | 0.00% | 0.01% | 0.07% | 0.47% | 6.9% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |

### Sólo contraseñas de hasta 10 caracteres (16.674) — la comparación justa con PassGPT

PassGPT sólo produce hasta 10 caracteres, así que medirlo contra el test completo le pondría un
techo estructural. Esta tabla es la que vale para compararlo.

| generador | 10² | 10³ | 10⁴ | 10⁵ | 10⁶ | desperdicio |
|---|---|---|---|---|---|---|
| `mascaras:rockyou` | 0.00% | 0.01% | 0.07% | 0.36% | **3.15%** | 0.0% |
| `reglas:best64` | 0.00% | 0.01% | 0.07% | 0.40% | 2.48% | 26.4% |
| `reglas:dive` | 0.00% | 0.01% | 0.04% | 0.29% | 2.00% | 27.4% |
| `passgpt` | 0.00% | 0.00% | 0.03% | 0.11% | 1.03% | 0.7% |
| `markov:orden2` | 0.00% | 0.00% | 0.01% | 0.09% | 0.57% | 6.9% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |

## Qué dice esto, sin adornos

**Los dos generadores por muestreo pierden, y el modelo neuronal pierde más de lo que se
esperaba.** A un millón de intentos:

- las **máscaras de hashcat** (enumeración determinista de las formas más probables) recuperan
  **3,15 %**;
- las **reglas de hashcat** sobre la wordlist, **2,48 %**;
- **PassGPT**, el modelo publicado del paper, **1,03 %**;
- el **modelo de Markov del propio proyecto**, **0,57 %** — el peor de todos los que sirven
  para algo.

O sea: **en este presupuesto, enumerar mejor le gana a samplear mejor.** La razón es
estructural y conocida: un modelo por muestreo extrae de la distribución que aprendió, pero
**no ordena sus extracciones por probabilidad**. En los primeros 10⁶ intentos desperdicia
presupuesto en la cola de su propia distribución, mientras las máscaras recorren primero la
zona de mayor densidad (todos los números de 6 dígitos, todas las palabras del diccionario con
un sufijo numérico). El «desperdicio» de la tabla lo confirma por otro lado: las reglas gastan
26-27 % de su presupuesto en candidatos repetidos, y aun así ganan.

El resultado va **contra lo que el propio proyecto afirmaba**: se había presentado el modelo de
Markov como el cierre de la brecha de generación de candidatos. Medido, es la peor opción de la
tabla.

**La pregunta abierta, que no está medida:** la literatura reporta ventaja de los modelos
neuronales a presupuestos mucho mayores (10⁸-10¹⁰ intentos), donde la cobertura de la
distribución termina pagando. Acá se midió hasta 10⁶. **No se sabe si PassGPT da vuelta la
tabla a 10⁷ o 10⁸**, y afirmarlo sin medirlo sería exactamente el error que esta página existe
para corregir. Queda como el experimento pendiente, con su costo: 10⁷ intentos son ~80 minutos
de GPU, 10⁸ son ~13 horas.

## Lo que sí sale bien parado

- **`reglas:best64` con un 26,4 % de desperdicio** gasta un cuarto de su presupuesto repitiendo
  candidatos y aun así queda segundo. Deduplicar antes de atacar es una mejora gratis.
- **Las máscaras ganan con 0 % de desperdicio.** Enumerar sin repetir, en orden de probabilidad,
  es lo que más rinde por intento.
- La comparación es honesta: el conjunto de test es held-out de verdad, y por eso el
  `diccionario` saca exactamente 0 % — las contraseñas de test no están en train por
  construcción.

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
