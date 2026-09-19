# Evaluación de generadores de candidatos

Esta página existe porque el proyecto afirmaba cosas sobre su generador de candidatos sin
ninguna medición detrás. Ahora está medido, el resultado cambió dos veces por lo que la propia
medición fue mostrando, y el estado final es este.

Lo corre [`eval/run_eval.py`](../eval/README.md). Reproducible: mismo corpus público, misma
semilla, mismo protocolo.

---

# El protocolo original estaba sesgado (y cómo se descubrió)

La primera corrida usaba un test **uniforme sobre contraseñas únicas**. Al medir el decodificado
ordenado del modelo neuronal contra ese test, el resultado fue malo: 1 acierto en 2.000
intentos. Malo *y sospechoso*, porque los candidatos que el modelo ponía primero eran cosas
como `strawberry`, `basketball`, `mypassword` — contraseñas evidentemente usadas por mucha
gente.

El problema era la métrica, no el generador. Deduplicando el corpus, una contraseña que eligen
un millón de personas cuenta **exactamente igual** que una que eligió una sola. Eso mide
"cuánto tarda en recuperar una contraseña única al azar", que castiga a los modelos por
probabilidad justo en aquello en lo que son buenos.

La pregunta de un ataque real es otra: **"cuánto tarda en recuperar la contraseña de una
persona al azar"**. Para eso el test tiene que muestrearse de las contraseñas que la gente
realmente usa. Eso es `--ventana-cabeza`: el test sale de las 100.000 contraseñas más
frecuentes en vez de uniformemente sobre las 14,3 millones.

Las dos métricas se reportan. No son intercambiables y responden a preguntas distintas.

---

# El resultado, protocolo realista

**rockyou.txt** · 14.339.984 únicas · train 14.319.984 / test 20.000 muestreado de las
100.000 más frecuentes, sin solapamiento exacto.

## Presupuesto bajo: donde se decide una recuperación real

| generador | 10² | 10³ | 10⁴ | 10⁵ | desperdicio |
|---|---|---|---|---|---|
| `reglas:best64` | 0.04% | 0.42% | 3.23% | **14.79%** | 15.0% |
| `reglas:dive` | 0.04% | 0.23% | 1.45% | 7.78% | 30.0% |
| `markov:ordenado` | 0.01% | 0.09% | 0.39% | 3.30% | 0.0% |
| `mascaras:rockyou` | 0.00% | 0.01% | 0.04% | 2.10% | 0.0% |
| `markov:muestreo` | 0.01% | 0.02% | 0.10% | 0.73% | 1.0% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |

## El decodificado ordenado del modelo neuronal, a presupuesto muy bajo

`passgpt:ordenado` **no samplea**: enumera la distribución del modelo en orden decreciente de
probabilidad. Sólo se midió hasta 2.000 intentos porque produce ~11 candidatos por segundo (el
árbol de prefijos de un transformer es enorme y pocos prefijos terminan).

| generador | 10² | 10³ | 2×10³ |
|---|---|---|---|
| **`passgpt:ordenado`** | **0.075%** | **0.695%** | **1.145%** |
| `reglas:best64` | 0.04% | 0.42% | — |
| `reglas:dive` | 0.04% | 0.23% | — |
| `markov:ordenado` | 0.01% | 0.09% | — |
| `mascaras:rockyou` | 0.00% | 0.01% | — |

Comparado en los puntos exactos que se midieron para todos:

- a **100 intentos** saca 0,075 % contra 0,04 % de `best64` (**1,9×**) y 0,00 % de las máscaras;
- a **1.000 intentos** saca 0,695 % contra 0,42 % de `best64` (**1,65×**), 0,09 % de
  `markov:ordenado` (**7,7×**) y 0,01 % de las máscaras (**70×**);
- su **primer acierto aparece en la posición 7**, y entre los 40 primeros hay contraseñas reales
  (`asdfghjkl`, `1234567890`, `snowwhite`, `billabong`, `snoopdogg`, `princess19`…).

Con 2.000 intentos llega a 1,145 %. `best64` necesita más de 1.000 y menos de 10.000 para
alcanzar ese valor, así que **la ventaja del decodificado neuronal se da en el tramo bajo,
hasta unos pocos miles de intentos**; a partir de ahí `best64` —con una wordlist de 14,3 millones
de palabras y 64 reglas— lo pasa.

Que es exactamente el régimen que importa cuando el objetivo es **una persona concreta** y no
una filtración entera: se prueba un puñado de miles de candidatos, no mil millones.

---

# El resultado con el protocolo anterior (uniforme), para comparar

Se conserva porque es la medición que destapó el sesgo y porque muestra qué cambia. Test de
20.000 contraseñas únicas al azar de las 14,3 millones.

| generador | 10⁴ | 10⁵ | 10⁶ | desperdicio |
|---|---|---|---|---|
| `mascaras:rockyou` | 0.06% | 0.30% | **2.63%** | 0.0% |
| `reglas:best64` | 0.06% | 0.34% | 2.15% | 26.4% |
| `reglas:dive` | 0.04% | 0.24% | 1.36% | 32.0% |
| `markov:ordenado` | 0.06% | 0.31% | 0.49% | 0.0% |
| `markov:muestreo` | 0.01% | 0.07% | 0.47% | 6.9% |
| `passgpt` (muestreo) | 0.03% | 0.10% | 0.86% | 0.7% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.0% |

Con este test las diferencias se aplanan (**0,3 % contra 14,8 %** a 10⁵ para `best64`) porque
casi todas las contraseñas del test son irrepetibles, y contra una contraseña irrepetible
ninguna estrategia puede hacer mucho.

## El arreglo del orden, medido en las dos métricas

El diagnóstico que dejó la primera corrida —los generadores por muestreo pierden **porque no
ordenan sus extracciones**— se confirmó en las dos, con la misma magnitud:

| presupuesto | `markov:muestreo` | `markov:ordenado` | mejora |
|---|---|---|---|
| 10.000 (realista) | 0.10% | 0.39% | **3,9x** |
| 100.000 (realista) | 0.73% | 3.30% | **4,5x** |
| 10.000 (uniforme) | 0.01% | 0.06% | **6x** |
| 100.000 (uniforme) | 0.07% | 0.31% | **4,4x** |

Y bajo el protocolo realista `markov:ordenado` **le gana a las máscaras de hashcat en todos los
puntos medidos** (a 10⁴ le saca 10×), que es la enumeración hecha a mano contra el modelo
aprendido.

---

# Qué dice esto, sin adornos

1. **En el tramo bajo —hasta unos pocos miles de intentos— el decodificado ordenado del modelo
   neuronal es el mejor generador medido, y por márgenes grandes** (1,65× al mejor baseline a
   1.000 intentos; 70× a las máscaras). Ese es el régimen de un ataque dirigido.
2. **A presupuestos altos manda la enumeración con wordlist**: `best64` con 14,3 millones de
   palabras y 64 reglas llega a 14,79 % a 10⁵ y pasa al modelo neuronal en algún punto entre
   10³ y 10⁴ intentos.
3. **El decodificado ordenado es caro de producir**: ~11 candidatos por segundo contra ~1.700
   del muestreo. Sirve para presupuestos de miles, no de millones. Las dos cosas son ciertas y
   hay que decir las dos.
4. **La métrica importa tanto como el generador.** El mismo `best64` da 0,34 % o 14,79 % a 10⁵
   según de dónde salga el test. Publicar un número sin decir la métrica no dice nada.

## La advertencia que no hay que saltear

**PassGPT fue entrenado sobre datos derivados de RockYou**, el mismo corpus con el que se
evalúa. Su partición de test puede estar parcialmente memorizada, y sus números pueden estar
inflados por eso. No hay partición por usuario posible (`rockyou.txt` no trae identificador), y
la contaminación es inevitable con los pesos publicados. **El resultado está presentado con esa
salvedad, no a pesar de ella**: una parte de lo que el modelo hace bien en este test puede ser
recordar en vez de generalizar.

## Lo que sí sale bien parado

- **Las máscaras con 0 % de desperdicio** siguen siendo muy eficientes por intento en el
  régimen de presupuesto alto.
- `reglas:best64` gasta un 15-26 % de su presupuesto repitiendo candidatos y aun así gana a
  presupuesto alto: deduplicar antes de atacar es una mejora gratis que quedó sin hacer.
- El `diccionario` saca 0 % en las dos métricas: el test es held-out de verdad.

## Limitaciones (afectan la lectura de los números)

1. **La partición no es por usuario.** `rockyou.txt` no trae identificador de usuario, así que
   no se puede separar por persona. Particionar al azar deja pasar variantes morfológicas entre
   train y test.
2. **Contaminación de PassGPT**, descrita arriba.
3. **`passgpt:ordenado` se midió hasta 2.000 intentos**, por su costo. Los demás, hasta 10⁵-10⁶.
4. **Los valores absolutos dependen de la métrica** y hay que leerlos siempre con la ventana de
   muestreo del test al lado.

## Cómo reproducirlo

```bash
# protocolo realista (el principal)
python eval/run_eval.py --presupuesto 100000 --test-size 20000 --ventana-cabeza 100000 \
    --salida eval/results-cabeza

# protocolo uniforme (el que destapó el sesgo)
python eval/run_eval.py --presupuesto 1000000 --test-size 20000 --salida eval/results

# el decodificado neuronal ordenado (necesita el extra [eval] y GPU)
python eval/run_eval.py --passgpt --presupuesto 2000 --ventana-cabeza 100000
```

Los crudos quedan en `eval/results*/resultados.json` y las tablas en `tabla.md`. Dentro de una
corrida el medidor conserva la posición exacta de cada acierto, que es lo que permite derivar
curvas de subconjuntos sin volver a correr nada; esas posiciones no se persisten en el JSON para
no volcar al repositorio las contraseñas del corpus.
