### Todo el conjunto de test

Test: 20,000 contraseñas. Presupuesto: 1,000,000 intentos.

| generador | 100 intentos | 1,000 intentos | 10,000 intentos | 100,000 intentos | 1,000,000 intentos | desperdicio |
|---|---|---|---|---|---|---|
| `mascaras:rockyou` | 0.00% | 0.01% | 0.06% | 0.30% | 2.63% | 0.0% |
| `reglas:best64` | 0.00% | 0.01% | 0.06% | 0.34% | 2.15% | 26.4% |
| `reglas:dive` | 0.00% | 0.01% | 0.04% | 0.26% | 1.76% | 27.4% |
| `passgpt` | 0.00% | 0.00% | 0.03% | 0.10% | 0.86% | 0.7% |
| `markov:orden2` | 0.00% | 0.00% | 0.01% | 0.07% | 0.47% | 6.9% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |

### Sólo contraseñas de hasta 10 caracteres (la comparación justa con PassGPT)

Test: 16,674 contraseñas con esa característica. Presupuesto: 1,000,000 intentos.

| generador | 100 intentos | 1,000 intentos | 10,000 intentos | 100,000 intentos | 1,000,000 intentos | desperdicio |
|---|---|---|---|---|---|---|
| `mascaras:rockyou` | 0.00% | 0.01% | 0.07% | 0.36% | 3.15% | 0.0% |
| `reglas:best64` | 0.00% | 0.01% | 0.07% | 0.40% | 2.48% | 26.4% |
| `reglas:dive` | 0.00% | 0.01% | 0.04% | 0.29% | 2.00% | 27.4% |
| `passgpt` | 0.00% | 0.00% | 0.03% | 0.11% | 1.03% | 0.7% |
| `markov:orden2` | 0.00% | 0.00% | 0.01% | 0.09% | 0.57% | 6.9% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |
