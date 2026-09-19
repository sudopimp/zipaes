### Todo el conjunto de test

Test: 20,000 contraseñas. Presupuesto: 100,000 intentos.

| generador | 100 intentos | 1,000 intentos | 10,000 intentos | 100,000 intentos | desperdicio |
|---|---|---|---|---|---|
| `reglas:best64` | 0.04% | 0.42% | 3.23% | 14.79% | 15.0% |
| `reglas:dive` | 0.04% | 0.23% | 1.45% | 7.78% | 30.0% |
| `markov:orden2:ordenado` | 0.01% | 0.09% | 0.39% | 3.30% | 0.0% |
| `mascaras:rockyou` | 0.00% | 0.01% | 0.04% | 2.10% | 0.0% |
| `markov:orden2:muestreo` | 0.01% | 0.02% | 0.10% | 0.73% | 1.0% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |
