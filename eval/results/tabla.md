### Todo el conjunto de test

Test: 20,000 contraseñas. Presupuesto: 1,000,000 intentos.

| generador | 100 intentos | 1,000 intentos | 10,000 intentos | 100,000 intentos | 1,000,000 intentos | desperdicio |
|---|---|---|---|---|---|---|
| `mascaras:rockyou` | 0.00% | 0.01% | 0.06% | 0.30% | 2.63% | 0.0% |
| `reglas:best64` | 0.00% | 0.01% | 0.06% | 0.34% | 2.15% | 26.4% |
| `reglas:dive` | 0.00% | 0.01% | 0.04% | 0.24% | 1.36% | 32.0% |
| `markov:orden2:ordenado` | 0.00% | 0.00% | 0.06% | 0.31% | 0.49% | 0.0% |
| `markov:orden2:muestreo` | 0.00% | 0.00% | 0.01% | 0.07% | 0.47% | 6.9% |
| `diccionario` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.0% |
