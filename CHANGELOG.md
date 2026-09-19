# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado según [SemVer](https://semver.org/lang/es/).

## [1.4.0] — 2026-09-19

Dos cosas: se aplica el arreglo del orden al modelo neuronal, y se corrige un sesgo del propio
protocolo de evaluación que la medición dejó al descubierto.

### Agregado

- **`generar_passgpt_ordenado`** — decodificado **ordenado** de PassGPT: el mismo recorrido
  mejor-primero que `MarkovModel.iter_ordenado`, pero con el transformer como puntuador. Los
  prefijos se evalúan en lotes para aprovechar la GPU, agrupados por largo (rellenar correría
  las posiciones de GPT-2, que usa embeddings absolutos aprendidos).
- **`--ventana-cabeza`** en el arnés: el test se muestrea de las N contraseñas más frecuentes
  en vez de uniformemente sobre todas las únicas. Cambia la pregunta que responde la evaluación,
  y resultó ser la correcta.

### Medido

Con el test realista (muestreado de las 100.000 contraseñas más usadas), a presupuesto bajo:

| generador | 10² | 10³ | 2×10³ |
|---|---|---|---|
| `passgpt:ordenado` | **0.075%** | **0.695%** | **1.145%** |
| `reglas:best64` | 0.04% | 0.42% | — |
| `reglas:dive` | 0.04% | 0.23% | — |
| `markov:ordenado` | 0.01% | 0.09% | — |
| `mascaras:rockyou` | 0.00% | 0.01% | — |

A 1.000 intentos el decodificado ordenado del modelo neuronal saca **1,65×** lo que el mejor
baseline, **7,7×** lo que el Markov ordenado y **70×** lo que las máscaras de hashcat. Su primer
acierto aparece en la posición 7. Es el mejor generador medido en el tramo de presupuesto bajo,
que es el régimen de un ataque dirigido.

A presupuesto alto sigue ganando la enumeración con wordlist: `best64` llega a 14,79 % a 10⁵ y
pasa al modelo neuronal en algún punto entre 10³ y 10⁴ intentos. Y el decodificado ordenado es
**caro**: ~11 candidatos por segundo contra ~1.700 del muestreo, así que sirve para miles de
intentos, no para millones.

### Corregido (protocolo)

- **El test uniforme sobre contraseñas únicas sesgaba la evaluación contra los modelos por
  probabilidad.** Al deduplicar, una contraseña que eligen un millón de personas cuenta igual
  que una que eligió una sola, así que la métrica premiaba cubrir la cola irrepetible en vez de
  acertar lo que la gente usa. Con el test de cabeza, el mismo `best64` pasa de 0,34 % a 14,79 %
  a 10⁵: **43×**, sólo por cambiar de dónde sale el test.
- Se detectó porque el decodificado neuronal daba 1 acierto en 2.000 intentos *mientras ponía
  primero contraseñas como `strawberry` y `basketball`*. Un resultado malo con candidatos
  buenísimos es señal de que la métrica está mal, no el generador.
- Las dos métricas se reportan por separado. No son intercambiables.

### Notas

- **La contaminación de PassGPT sigue ahí y está declarada**: fue entrenado sobre datos
  derivados de RockYou, el mismo corpus de evaluación, así que parte de su ventaja en este test
  puede ser memorizar en vez de generalizar. Con los pesos publicados y sin identificador de
  usuario en `rockyou.txt` no hay forma de eliminarla.

## [1.3.0] — 2026-09-19

Cierra el diagnóstico de la evaluación: el problema de los generadores por muestreo era **el
orden**, no el modelo. Se arregla eso y se mide cuánto vale.

### Agregado

- **`MarkovModel.iter_ordenado`** — enumeración por probabilidad decreciente con un recorrido
  mejor-primero sobre el árbol de prefijos. Un prefijo es cota superior de todos sus
  descendientes, así que sacar de la cola en orden de probabilidad garantiza que lo emitido
  sale en ese orden. Determinista, sin gasto en candidatos repetidos.
  En el CLI: `zipaes wordlist --ordenado --count N`.
- **`MarkovModel.distribucion`** — distribución del próximo carácter con interpolación tipo
  Jelinek-Mercer sobre contextos de largo decreciente, normalizada a 1.
- **`MarkovModel.logprobabilidad`** — puntuación de una contraseña completa; es la función que
  define el orden y la que usan los tests para verificarlo.

### Cambiado

- **El entrenamiento guarda contextos de todos los largos, no sólo del largo completo.** Sin
  los niveles cortos no hay retroceso, y sin retroceso la búsqueda ordenada se cortaba en seco
  justo donde más falta hacía una estimación aproximada.
- **Se agregó el piso del retroceso**: la frecuencia global de caracteres, para que ningún
  contexto quede sin respuesta. Va **derivada** y no serializada, así los modelos guardados con
  el formato anterior siguen cargando.
- `distribucion` memoiza por sufijo: la búsqueda revisita los mismos contextos miles de veces.

### Medido

Sobre el mismo test held-out de 20.000 contraseñas, contra la misma versión sampleando:

| presupuesto | muestreo | ordenado | mejora |
|---|---|---|---|
| 10.000 | 0.01% | 0.06% | **6x** |
| 100.000 | 0.07% | 0.31% | **4,4x** |
| 1.000.000 | 0.47% | 0.49% | 1,04x |

A 100.000 intentos el ordenado **supera a las máscaras de hashcat** (0,31 % contra 0,30 %) y a
10.000 empata con ellas y con `best64`. La ventaja se diluye al crecer el presupuesto: con
suficientes extracciones el muestreo termina sacando lo mismo, sólo que más tarde.

Costo: ~3.000-4.800 candidatos por segundo, 166 MB, **un núcleo de CPU y cero GPU**.

Sigue sin ser suficiente para llamarlo estado del arte: a 10⁶ las máscaras y las reglas de
hashcat encabezan la tabla, y PassGPT (0,86 %) sigue por delante de los dos Markov. El paso que
falta —aplicar el mismo orden a la distribución del modelo neuronal— queda documentado como la
tarea pendiente.

### Corregido

- **La interpolación de niveles dejaba masa sin repartir** (1 + (1-λ) + (1-λ)² … = 1/λ), así que
  las probabilidades sumaban 1,2. Ahora se normaliza.
- **La cota de largo máximo impedía cerrar la contraseña**: bloqueaba expandir en el largo tope,
  así que nunca se podía agregar el marcador de fin y la enumeración no emitía nada.
- **Un contexto sin ningún sufijo visto daba distribución vacía** y cortaba la rama. Resuelto
  con el piso de frecuencia global.

### Rendimiento (dos errores propios, encontrados al medir)

- La cola se podaba **en cada iteración** una vez saturada: un ordenamiento de 200.000
  elementos por candidato. Ahora se poda al duplicar el tope, no en cada inserción.
- Se expandían **los 214 caracteres** del vocabulario en cada paso; ahora sólo los `ramas` más
  probables (32), que no cambia lo que se emite primero.

## [1.2.0] — 2026-09-19

Cierra el círculo de ZipCrypto: ya no sólo se ataca en local, también se puede emitir el
hash que consumen las herramientas externas.

### Agregado

- **Emisión del hash `$pkzip2$`** (`emit_pkzip2`) para hashcat modo **17200** y John the
  Ripper. `zipaes hash` sobre un archivo ZipCrypto ahora emite, en vez de derivar a otra
  herramienta a mano.
- `modo_y_hash()` elige el modo y el formato según el tipo de entrada: 13600 con `$zip2$`
  para AES, 17200 con `$pkzip2$` para ZipCrypto. `hashcat_attack` y `john_attack` lo usan,
  así que los dos formatos funcionan por el mismo camino.

### Cambiado

- **La elección automática de backend prefiere el camino propio para ZipCrypto**, y está
  medido: en la misma máquina y la misma lista, el ataque propio hace ~36.700 candidatos
  por segundo contra ~10.900 del modo 17200 de hashcat. El kernel de hashcat descifra,
  descomprime y recalcula el CRC del archivo entero por cada candidato; el camino propio
  sólo descifra los 12 bytes de la cabecera. Pedir `--backend hashcat` explícitamente sigue
  funcionando.
- `recover()` acepta entradas ZipCrypto (antes asumía que toda entrada era AES).

### Notas de implementación

- El modo 17200 **sólo ataca entradas comprimidas con deflate**. Para las almacenadas (que
  es lo que produce `zip` cuando comprimir no ayuda) no hay kernel posible, así que la
  emisión falla con un mensaje explícito en vez de producir un hash que nunca va a romper.
  Es una limitación del formato `$pkzip2$`, no de esta implementación.
- El byte de control va en el **byte alto** de los campos de checksum: el kernel compara
  contra `checksum_from_crc >> 8` e `checksum_from_timestamp >> 8`. Ponerlo en el byte bajo
  —que es lo intuitivo— da un hash que hashcat acepta y nunca rompe. Se descubrió leyendo
  el kernel y se confirmó contra el vector de autoprueba de hashcat: con `crc32 = eda7a8de`
  el campo vale `eda7`, o sea `(crc >> 16) & 0xffff`.
- Los bloques de más de 320 KB no se pueden emitir: el kernel descomprime el bloque entero
  para validar el CRC, así que recortarlo lo volvería inútil. Se falla explícitamente.

### Pruebas

- Integración real con hashcat modo 17200: emite, ataca y confirma con el verificador
  propio. Sumado a los dos del modo 13600, hay tres tests que ejercitan hashcat de verdad.

## [1.1.1] — 2026-09-19

### Corregido

- **El ataque con hashcat podía reportar "no encontrada" con la contraseña ya en el
  potfile.** hashcat reescribe el campo del valor de verificación sin ceros a la izquierda
  al volcar el resultado (issue #4200 del propio hashcat), así que la comparación literal
  fallaba en aproximadamente uno de cada dieciséis hashes —justo los que tienen un `0`
  inicial en ese campo, que son dos bytes al azar. Ahora la comparación normaliza ese campo
  numéricamente. Se detectó porque el test de integración real era intermitente; la prueba
  ahora busca un salt que produzca ese caso, así que lo cubre siempre.
- `zip64_entries` en el informe: ZIP64 se detecta además por entrada, vía el extra field
  `0x0001`, no sólo por el localizador al final del archivo. `UnsupportedZipError` y
  `has_zip64_extra` se exportan.

### Interno

- `zipaes/_search.py`: la búsqueda paralela que compartían los dos motores de ataque estaba
  duplicada; ahora hay una sola implementación, con el umbral de paralelización como
  parámetro y el predicado declarado a nivel de módulo (lo que exige `multiprocessing`).

## [1.1.0] — 2026-09-19

Cierra las cuatro brechas identificadas en la revisión de 1.0.0: soporte de ZipCrypto,
backend de GPU, generación de candidatos con modelo y robustez del parser.

### Agregado

- **Soporte completo de ZipCrypto** (cifrado tradicional de PKWARE): derivación de claves,
  descifrado con avance de estado por la cabecera de cifrado, verificación concluyente por
  CRC, ataque de diccionario (sin derivación de claves, cientos de miles de candidatos por
  segundo) y extracción. Antes sólo se detectaba y se derivaba a hashcat.
- **Orquestación de backends externos** (`backend.py`): detección de hashcat y John the
  Ripper (PATH, variables `HASHCAT`/`JOHN`, globs y rutas habituales), ataque delegado,
  lectura de potfile y errores claros cuando faltan. `--backend auto|hashcat|john|python`.
- **Generación de candidatos** (`candidates.py`): mangleo estructural estilo PACK,
  composición estilo PRINCE y **modelo de Markov** entrenable sobre un corpus, con guardado
  y carga en JSON y generación reproducible por semilla.
- **Escritura de ZipCrypto** en el kit de pruebas, y fixtures reales generadas con Info-ZIP.
- **Fuzzing del parser**: mutaciones deterministas sobre los tres formatos, con invariantes
  verificados cuando el parseo tiene éxito.
- Comando `zipaes backend` y `--json` en todos los comandos.

### Cambiado

- `inspect()` ahora devuelve las entradas ZipCrypto parseadas, no sólo sus nombres.
- La elección automática de backend **no elige hashcat en AE-1**, por la limitación de 16
  bits del kernel del modo 13600.
- `_load_target` del CLI unifica AES y ZipCrypto: `info`, `verify`, `crack` y `extract`
  funcionan igual con los dos.
- El código de candidatos se centralizó en `candidates.py`; `crack.py` ya no duplica la
  lógica de mutaciones.

### Corregido

- **El parser confiaba en el `compressed size` declarado.** Un campo manipulado con 4 GB
  hacía que intentara leerlos. Ahora el tamaño se valida contra lo que queda del archivo.
- **`zipfile` puede levantar `NotImplementedError`** ante versiones de contenedor inválidas;
  `inspect()` lo traduce a `UnsupportedZipError` (un `ValueError`).
- **La detección de hashcat usaba `Path.home()`**, que lee `HOME` y falla en entornos donde
  está redefinido. Ahora el directorio personal se obtiene de la base de usuarios del
  sistema (`pwd`), y la búsqueda incluye globs.
- La actualización CRC-32 de ZipCrypto usa la tabla cruda de PKWARE y no `zlib.crc32`, que
  aplica el acondicionamiento del CRC estándar y produce claves distintas.
- El descifrado de ZipCrypto consume la cabecera de 12 bytes antes de los datos: sin eso la
  salida era basura aunque el chequeo de cabecera diera bien.

## [1.0.0] — 2026-09-19

Primera versión estable.

### Agregado

- **Parseo del formato AES de ZIP**: detección por extra field `0x9901`, soporte de AE-1 y
  AE-2, fuerzas AES-128/192/256, y clasificación de entradas ZipCrypto y sin cifrar.
- **Criptografía completa**: derivación PBKDF2-HMAC-SHA1 (1000 iteraciones), keystream
  AES-CTR con contador little-endian desde 1, verificación por valor de verificación y por
  código de autenticación HMAC-SHA1, y descifrado con descompresión según el método real.
- **Emisión del hash `$zip2$`** para hashcat (modo 13600) y John the Ripper, con validador
  de formato que respeta las restricciones del parser de hashcat.
- **Ataque de diccionario paralelo** con el verificador propio, con generación de mutaciones
  y construcción de listas dirigidas.
- **Extracción segura**: rechaza nombres de entrada que intenten escapar del directorio
  destino.
- **`selftest`**: autocomprobación de punta a punta contra un archivo de contraseña conocida,
  incluida la validación del formato del hash.
- **`testkit`**: escritor de zips AES para generar fixtures sin depender de herramientas
  externas.
- **CLI** con siete subcomandos, salida `--json` y códigos de salida estables.
- **98 pruebas** con pytest, incluidas pruebas de interoperabilidad bidireccional con 7-Zip.
- Documentación: metodología de recuperación, especificación del formato en detalle, uso
  responsable y preguntas frecuentes.

### Notas

- Soporte de AE-1 en el ataque por diccionario propio, con la limitación de hashcat
  documentada y advertida por el CLI.
- Fuera de alcance en esta versión: ZIP64, archivos multi-volumen, data descriptor y cifrado
  ZipCrypto (se detecta y se deriva a hashcat `--mode 17200`).

[1.0.0]: https://github.com/sudopimp/zipaes/releases/tag/v1.0.0