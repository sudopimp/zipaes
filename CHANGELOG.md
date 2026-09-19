# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado según [SemVer](https://semver.org/lang/es/).

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