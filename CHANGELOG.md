# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado según [SemVer](https://semver.org/lang/es/).

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