# Preguntas frecuentes

### ¿Sirve para cualquier zip con contraseña?

No. Cubre el cifrado **AES** de WinZip (AE-1 y AE-2), que es el que produce 7-Zip con
`-mem=AES256`, WinZip y varias herramientas de backup. El cifrado tradicional de PKWARE
(**ZipCrypto**) es otro formato: `zipaes info` lo detecta y te indica que uses hashcat
`--mode 17200`.

### `unzip` me da "unsupported compression method 99". ¿Qué es eso?

Es la marca del cifrado AES. Info-ZIP no lo implementa, y la biblioteca estándar de Python
tampoco (`zipfile` levanta `RuntimeError: ... is encrypted`). Es justamente el caso que
motiva este proyecto.

### ¿Rompe el cifrado?

No. Prueba candidatos, igual que `hashcat` o `John the Ripper`. Si la contraseña es larga y
aleatoria, no hay herramienta que la recupere en un tiempo razonable. Lo que aporta `zipaes`
es el formato, la verificación concluyente y un flujo reproducible.

### Encontré la contraseña con hashcat. ¿Necesito verificar?

Sí, siempre. El filtro de hashcat compara el valor de verificación, que en AE-1 mide 1 byte:
uno de cada 256 falsos positivos lo supera. `zipaes verify` recalcula el código de
autenticación HMAC-SHA1 y da una respuesta concluyente.

### Hashcat no encuentra una contraseña que sé que está en el diccionario. ¿Por qué?

Probablemente el archivo sea **AE-1**. El kernel del modo 13600 compara el campo del `pv` a
16 bits, y AE-1 sólo guarda 1 byte de verificación, así que no puede satisfacer la
comparación. Usá `zipaes crack`, que no depende del largo del `pv`, o verificá los
candidatos sospechosos uno por uno con `zipaes verify`.

`zipaes hash archivo.zip --avisos` te avisa de esto cuando corresponde.

### ¿Por qué hay un `selftest`?

Porque un hash mal formado no falla visiblemente: simplemente no encuentra nada. El
`selftest` construye un archivo con contraseña conocida y recorre el flujo completo,
incluida la validación del formato del hash. Corrélo antes de atacar cualquier archivo real.

### ¿Cuánto tarda?

Depende del diccionario, no de la herramienta. Una lista dirigida de miles de candidatos:
segundos, en cualquier máquina. `rockyou` con reglas: minutos en una GPU modesta. Una
contraseña larga y aleatoria: no hay respuesta razonable.

### ¿Puedo usarlo para un archivo que no es mío?

No sin autorización. Leé [`ETICA-Y-LEGAL.md`](ETICA-Y-LEGAL.md). La herramienta no distingue
titularidad, y esa decisión es tuya y tu responsabilidad.

### ¿Soporta archivos de más de 4 GB o partidos en volúmenes?

No. Están fuera del alcance actual (ZIP64 y multi-volumen).

### ¿Y si el zip tiene entradas que no son AES?

Se procesan las AES y se informan las otras. Un archivo mixto se ataca por su parte AES.

### ¿Funciona en Windows y macOS?

El paquete es Python puro y multiplataforma. Las pruebas de interoperabilidad con 7-Zip se
omiten automáticamente si no está instalado.

### ¿Cómo colaboro?

Con *issues* que describan el escenario y cómo reproducirlo, y con *pull requests* que
incluyan tests. Para cambios de formato, agregá primero un caso de prueba que falle.