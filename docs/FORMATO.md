# El cifrado AES de ZIP, en detalle

Documento de referencia del formato tal como lo implementan WinZip, 7-Zip y otras
herramientas, y de cómo se traduce al hash que consumen las herramientas de cracking.

Fuentes: APPNOTE de PKWARE 6.3.x §4.4.4, la especificación AES pública de WinZip, y el
parser del modo 13600 de hashcat (`module_13600.c`).

---

## 1. Cómo se marca una entrada cifrada con AES

Dentro del contenedor ZIP, una entrada AES se reconoce por tres cosas:

| Dónde | Qué |
|---|---|
| Cabecera local y central | `compression method = 99` |
| Cabecera local y central | bit 0 de los flags en 1 (cifrado) |
| Extra field `0x9901` | versión de vendor, identificador `AE`, fuerza, método real |

El extra field `0x9901` en su forma estándar:

```
offset  tamaño  campo
0       2       versión de vendor: 1 = AE-1, 2 = AE-2
2       2       identificador del vendor: "AE"
4       1       fuerza: 1 = AES-128, 2 = AES-192, 3 = AES-256
5       2       método de compresión real (0 = store, 8 = deflate)
```

Como el método declarado en la cabecera es 99 (AES), el método **real** sólo se conoce por
este campo. Si lo ignorás, no sabés si tenés que inflar el resultado o no.

---

## 2. AE-1 contra AE-2

| | AE-1 | AE-2 |
|---|---|---|
| Valor de verificación de clave | **1 byte** | **2 bytes** |
| CRC en la cabecera | CRC real del archivo | **cero** |
| Uso | más viejo, todavía frecuente | el más común hoy |

7-Zip escribe AE-2. WinZip y varias herramientas siguen escribiendo AE-1.

La diferencia de 1 byte de verificación parece cosmética y no lo es: es la causa de que
muchos ataques por GPU fallen silenciosamente (§5).

---

## 3. Disposición de los datos cifrados

Justo después del nombre y los extra fields, en la cabecera local:

```
[ salt ][ pv ][ ciphertext ][ auth_code ]
   4+4*f   1|2      n             10
```

El tamaño del `salt` depende de la fuerza:

| Fuerza | Bits | salt | Clave derivada |
|---|---|---|---|
| 1 | AES-128 | 8 bytes | 16 bytes |
| 2 | AES-192 | 12 bytes | 24 bytes |
| 3 | AES-256 | 16 bytes | 32 bytes |

**El error clásico es asumir 16 bytes siempre.** Funciona en todo lo que sea AES-256 (lo más
habitual), y rompe en silencio con AES-128 y AES-192.

El `compressed size` de la cabecera incluye `salt + pv + ciphertext + auth_code`, no sólo el
ciphertext. Otra fuente habitual de off-by-N.

---

## 4. Derivación de claves y cifrado

```
DK        = PBKDF2-HMAC-SHA1(contraseña, salt, 1000 iteraciones, 2*clave + pv)
clave_aes = DK[0 : clave]
clave_mac = DK[clave : 2*clave]
pv        = DK[2*clave : 2*clave + pv]
```

Las 1000 iteraciones son **fijas** en la especificación: no hay parámetro que las cambie.
Eso hace que el algoritmo sea barato y explica por qué la GPU es tan eficaz acá.

Cifrado:

```
ciphertext = AES-CTR(clave_aes, texto plano comprimido)
```

El contador de WinZip AES tiene dos particularidades:

- es de **128 bits little-endian**;
- **arranca en 1**, no en 0.

Es decir que el primer bloque del keystream es `AES-ECB(clave, 01 00 ... 00)` y el segundo
`AES-ECB(clave, 02 00 ... 00)`. El modo CTR estándar de las bibliotecas criptográficas usa
un contador big-endian sobre el valor completo, así que **no sirve** para esto: hay que
construir el keystream bloque a bloque.

Autenticación:

```
auth_code = HMAC-SHA1(clave_mac, ciphertext)[:10]
```

Diez bytes, calculados sobre el **ciphertext**, no sobre el texto plano.

---

## 5. Verificación: por qué el `pv` no alcanza

El `pv` se guarda en claro, así que compararlo es inmediato y sirve para descartar
candidatos rápido. Pero **no es una prueba de que la contraseña sea correcta**:

- con AE-2 son 16 bits → 1 de cada 65.536 falsos positivos pasa el filtro;
- con AE-1 es **1 byte** → 1 de cada **256** falsos positivos pasa el filtro.

La única verificación concluyente es recalcular el `auth_code` sobre el ciphertext y
compararlo (80 bits de contraste). Eso es lo que hace `zipaes verify` siempre, y por eso es
seguro usarlo para confirmar lo que reportó hashcat.

---

## 6. El hash `$zip2$`

Formato que consumen John the Ripper (jumbo) y hashcat modo 13600:

```
$zip2$*0*<fuerza>*0*<salt>*<pv>*<largo_ct>*<ciphertext>*<auth_code>*$/zip2$
```

| Posición | Campo | Contenido |
|---|---|---|
| 0 | literal | `$zip2$` |
| 1 | tipo | fijo `0` |
| 2 | fuerza | `1`, `2` o `3` (define el largo esperado del salt) |
| 3 | magic | fijo `0` |
| 4 | salt | hex, 16/24/32 caracteres según la fuerza |
| 5 | pv | hex, 2 caracteres en AE-1 y 4 en AE-2 |
| 6 | largo del ciphertext | hex, sin `0x` |
| 7 | ciphertext | hex |
| 8 | auth_code | hex, exactamente 20 caracteres |
| 9 | literal | `$/zip2$` |

Restricciones que impone el parser de hashcat, y que hay que respetar o el hash no carga:

- son **10 campos** exactos separados por `*`;
- el largo del salt debe ser exactamente `8 * (fuerza + 1)` caracteres hex: 16, 24 y 32 para
  fuerza 1, 2 y 3;
- el `auth_code` debe tener exactamente 20 caracteres hex.

Un hash que no cumple esto no da error: hashcat lo rechaza o lo carga mal y el ataque no
encuentra nada. De ahí la insistencia en validar el emisor con `zipaes selftest`.

### La limitación de AE-1 en hashcat

El kernel compara el campo 5 a **16 bits**:

```c
if (mode == 3) if (MATCHES_NONE_VS ((out[1] >> 16), verify_bytes)) break;
```

Con AE-2 el campo tiene 2 bytes y la comparación es exacta. Con AE-1 el campo tiene 1 byte:
la comparación de 16 bits no se puede satisfacer con ese dato, y **el ataque puede no
encontrar una contraseña que sí está en el diccionario**.

Para AE-1: usar el verificador propio (`zipaes crack`), que no depende del largo del `pv`.

Nota sobre variantes de estilo: la convención de `zip2john` es emitir siempre 2 bytes de
`pv`, leyendo un byte de más cuando el archivo es AE-1. Eso desplaza el ciphertext y puede
producir un hash que no valida. Ante la duda, comparar contra la verificación propia.

---

## 7. ZipCrypto: el cifrado tradicional

El cifrado clásico de PKWARE (`ZipCrypto`) no tiene nada que ver con AES. Se reconoce por
método 1 y bit de cifrado activo, **sin** extra field `0x9901`.

### Cómo funciona

Tres claves de 32 bits que evolucionan con cada byte:

```
key0 = 0x12345678, key1 = 0x23456789, key2 = 0x34567890

update(byte):
    key0 = crc32_crudo(key0, byte)
    key1 = (key1 + (key0 & 0xff)) * 134775813 + 1        (mod 2^32)
    key2 = crc32_crudo(key2, byte alto de key1)

keystream_byte():
    temp = (key2 | 2) & 0xffff
    return ((temp * (temp ^ 1)) >> 8) & 0xff
```

Dos detalles que rompen implementaciones:

1. **`crc32_crudo` no es `zlib.crc32`.** La actualización de PKWARE es
   `(crc >> 8) ^ tabla[(crc ^ byte) & 0xff]`, sin el acondicionamiento previo y posterior
   del CRC estándar. `zlib.crc32(un_byte, anterior)` da otro valor y produce claves
   distintas: hay que construir la tabla explícitamente.
2. **El estado avanza con la cabecera.** El archivo arranca con 12 bytes de cabecera de
   cifrado. Hay que consumirlos (descifrarlos) para avanzar las claves **antes** de
   descifrar los datos. Si se empieza de cero en los datos, la salida es basura aunque el
   chequeo de la cabecera dé bien.

### Estructura

```
[cabecera de cifrado: 12 bytes][datos cifrados]
```

El último byte de la cabecera (en claro) es el valor de control:

| Bit 3 de los flags | Byte esperado |
|---|---|
| 0 (normal) | byte alto del CRC |
| 1 (data descriptor) | byte alto de la hora DOS |

### Verificación

El valor de control es **1 byte**: deja pasar uno de cada 256 candidatos falsos. La
verificación concluyente es descifrar el contenido, descomprimirlo y comparar el CRC-32.
Eso es lo que hace `zipaes verify`.

### Data descriptor

Cuando el bit 3 está activo, la cabecera local deja los tamaños en cero y los pone un
registro *después* de los datos. La consecuencia práctica es que **los tamaños hay que
tomarlos del directorio central**, no de la cabecera local. Info-ZIP usa este modo por
defecto, así que no es un caso raro.

### Qué NO es

No es AES, así que el hash `$zip2$` no aplica y el ataque va por otro lado. Como no hay
derivación de claves, probarlo es muchísimo más barato — en la práctica el backend propio
alcanza y sobra para este formato.

### El hash `$pkzip2$` (modo 17200 de hashcat)

`zipaes hash` emite el formato que consumen hashcat (modo 17200) y John the Ripper:

```
$pkzip2$1*1*2*0*5f*2261*9aa527f8*0*0*8*5f*9aa5*7e86*<datos>*$/pkzip2$
         │ │ │ │  │    │       │  │ │  │   │     │
         │ │ │ │  │    │       │  │ │  │   │     └─ datos: cabecera de cifrado + contenido
         │ │ │ │  │    │       │  │ │  │   └─────── checksum de la hora DOS (16 bits)
         │ │ │ │  │    │       │  │ │  └─────────── checksum del CRC (16 bits)
         │ │ │ │  │    │       │  │ └────────────── largo de los datos
         │ │ │ │  │    │       │  └──────────────── compresión: 8 = deflate (obligatorio)
         │ │ │ │  │    │       └─────────────────── offset extra
         │ │ │ │  │    └─────────────────────────── offset
         │ │ │ │  └──────────────────────────────── crc32
         │ │ │ └─────────────────────────────────── largo sin comprimir
         │ │ └───────────────────────────────────── largo comprimido
         │ └─────────────────────────────────────── tipo de magic
         └───────────────────────────────────────── tipo de datos
```

Tres cosas que cuestan descubrir:

1. **El byte de control va desplazado.** El kernel compara contra
   `checksum_from_crc >> 8`, así que el valor es la parte alta del CRC de 32 bits:
   `(crc >> 16) & 0xffff`. Poner el byte de control en el byte bajo —que es lo natural— da
   un hash que hashcat **acepta y nunca rompe**. Con `crc32 = eda7a8de` el campo vale
   `eda7`, que es exactamente lo que trae el vector de autoprueba de hashcat.
2. **La compresión tiene que ser deflate.** El parser rechaza cualquier otra cosa
   (`PARSER_PKZIP_CT_UNMATCHED`), y no existe kernel para las entradas almacenadas.
3. **Los datos no se pueden recortar.** El kernel descifra y descomprime el bloque entero
   para validar el CRC del archivo, así que un bloque incompleto produce un hash inútil.
   Hay un tope de 320 KB en el kernel, y por encima de eso no hay nada que emitir.

---

## 8. Resumen de errores frecuentes

| Error | Consecuencia |
|---|---|
| Asumir salt de 16 bytes | rompe AES-128/192 |
| Usar el CTR big-endian de la biblioteca | salida basura, verificación imposible |
| Contador arrancando en 0 | ídem |
| Calcular el HMAC sobre el texto plano | auth_code nunca coincide |
| Confiar en el `pv` como prueba | falsos positivos (1/256 en AE-1) |
| Ignorar el método real del extra field | texto plano comprimido ilegible |
| No descontar salt+pv+auth del `compressed size` | off-by-N al leer el ciphertext |
| No distinguir AE-1 de AE-2 | hash inválido en la mitad de los casos |