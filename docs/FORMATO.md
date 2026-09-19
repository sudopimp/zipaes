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

## 7. ZipCrypto no es AES

El cifrado tradicional de PKWARE (`ZipCrypto`) usa un PRNG propio, no AES. Se reconoce por
método 1 y bit de cifrado activo, **sin** extra field `0x9901`. Es mucho más débil, pero es
otro formato y otro hash: hashcat `--mode 17200`, John `$pkzip2$`.

`zipaes info` distingue los dos casos y te dice a qué modo ir.

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