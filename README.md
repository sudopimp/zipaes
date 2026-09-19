<div align="center">

# zipaes

**Auditoría, recuperación y extracción de archivos ZIP con cifrado AES (WinZip AE-1 / AE-2).**

Lo que `unzip` y la biblioteca estándar de Python **no** pueden abrir.

[![CI](https://github.com/sudopimp/zipaes/actions/workflows/ci.yml/badge.svg)](https://github.com/sudopimp/zipaes/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Licencia](https://img.shields.io/badge/licencia-MIT-green)
![Tests](https://img.shields.io/badge/tests-98-brightgreen)

</div>

---

## El problema

Un zip con cifrado AES (el que produce WinZip, 7-Zip con `-mem=AES256`, WinRAR y varias
herramientas más) es un archivo que buena parte del ecosistema simplemente no sabe leer:

```console
$ unzip importante.zip
skipping: documentos/nota.txt  unsupported compression method 99
```

```python
>>> import zipfile
>>> zipfile.ZipFile("importante.zip").testzip()
RuntimeError: File 'documentos/nota.txt' is encrypted, password required for extraction
```

El **método 99** es la marca del cifrado AES, y ni Info-ZIP ni `zipfile` lo implementan.
7-Zip sí puede extraerlo, pero no te da lo que hace falta para *recuperar* la contraseña
cuando no la tenés: el hash para las herramientas de cracking, una verificación
concluyente, ni un flujo reproducible.

Eso es lo que cubre `zipaes`.

---

## Qué hace

| Comando | Para qué |
|---|---|
| `zipaes info` | Panorama del archivo: cuántas entradas, con qué cifrado, y los campos AES de cada una |
| `zipaes verify` | Comprueba una contraseña de forma **concluyente** (recalcula el código de autenticación) |
| `zipaes hash` | Emite el hash `$zip2$` para **hashcat** (modo 13600) o **John the Ripper** |
| `zipaes crack` | Ataque de diccionario en paralelo con el verificador propio |
| `zipaes extract` | Descifra y extrae el contenido una vez que tenés la contraseña |
| `zipaes wordlist` | Genera listas de candidatos (mayúsculas, capitalización, sufijos, años) |
| `zipaes selftest` | Se autocomprueba de punta a punta contra un archivo de contraseña conocida |

Todos aceptan `--json`.

---

## Instalación

```bash
git clone https://github.com/sudopimp/zipaes
cd zipaes
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

La única dependencia es `cryptography`. Nada más.

---

## Autocomprobación

Antes de tocar cualquier archivo real, comprobá que el flujo funciona en tu máquina:

```console
$ zipaes selftest
autocomprobacion: OK
  variante   : AE-2 / AES-256 / store
  [ok  ] crear zip AES de prueba  (prueba.zip)
  [ok  ] detectar entradas AES  (2 de 2)
  [ok  ] leer salt y verificacion  (AE-2, salt de 16 bytes)
  [ok  ] aceptar la clave correcta
  [ok  ] rechazar una clave incorrecta
  [ok  ] formato $zip2$ valido para hashcat
  [ok  ] recuperar por diccionario  (contrasena-de-prueba)
  [ok  ] extraer con la clave  (2 archivos en 0.009s)
  [ok  ] el contenido coincide byte a byte
```

Probá también las otras variantes: `zipaes selftest --ae1`, `--fuerza 1`, `--deflate`.

---

## Uso paso a paso

### 1. Mirar qué hay adentro

```console
$ zipaes info importante.zip
archivo: importante.zip
entradas: 2
aes: 2
zipcrypto: 0
sin_cifrar: 0
primera_entrada_aes: documentos/nota.txt
detalle:
  - nombre=documentos/nota.txt, formato=AE-2, fuerza=AES-256,
    salt=f781667b0d30116f6f3bbcf27b3a15e1, verificacion_clave=77f0,
    auth_code=fdd67ae8744acdb6ec39, comprimido=32, sin_comprimir=4, metodo_real=0
```

Si el archivo usara cifrado tradicional (**ZipCrypto**), el comando lo dice y te manda al
modo correcto de hashcat en lugar de dejarte probando al azar.

### 2. Emitir el hash y atacar por GPU

```console
$ zipaes hash importante.zip
importante.zip:$zip2$*0*3*0*f781667b0d30116f6f3bbcf27b3a15e1*77f0*4*7da59a4d*fdd67ae8744acdb6ec39*$/zip2$
```

```bash
hashcat -m 13600 hash.txt rockyou.txt -r rules/best64.rule
```

### 3. Confirmar el resultado

Un candidato de hashcat **no es prueba suficiente**. Confirmalo con la verificación real:

```console
$ zipaes verify importante.zip -p la-clave-encontrada
archivo: importante.zip
entrada: documentos/nota.txt
valida: si

$ zipaes verify importante.zip -p una-clave-cualquiera
valida: no
```

Código de salida `0` si la contraseña es correcta, `2` si no.

### 4. Extraer

```console
$ zipaes extract importante.zip -p la-clave-encontrada -o salida/
extraidos: 2
fallidos: 0
omitidos: 0
```

### Sin GPU (diccionario propio)

```console
$ zipaes crack importante.zip --palabras alfa beta mi-clave
entrada: documentos/nota.txt
encontrada: si
password: mi-clave
```

Con `--mutaciones` prueba variantes de cada palabra; con `-w lista.txt` usa un diccionario;
con `-j N` fija la cantidad de procesos.

---

## Cómo funciona

El cifrado AES de WinZip se define en el APPNOTE de PKWARE y en la especificación pública
de WinZip. En resumen:

```
DK         = PBKDF2-HMAC-SHA1(contraseña, salt, 1000 iteraciones, 2*clave + pv)
clave_aes  = DK[0 : clave]
clave_mac  = DK[clave : 2*clave]
pv         = DK[2*clave : 2*clave + pv]        # valor de verificación de clave

ciphertext = AES-CTR(clave_aes, datos)         # contador little-endian, arranca en 1
auth_code  = HMAC-SHA1(clave_mac, ciphertext)[:10]
```

En el archivo, cada entrada queda guardada así:

```
[salt: 8/12/16 bytes][pv: 1 o 2 bytes][ciphertext][auth_code: 10 bytes]
```

Tres detalles que suelen arruinar implementaciones:

1. **El `pv` no alcanza como verificación.** En AE-1 mide **1 byte**: uno de cada 256
   candidatos falsos lo supera por azar. La prueba real es recalcular el `auth_code`.
   `zipaes verify` hace siempre las dos cosas.
2. **El contador del CTR es little-endian.** No sirve el modo CTR estándar de las
   bibliotecas criptográficas, que usa un contador big-endian sobre los 128 bits. Hay que
   construir el keystream bloque a bloque.
3. **El salt no siempre mide 16 bytes.** Mide `4 + 4*fuerza`: 8 (AES-128), 12 (AES-192),
   16 (AES-256). Asumir 16 es un error silencioso que sólo aparece con AES-128/192.

Todo esto está implementado y cubierto por tests en `zipaes/format.py` y
`zipaes/crypto.py`. El detalle completo, en [`docs/FORMATO.md`](docs/FORMATO.md).

---

## El flujo recomendado de recuperación

```
1. zipaes info archivo.zip          # ¿es AES? ¿qué variante y fuerza?
2. zipaes selftest                  # ¿el flujo funciona en esta máquina?
3. zipaes hash archivo.zip          # hash -> hashcat -m 13600 / john
4. zipaes verify archivo.zip -p ... # confirmar el candidato (concluyente)
5. zipaes extract archivo.zip -p ... -o salida/
```

**El paso 2 no es ceremonia.** Un hash mal formado no falla de forma visible: simplemente
no encuentra nada, y podés dejar la GPU trabajando horas contra un problema imposible.
Validar el emisor contra un archivo de contraseña conocida *antes* de atacar es la
diferencia entre una tarde y una semana. En
[`docs/METODOLOGIA.md`](docs/METODOLOGIA.md) está el razonamiento completo.

---

## Límites conocidos

- **AE-1 y hashcat.** El campo del `pv` en el hash `$zip2$` se compara a 16 bits en el
  kernel de hashcat (modo 13600). Un archivo AE-1 guarda un solo byte de verificación, así
  que **el ataque por GPU puede no encontrarlo**. Para AE-1 usá `zipaes crack`, que no
  depende del largo del `pv`. `zipaes hash --avisos` te lo recuerda.
- **ZipCrypto (cifrado tradicional) no está soportado.** No es AES: usá hashcat
  `--mode 17200`. El CLI te lo indica.
- **Sin ZIP64, sin multi-volumen, sin data descriptor.** Cubre el caso habitual; los
  archivos >4 GB o partidos en volúmenes quedan fuera.
- **No hace fuerza bruta.** No adivina: prueba candidatos que le des, o delega el trabajo
  pesado a hashcat/John y confirma el resultado.
- **No rompe el cifrado.** AES-256 con una contraseña fuerte sigue siendo AES-256 con una
  contraseña fuerte. Lo que este proyecto aporta es formato, verificación y flujo.

---

## Uso responsable

> `zipaes` es una herramienta de **recuperación**, pensada para archivos **tuyos** o sobre
> los que tengas **autorización explícita y por escrito** del titular.
>
> Usarla contra archivos de terceros sin autorización puede constituir un delito en tu
> jurisdicción, con independencia de si la contraseña se recupera o no.
>
> No elude ningún control de acceso: no explota vulnerabilidades ni debilita el cifrado.
> Verifica candidatos que vos aportás, exactamente igual que `hashcat` o `John the Ripper`.
>
> Los autores no se responsabilizan del uso indebido. Si tu caso es un equipo de una
> empresa, un peritaje o una sucesión, dejá constancia de la autorización antes de empezar.

Leé [`docs/ETICA-Y-LEGAL.md`](docs/ETICA-Y-LEGAL.md) para el detalle.

---

## Estructura

```
zipaes/
  format.py     parseo del contenedor ZIP y de las entradas AES
  crypto.py     derivación de claves, keystream, verificación, descifrado
  hashfmt.py    emisión del hash $zip2$ para hashcat / John
  crack.py      ataque de diccionario en paralelo y generación de candidatos
  extract.py    extracción segura (sin escapes de ruta)
  selftest.py   autocomprobación de punta a punta
  testkit.py    escritor de zips AES para fixtures de prueba
  cli.py        interfaz de línea de comandos
tests/          98 pruebas con pytest, incluidas las de interoperabilidad con 7-Zip
docs/           metodología, formato, ética y preguntas frecuentes
```

## Calidad

```bash
make check    # ruff check + ruff format --check + pytest
```

- **98 tests**, todos en verde, sin red ni servicios externos.
- Las pruebas de interoperabilidad **crean archivos con 7-Zip y los abren con este
  paquete**, y al revés: si 7-Zip acepta lo que escribimos, el formato está bien construido.
- `ruff` limpio.
- CI en Python 3.11, 3.12 y 3.13.

## Documentación

- [Metodología de recuperación](docs/METODOLOGIA.md) — el orden correcto y por qué
- [El formato AES de ZIP, en detalle](docs/FORMATO.md) — especificación, `$zip2$`, trampas
- [Ética y marco legal](docs/ETICA-Y-LEGAL.md) — uso aceptable
- [Preguntas frecuentes](docs/FAQ.md)

## Licencia

MIT. Ver [`LICENSE`](LICENSE).

## Agradecimientos

A los proyectos que hacen el trabajo pesado cuando la contraseña resiste:
[hashcat](https://hashcat.net/hashcat/), [John the Ripper](https://www.openwall.com/john/)
y [7-Zip](https://www.7-zip.org/). El formato está documentado en el APPNOTE de PKWARE y
en la [especificación AES de WinZip](https://www.winzip.com/en/support/aes-encryption/).