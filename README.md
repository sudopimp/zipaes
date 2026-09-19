<div align="center">

# zipaes

**Auditoría, recuperación y extracción de archivos ZIP cifrados.**

AES (WinZip AE-1 / AE-2) y ZipCrypto, con hashcat y John the Ripper integrados.

[![CI](https://github.com/sudopimp/zipaes/actions/workflows/ci.yml/badge.svg)](https://github.com/sudopimp/zipaes/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Licencia](https://img.shields.io/badge/licencia-MIT-green)
![Tests](https://img.shields.io/badge/tests-216-brightgreen)

</div>

---

## El problema

Un zip cifrado es un archivo que buena parte del ecosistema no sabe leer:

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
Y cuando la contraseña se perdió, 7-Zip puede extraer pero no te da lo que hace falta para
*recuperarla*: el hash para las herramientas de cracking, una verificación concluyente y
un flujo reproducible.

Eso es lo que cubre `zipaes`.

---

## Qué hace

| Comando | Para qué |
|---|---|
| `zipaes info` | Panorama del archivo: tipo de cifrado, entradas, campos AES, ZIP64 |
| `zipaes verify` | Comprueba una contraseña de forma **concluyente** (auth code en AES, CRC en ZipCrypto) |
| `zipaes hash` | Emite el hash para **hashcat** o **John**: `$zip2$` (modo 13600) en AES, `$pkzip2$` (modo 17200) en ZipCrypto |
| `zipaes crack` | Ataque de diccionario, en local o **delegando en hashcat/John** |
| `zipaes extract` | Descifra y extrae el contenido (AES y ZipCrypto) |
| `zipaes wordlist` | Genera candidatos: mangleo tipo PACK, composición y **modelo de Markov** |
| `zipaes backend` | Muestra las herramientas externas detectadas y sus versiones |
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

La única dependencia obligatoria es `cryptography`. `hashcat` y `john` son opcionales y se
detectan solos (PATH, variable `HASHCAT`/`JOHN`, o ubicaciones habituales).

---

## Autocomprobación

Antes de tocar cualquier archivo real:

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
zip64: no
tipo: AES
detalle:
  - nombre=documentos/nota.txt, formato=AE-2, fuerza=AES-256,
    salt=f781667b0d30116f6f3bbcf27b3a15e1, verificacion_clave=77f0,
    auth_code=fdd67ae8744acdb6ec39, comprimido=32, sin_comprimir=4, metodo_real=0
```

### 2. Atacar

**Con GPU** (recomendado en cualquier caso serio):

```bash
zipaes hash importante.zip > hash.txt
hashcat -m 13600 hash.txt diccionario.txt -r rules/best64.rule
```

O dejando que `zipaes` orqueste hashcat por vos:

```bash
zipaes crack importante.zip -w diccionario.txt --backend hashcat
```

Sin GPU, con el verificador propio:

```bash
zipaes crack importante.zip -w diccionario.txt -j 8 --backend python
```

Con `--backend auto` (por defecto) se elige hashcat si está disponible — **salvo en AE-1**,
donde el kernel de hashcat no es fiable por una limitación de 16 bits que se explica más
abajo. En ese caso, y con hashcat ausente, cae al verificador propio.

### 3. Confirmar

```console
$ zipaes verify importante.zip -p la-clave-encontrada
tipo: AES
valida: si

$ zipaes verify importante.zip -p una-clave-cualquiera
valida: no
```

Código de salida `0` si la contraseña es correcta, `2` si no. **No te saltees este paso**:
lo que reporta hashcat se confirma acá.

### 4. Extraer

```console
$ zipaes extract importante.zip -p la-clave-encontrada -o salida/
extraidos: 2
fallidos: 0
omitidos: 0
```

---

## Candidatos: la parte que decide el resultado

El formato correcto no recupera contraseñas; el **diccionario** sí. `zipaes wordlist`
combina tres estrategias, de más barata a más cara:

```bash
# 1. dirigida: mangleo PACK de palabras del contexto + composición entre ellas
zipaes wordlist -o lista.txt juan perez 2025

# 2. con modelo de Markov entrenado sobre un corpus propio
zipaes wordlist -o lista.txt --train rockyou.txt --save-model modelo.json --count 200000

# 3. reutilizando un modelo ya entrenado (entrenar una vez, usar mil)
zipaes wordlist -o lista.txt --model modelo.json --count 500000 --seed 42
```

| Estrategia | Qué hace |
|---|---|
| **Mangleo (PACK)** | mayúsculas, leet, inversión, duplicación, sufijos, años, prefijos |
| **Composición (PRINCE)** | `juan` + `perez` → `juanperez`, `perez_juan`, `juan2025`… |
| **Modelo de Markov** | aprende la distribución de caracteres de un corpus y samplea candidatos nuevos |
| **Modelo ordenado** | ídem, pero enumera por probabilidad **decreciente** en vez de samplear |

El modo `--ordenado` es el que más rinde a presupuesto bajo, y la diferencia está medida: con
10.000 intentos saca **6×** más contraseñas que samplear, y con 100.000 **4,4×** — alcanzando a
las máscaras de hashcat. Es determinista y no gasta presupuesto en candidatos repetidos.

```bash
zipaes wordlist -o ordenada.txt --train rockyou.txt --count 1000000 --ordenado
```

El modelo es la misma idea que `hcstat` de hashcat y que los modelos de n-gramas de la
literatura de adivinación: la contraseña tiene estructura, y esa estructura se puede
aprender. Se entrena una vez y se guarda en JSON; la generación es reproducible con `--seed`.

**Qué está probado y qué no.** Está probado que el modelo genera candidatos que el mangleo
no puede alcanzar (hay un test que lo mide). Y está **medido cuánto ayuda**, con un resultado
que mezcla: a un millón de intentos y sobre contraseñas held-out, el modelo recupera **0,49 %**
contra **2,63 %** de las máscaras de hashcat y **2,15 %** de sus reglas. Pero a 10.000-100.000
intentos —donde una recuperación se decide de verdad— el modo **ordenado** empata con las
máscaras y las supera a 100.000, con **4-6× de ventaja** sobre samplear.

La razón de fondo: un modelo por muestreo extrae de la distribución que aprendió pero **no
ordena sus extracciones**, así que a presupuesto chico desperdicia intentos en la cola de su
propia distribución. Por eso existe `--ordenado`, que enumera por probabilidad decreciente. La
comparación completa está en [`docs/EVALUACION.md`](docs/EVALUACION.md).

Nada de esto recupera una contraseña aleatoria de 20 caracteres. Contra eso no hay
estrategia que sirva: es matemática, no perseverancia.

---

## Cifrado tradicional (ZipCrypto)

Además de AES, `zipaes` detecta y **ataca ZipCrypto**, el cifrado clásico de PKWARE:

```console
$ zipaes info clasico.zip
tipo: ZIPCRYPTO
detalle:
  - nombre=secreto.txt, formato=ZipCrypto, flags=0x0009, data_descriptor=True,
    metodo_real=0, crc=af1b45f9, cifrado=40, sin_comprimir=28

$ zipaes crack clasico.zip --palabras alfa clave-zip
tipo: ZIPCRYPTO
backend: python-zipcrypto
encontrada: si
password: clave-zip

$ zipaes extract clasico.zip -p clave-zip -o salida/
extraidos: 1
```

ZipCrypto no es AES: usa un generador de 3 claves de 32 bits, **sin derivación de claves**.
Por eso probarlo es órdenes de magnitud más barato y no hace falta GPU: el ataque propio
corre a cientos de miles de candidatos por segundo. Su verificación es concluyente igual:
se descifra el contenido y se compara el CRC, no el byte de control de la cabecera (que
deja pasar uno de cada 256 falsos positivos).

Y si preferís las herramientas externas, el hash también se emite:

```console
$ zipaes hash clasico.zip
$pkzip2$1*1*2*0*5f*2261*9aa527f8*0*0*8*5f*9aa5*7e86*09661853…*$/pkzip2$

$ hashcat -m 17200 hash.txt diccionario.txt
```

Eso sí: el modo 17200 sólo ataca entradas comprimidas con **deflate**. Si el archivo usa
almacenamiento sin comprimir, `zipaes hash` te lo dice y `zipaes crack` lo resuelve igual.

Detalle del formato en [`docs/FORMATO.md`](docs/FORMATO.md).

---

## Cómo funciona (AES)

```
DK         = PBKDF2-HMAC-SHA1(contraseña, salt, 1000 iteraciones, 2*clave + pv)
clave_aes  = DK[0 : clave]
clave_mac  = DK[clave : 2*clave]
pv         = DK[2*clave : 2*clave + pv]

ciphertext = AES-CTR(clave_aes, datos)         # contador little-endian, arranca en 1
auth_code  = HMAC-SHA1(clave_mac, ciphertext)[:10]
```

En el archivo: `[salt: 8/12/16][pv: 1 o 2][ciphertext][auth_code: 10]`.

Tres detalles que suelen arruinar implementaciones:

1. **El `pv` no alcanza como verificación.** En AE-1 mide **1 byte**: uno de cada 256
   candidatos falsos lo supera. La prueba real es recalcular el `auth_code`.
2. **El contador del CTR es little-endian.** El modo CTR estándar de las bibliotecas usa un
   contador big-endian sobre los 128 bits: no sirve. Hay que construir el keystream bloque
   a bloque.
3. **El salt no siempre mide 16 bytes.** Mide `4 + 4*fuerza`: 8, 12 o 16. Asumir 16 es un
   error silencioso que sólo aparece con AES-128/192.

Todo está implementado y cubierto por tests en `zipaes/format.py` y `zipaes/crypto.py`.
El detalle completo, en [`docs/FORMATO.md`](docs/FORMATO.md).

---

## El flujo recomendado

```
1. zipaes backend                    # ¿hay hashcat? ¿hay john?
2. zipaes info archivo.zip           # ¿AES o ZipCrypto? ¿variante y fuerza?
3. zipaes selftest                   # ¿el flujo funciona en esta máquina?
4. zipaes wordlist ...               # lista dirigida + modelo
5. zipaes crack archivo.zip -w ...   # o hashcat -m 13600 con el hash de `zipaes hash`
6. zipaes verify archivo.zip -p ...  # confirmar el candidato (concluyente)
7. zipaes extract archivo.zip -p ... -o salida/
```

**El paso 3 no es ceremonia.** Un hash mal formado no falla de forma visible: simplemente
no encuentra nada, y podés dejar la GPU trabajando horas contra un problema imposible.
En [`docs/METODOLOGIA.md`](docs/METODOLOGIA.md) está el razonamiento completo.

---

## Límites conocidos

- **AE-1 y hashcat.** El campo del `pv` en el hash `$zip2$` se compara a 16 bits en el
  kernel de hashcat (modo 13600). Un archivo AE-1 guarda un solo byte de verificación, así
  que **el ataque por GPU puede no encontrarlo**. Para AE-1 usá `zipaes crack`, que no
  depende del largo del `pv`, y `--backend auto` ya lo elige. `zipaes hash --avisos` te lo
  recuerda.
- **ZipCrypto y el modo 17200.** El kernel de hashcat sólo ataca entradas **comprimidas con
  deflate**. Si la entrada está almacenada —que es lo que hace `zip` cuando comprimir no
  ayuda, típico en archivos chicos— no hay kernel posible: `zipaes hash` lo dice en vez de
  emitir un hash que nunca va a romper, y `zipaes crack` la resuelve igual con el backend
  propio. Además, en una medición puntual el camino propio resultó **~3,4× más rápido** que el
  modo 17200 (un archivo, una lista de 20.000 candidatos, una máquina). Ojo con generalizar de
  ahí: el costo del kernel de hashcat crece con el tamaño del archivo comprimido, y su ventaja
  crece con el tamaño de la lista y con la cantidad de GPUs. Para ZipCrypto el camino propio es
  el mejor punto de partida, no una regla universal.
- **El motor de candidatos está medido.** Con un test realista (las contraseñas que la gente de
  verdad usa), **a presupuesto bajo el mejor generador es el decodificado ordenado del modelo
  neuronal**: a 1.000 intentos saca 1,65× lo que la mejor regla de hashcat, 7,7× lo que el
  modelo propio y 70× lo que sus máscaras. A presupuesto alto manda la enumeración con wordlist
  (`best64` llega a 14,79 % a 10⁵). Todo el detalle, con el protocolo, las dos métricas y las
  limitaciones declaradas, en [`docs/EVALUACION.md`](docs/EVALUACION.md).
- **ZIP64**: se detecta e informa, pero el soporte es parcial (archivos >4 GB o muchos
  miles de entradas pueden fallar). Los archivos multi-volumen quedan fuera.
- **No hace fuerza bruta.** No adivina: prueba candidatos que le des, o delega el trabajo
  pesado a hashcat/John y confirma el resultado.
- **No rompe el cifrado.** AES-256 con una contraseña fuerte sigue siendo AES-256 con una
  contraseña fuerte.

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
  format.py      contenedor ZIP, entradas AES y ZipCrypto, ZIP64, data descriptor
  crypto.py      derivación de claves AES, keystream, verificación, descifrado
  zipcrypto.py   cifrado tradicional de PKWARE: claves, verificación, ataque
  hashfmt.py     emisión del hash $zip2$ para hashcat / John
  backend.py     detección y orquestación de hashcat y John the Ripper
  candidates.py  mangleo PACK, composición PRINCE y modelo de Markov
  crack.py       ataque de diccionario propio (el camino correcto para AE-1)
  extract.py     extracción segura (sin escapes de ruta) para AES y ZipCrypto
  selftest.py    autocomprobación de punta a punta
  testkit.py     escritor de zips AES para fixtures de prueba
  cli.py         interfaz de línea de comandos
tests/           216 pruebas con pytest
docs/            metodología, formato, ética y preguntas frecuentes
```

## Calidad

```bash
make check    # ruff check + ruff format --check + pytest
```

- **216 tests**, todos en verde, sin red ni servicios externos.
- **Interoperabilidad real**: las pruebas crean archivos con **7-Zip** y con **Info-ZIP** y
  los abren con este paquete, y verifican que 7-Zip acepte lo que el kit de pruebas escribe.
  No se valida contra sí mismo.
- **Fuzzing del parser**: 300 mutaciones deterministas por formato (bit flips, truncados,
  tamaños absurdos) que exigen que el parser no reviente con excepciones que delaten un
  descuido, y que respete los invariantes del formato cuando el parseo tiene éxito.
- **Integración real con hashcat** en los tres caminos: modo 13600 (AES), modo 13600 con el
  caso patológico que hashcat normaliza al volcar el resultado, y modo 17200 (ZipCrypto). Las
  pruebas buscan las fixtures que disparan cada caso, así que no dependen del azar.
- `ruff` limpio. CI en Python 3.11/3.12/3.13 más macOS y Windows.

## Documentación

- [Metodología de recuperación](docs/METODOLOGIA.md) — el orden correcto y por qué
- [Evaluación de generadores](docs/EVALUACION.md) — qué se midió, qué gana y qué queda abierto
- [El formato, en detalle](docs/FORMATO.md) — AES y ZipCrypto, `$zip2$`, `$pkzip2$`, trampas
- [Ética y marco legal](docs/ETICA-Y-LEGAL.md) — uso aceptable
- [Preguntas frecuentes](docs/FAQ.md)

## Licencia

MIT. Ver [`LICENSE`](LICENSE).

## Agradecimientos

A los proyectos que hacen el trabajo pesado cuando la contraseña resiste:
[hashcat](https://hashcat.net/hashcat/), [John the Ripper](https://www.openwall.com/john/),
[7-Zip](https://www.7-zip.org/) e Info-ZIP. El formato está documentado en el APPNOTE de
PKWARE y en la [especificación AES de WinZip](https://www.winzip.com/en/support/aes-encryption/).