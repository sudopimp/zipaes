# Metodología de recuperación

Cómo abordar un zip con cifrado AES cuya contraseña se perdió, en el orden que menos
tiempo hace perder. Está escrito desde la experiencia de haber resuelto el problema: casi
todo lo que sigue es consecuencia de errores que se cometen una vez.

---

## Regla cero: no ataques a ciegas

Antes de gastar un solo ciclo de GPU, contestá tres preguntas:

1. **¿Es AES?** Puede ser ZipCrypto. `zipaes info archivo.zip` lo dice.
2. **¿Qué variante y qué fuerza?** AE-1 o AE-2, y AES-128/192/256. Cambia la estrategia.
3. **¿El flujo funciona en esta máquina?** `zipaes selftest`.

Un hash mal formado tiene un modo de falla silencioso: no encuentra nada. No hay error, no
hay advertencia, sólo una GPU trabajando contra un problema imposible. Por eso el paso de
validación va **antes** del ataque, no después.

---

## Los cinco pasos

### 1. Identificar

```bash
zipaes info archivo.zip
```

Te importa:

- cuántas entradas AES hay (con una alcanza para el ataque: probar más no aporta, y si son
  muchas, más rápido todavía, porque todas comparten contraseña);
- la **variante** (AE-1 / AE-2) y la **fuerza**;
- si hay entradas que **no** son AES: un archivo mixto se ataca por la parte AES.

### 2. Validar el emisor

```bash
zipaes selftest
zipaes selftest --ae1
zipaes selftest --fuerza 1
zipaes selftest --deflate
```

Esto construye un zip AES con una contraseña conocida, recorre el flujo completo y comprueba
cada paso, incluido que el hash emitido cumpla el formato que espera hashcat. Si algo del
entorno está mal, aparece acá y no a las tres horas.

### 3. Atacar

**Camino rápido (GPU):**

```bash
zipaes hash archivo.zip > hash.txt
hashcat -m 13600 hash.txt diccionario.txt -r rules/best64.rule
```

`-m 13600` es WinZip AES. Con una GPU modesta y un diccionario público + reglas, la tasa es
de millones de candidatos por segundo.

**Dejando que zipaes lo orqueste:**

```bash
zipaes backend                                     # ¿qué hay disponible?
zipaes crack archivo.zip -w diccionario.txt --backend hashcat
zipaes crack archivo.zip -w diccionario.txt --backend auto     # por defecto
```

`auto` elige hashcat si está disponible — **salvo en AE-1**, donde el kernel del modo 13600
no es fiable (§4), y **salvo en ZipCrypto**, donde el camino propio es más rápido (§5).

**Si es ZipCrypto, no hace falta GPU.** El formato no deriva claves, así que probar un
candidato es descifrar 12 bytes y comparar un byte. El ataque propio aprovecha eso y reserva
la validación completa (descifrar todo y verificar el CRC) para los pocos candidatos que
pasan el filtro. El kernel del modo 17200 de hashcat, en cambio, descifra, descomprime y
recalcula el CRC del archivo entero por cada candidato. Medido con la misma lista en la
misma máquina: **~36.700 contra ~10.900 candidatos por segundo**. Por eso `auto` elige el
camino propio, y el hash `$pkzip2$` (`zipaes hash`) queda para quien quiera usar hashcat
igual — por ejemplo para repartir el trabajo en varias máquinas.

**Camino sin GPU (CPU, sin dependencias):**

```bash
zipaes crack archivo.zip -w diccionario.txt -j 8 --backend python
```

**Antes de escalar, agotá lo obvio.** La mayoría de los casos reales no son contraseñas
aleatorias: son variantes de algo que la persona ya usaba. Armá una lista dirigida con lo
que sepas del contexto (nombre del proyecto, apodo, dominio, año, equipo favorito, fechas)
y probala primero:

```bash
zipaes wordlist -o dirigida.txt proyecto apodo dominio 2025
zipaes crack archivo.zip -w dirigida.txt
```

Eso genera mangleo tipo PACK de cada palabra (mayúsculas, leet, inversión, sufijos, años) y
composición entre ellas (`proyecto_apodo`, `apodo2025`, …).

**Y si el contexto no alcanza, entrená un modelo.** Es la técnica que más rinde cuando hay
un corpus disponible (una filtración, un diccionario público, contraseñas viejas del mismo
entorno):

```bash
zipaes wordlist -o lista.txt --train rockyou.txt --save-model modelo.json --count 200000
zipaes crack archivo.zip -w lista.txt --backend hashcat
```

El modelo aprende la distribución de caracteres del corpus y samplea candidatos nuevos:
llega a lugares a los que las reglas fijas no llegan, porque no se limita a transformar
palabras que le des. Se entrena una vez y se reutiliza (`--model modelo.json`), y la
generación es reproducible con `--seed`.

### 4. Confirmar

```bash
zipaes verify archivo.zip -p candidato
```

**No te saltees este paso.** El `pv` que usa hashcat para filtrar mide 1 byte en AE-1: uno
de cada 256 falsos positivos lo supera. `verify` recalcula el código de autenticación
HMAC-SHA1, que es una prueba real.

Salida `0`: contraseña correcta. Salida `2`: no lo es.

### 5. Extraer

```bash
zipaes extract archivo.zip -p contraseña -o salida/
```

Descifra y descomprime cada entrada respetando la estructura de carpetas, y rechaza
cualquier nombre que intente escapar del directorio destino.

---

## La trampa de AE-1 con hashcat

El formato `$zip2$` que consumen hashcat y John lleva el valor de verificación de clave. El
kernel de hashcat **compara 16 bits** contra ese campo.

- **AE-2**: el archivo guarda 2 bytes de verificación → la comparación de 16 bits es exacta
  → todo funciona.
- **AE-1**: el archivo guarda **1 byte** → la comparación de 16 bits no puede satisfacerse
  con ese único byte conocido → **el ataque por GPU puede no encontrar nada aunque la
  contraseña esté en el diccionario**.

Para AE-1 usá el verificador propio, que no depende del largo del `pv`:

```bash
zipaes hash archivo.zip --avisos        # te avisa si es AE-1
zipaes crack archivo.zip -w lista.txt   # funciona igual en AE-1
```

Es más lento que la GPU, pero es correcto. Y la regla general vale siempre: **lo que
encuentra hashcat se confirma con `zipaes verify`, no al revés.**

---

## Estrategia de diccionarios

Orden recomendado, de más barato a más caro:

1. **Lista dirigida** (decenas a miles de candidatos, segundos). Contexto del dueño del
   archivo. Acá se resuelve la mayoría.
2. **Diccionario público + reglas** (`rockyou` + `best64`). ~1.100 millones de candidatos,
   minutos en GPU.
3. **Reglas más agresivas** (`dive` y compañía), máscaras, o combinaciones. Horas.
4. **Fuerza bruta pura.** Sólo si el espacio es chico (por ejemplo, un PIN de 6 dígitos).
   Contra una contraseña larga y aleatoria no hay estrategia que sirva: es matemática, no
   perseverancia.

Antes de escalar al punto 3, revisá si no te quedó sin probar algo del punto 1. Casi
siempre queda.

---

## Cuándo conviene parar

- Si el archivo es **de un tercero**, antes de cualquier paso: ver
  [`ETICA-Y-LEGAL.md`](ETICA-Y-LEGAL.md).
- Si la contraseña parece aleatoria y larga (≥ 12 caracteres sin patrón), el ataque de
  diccionario no la va a encontrar. Evaluá alternativas: ¿existe una copia sin cifrar?,
  ¿el archivo se generó con una herramienta que guarda la contraseña en algún lado?,
  ¿hay una nota o un gestor de contraseñas?
- Si el objetivo es el contenido y no la contraseña: buscá otras copias del mismo material.
  Recuperar el archivo por otra vía suele ser más rápido que romper el cifrado.