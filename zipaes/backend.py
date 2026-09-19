"""Backends externos: hashcat y John the Ripper.

El cracker propio existe para ser **correcto**, no rápido: en una RTX 4060, hashcat hace
unos 2,4 millones de candidatos por segundo contra los ~4.400 del verificador en Python,
unas 540 veces más. Reimplementar un motor de GPU sería absurdo; lo correcto es
orquestar las herramientas que ya son referencia del sector y reservar el camino propio
para cuando hace falta precisión o no hay GPU.

Este módulo se encarga de:

* encontrar los binarios (PATH, ``HASHCAT``/``JOHN`` del entorno, ubicaciones habituales);
* emitir el hash y lanzar la herramienta;
* leer el resultado del potfile o de la salida;
* degradar con un mensaje claro cuando no hay ninguna instalada.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from .format import AesEntry
from .hashfmt import (
    HASHCAT_MODE,
    HASHCAT_MODE_ZIPCRYPTO,
    emit_hash,
    emit_pkzip2,
)

__all__ = [
    "Tool",
    "find_tool",
    "detect_tools",
    "hashcat_attack",
    "john_attack",
    "recover",
    "BackendError",
    "home_dir",
]


def home_dir() -> str:
    """Directorio personal del usuario **real**.

    No se usa ``Path.home()`` ni ``os.path.expanduser("~")`` porque ambos leen ``HOME``,
    que puede estar redefinido (contenedores, entornos virtuales, sesiones de servicio).
    La fuente confiable es la base de datos de usuarios del sistema.
    """
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:  # noqa: BLE001 — en plataformas sin pwd caemos al entorno
        return os.environ.get("HOME") or os.path.expanduser("~")


#: globs de búsqueda, además del PATH
GLOBS_HABITUALES = {
    "hashcat": [
        "/opt/hashcat*/hashcat.bin",
        "/usr/local/hashcat*/hashcat.bin",
        "~/opt/hashcat*/hashcat.bin",
        "~/hashcat*/hashcat.bin",
        "/usr/share/hashcat/hashcat.bin",
    ],
    "john": [
        "/opt/john*/run/john",
        "~/john*/run/john",
        "/usr/share/john/john",
    ],
}

#: rutas fijas de respaldo
RUTAS_HABITUALES = {
    "hashcat": ["/usr/bin/hashcat", "/usr/local/bin/hashcat", "/opt/hashcat/hashcat.bin"],
    "john": ["/usr/bin/john", "/usr/local/bin/john", "/usr/sbin/john"],
}

VARIABLES_ENTORNO = {"hashcat": "HASHCAT", "john": "JOHN"}


class BackendError(RuntimeError):
    """El backend no está disponible o falló de una forma que conviene informar."""


@dataclass
class Tool:
    """Un backend externo detectado."""

    name: str
    path: str

    def version(self) -> str:
        flags = ["--version"] if self.name == "hashcat" else ["--version"]
        try:
            salida = subprocess.run([self.path, *flags], capture_output=True, text=True, timeout=15)
            texto = (salida.stdout or salida.stderr or "").strip().splitlines()
            return texto[0] if texto else "desconocida"
        except Exception:  # noqa: BLE001 — la versión es informativa, no crítica
            return "desconocida"

    def summary(self) -> dict:
        return {"nombre": self.name, "ruta": self.path, "version": self.version()}


def find_tool(name: str, extra_paths: list[str] | None = None) -> str | None:
    """Busca un binario: variable de entorno, PATH, globs habituales y rutas fijas."""
    if name not in RUTAS_HABITUALES:
        raise ValueError(f"herramienta desconocida: {name}")

    variable = VARIABLES_ENTORNO.get(name)
    if variable and os.environ.get(variable):
        candidato = os.environ[variable]
        if os.path.isfile(candidato) and os.access(candidato, os.X_OK):
            return candidato

    encontrado = shutil.which(name)
    if encontrado:
        return encontrado

    for patron in GLOBS_HABITUALES.get(name, []):
        expandido = patron.replace("~", home_dir())
        for candidato in sorted(glob.glob(expandido), reverse=True):
            if os.path.isfile(candidato) and os.access(candidato, os.X_OK):
                return candidato

    for candidato in list(extra_paths or []) + RUTAS_HABITUALES[name]:
        if os.path.isfile(candidato) and os.access(candidato, os.X_OK):
            return candidato
    return None


def detect_tools(extra_paths: list[str] | None = None) -> dict[str, Tool]:
    """Devuelve las herramientas externas disponibles."""
    detectadas: dict[str, Tool] = {}
    for name in RUTAS_HABITUALES:
        path = find_tool(name, extra_paths)
        if path:
            detectadas[name] = Tool(name=name, path=path)
    return detectadas


def _normalizar_hash(linea: str) -> tuple[str, ...] | None:
    """Normaliza un hash ``$zip2$`` para poder compararlo.

    El campo del valor de verificación (posición 5) se compara **numéricamente**: hashcat
    lo reescribe sin ceros a la izquierda al volcar el resultado al potfile (issue #4200),
    así que una comparación literal falla en aproximadamente uno de cada dieciséis hashes
    —los que tienen un `0` inicial en ese campo.
    """
    if not linea.startswith("$zip2$"):
        return None
    campos = linea.split("*")
    if len(campos) != 10:
        return None
    campos[5] = str(int(campos[5], 16)) if campos[5] else ""
    return tuple(campos)


def _leer_potfile(path: str, hash_line: str) -> str | None:
    """Extrae la contraseña del potfile para un hash dado.

    La comparación es tolerante a la normalización de hashcat (ver ``_normalizar_hash``).
    """
    if not os.path.isfile(path):
        return None
    buscado = _normalizar_hash(hash_line)
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line or ":" not in line:
                continue
            # el hash no contiene ":", así que la primera separación es la buena
            posible_hash, posible_clave = line.split(":", 1)
            if posible_hash == hash_line:
                return posible_clave
            if buscado is not None and _normalizar_hash(posible_hash) == buscado:
                return posible_clave
    return None


def _ejecutar(comando: list[str], timeout: int | None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise BackendError(f"la herramienta excedió el tiempo límite: {exc}") from exc
    except OSError as exc:
        raise BackendError(f"no se pudo ejecutar {comando[0]}: {exc}") from exc


def _es_zipcrypto(entry) -> bool:
    from .zipcrypto import ZipCryptoEntry

    return isinstance(entry, ZipCryptoEntry)


def modo_y_hash(entry) -> tuple[int, str]:
    """Devuelve ``(modo de hashcat, línea de hash)`` para la entrada.

    AES va al modo 13600 con el hash ``$zip2$``; ZipCrypto al 17200 con el ``$pkzip2$``.
    """
    if _es_zipcrypto(entry):
        return HASHCAT_MODE_ZIPCRYPTO, emit_pkzip2(entry)
    return HASHCAT_MODE, emit_hash(entry)


def hashcat_attack(
    entry: AesEntry,
    *,
    wordlist: str | None = None,
    rules: str | None = None,
    mask: str | None = None,
    workdir: str | None = None,
    hashcat_path: str | None = None,
    timeout: int | None = None,
    extra_args: list[str] | None = None,
) -> str | None:
    """Ataca una entrada AES con hashcat (modo 13600) y devuelve la contraseña.

    Requiere ``wordlist`` o ``mask``. La contraseña se lee del potfile, que tiene prioridad
    sobre la salida estándar.
    """
    if not wordlist and not mask:
        raise ValueError("hace falta wordlist o mask")

    binario = hashcat_path or find_tool("hashcat")
    if not binario:
        raise BackendError(
            "hashcat no está instalado. Instalalo, o definí la variable HASHCAT con la "
            "ruta del ejecutable, o usá --backend python."
        )

    propio = workdir is None
    trabajo = workdir or tempfile.mkdtemp(prefix="zipaes-hashcat-")
    os.makedirs(trabajo, exist_ok=True)
    hash_file = os.path.join(trabajo, "hash.txt")
    pot_file = os.path.join(trabajo, "hashcat.pot")

    modo, hash_line = modo_y_hash(entry)  # sin prefijo de nombre: hashcat no lo espera
    with open(hash_file, "w", encoding="utf-8") as handle:
        handle.write(hash_line + "\n")

    comando = [
        binario,
        "-m",
        str(modo),
        "--potfile-path",
        pot_file,
        "--quiet",
        "--force",
        hash_file,
    ]
    comando += ["-a", "3", mask] if mask else ["-a", "0", wordlist or ""]
    if rules and not mask:
        comando += ["-r", rules]
    comando += list(extra_args or [])

    resultado = _ejecutar(comando, timeout)
    clave = _leer_potfile(pot_file, hash_line)
    if clave:
        return clave

    # la salida estándar puede traer "hash:clave" cuando no se usa potfile
    for linea in (resultado.stdout or "").splitlines():
        if linea.startswith(hash_line + ":"):
            return linea[len(hash_line) + 1 :]

    if resultado.returncode not in (0, 1) and not _es_exhausted(resultado):
        detalle = (resultado.stderr or resultado.stdout or "").strip().splitlines()
        pista = detalle[-1] if detalle else f"código {resultado.returncode}"
        if propio:
            shutil.rmtree(trabajo, ignore_errors=True)
        raise BackendError(f"hashcat falló: {pista}")
    if propio:
        shutil.rmtree(trabajo, ignore_errors=True)
    return None


def _es_exhausted(resultado: subprocess.CompletedProcess) -> bool:
    texto = ((resultado.stdout or "") + (resultado.stderr or "")).lower()
    return "exhausted" in texto or "recovered" in texto


def john_attack(
    entry: AesEntry,
    *,
    wordlist: str | None = None,
    john_path: str | None = None,
    timeout: int | None = None,
) -> str | None:
    """Ataca una entrada AES con John the Ripper."""
    binario = john_path or find_tool("john")
    if not binario:
        raise BackendError(
            "John the Ripper no está instalado. Instalalo, o definí la variable JOHN "
            "con la ruta del ejecutable, o usá --backend python."
        )

    propio = timeout is None
    trabajo = tempfile.mkdtemp(prefix="zipaes-john-")
    hash_file = os.path.join(trabajo, "hash.txt")
    hash_line = f"{entry.name}:{modo_y_hash(entry)[1]}"
    with open(hash_file, "w", encoding="utf-8") as handle:
        handle.write(hash_line + "\n")

    comando = [binario, f"--pot={os.path.join(trabajo, 'john.pot')}", hash_file]
    if wordlist:
        comando.append(f"--wordlist={wordlist}")
    _ejecutar(comando, timeout)

    mostrar = _ejecutar(
        [binario, f"--pot={os.path.join(trabajo, 'john.pot')}", "--show", hash_file],
        timeout,
    )
    for linea in (mostrar.stdout or "").splitlines():
        if linea.startswith(entry.name + ":"):
            resto = linea[len(entry.name) + 1 :]
            if resto and not resto.startswith(":"):
                return resto.split(":")[0]
    if propio:
        shutil.rmtree(trabajo, ignore_errors=True)
    return None


def recover(
    entry: AesEntry,
    *,
    wordlist: str | None = None,
    backend: str = "auto",
    rules: str | None = None,
    hashcat_path: str | None = None,
    john_path: str | None = None,
    timeout: int | None = None,
) -> tuple[str | None, str]:
    """Recupera una contraseña con el backend pedido.

    Devuelve ``(contraseña, backend_usado)``.

    Con ``backend="auto"``:

    - **AES**: se elige hashcat si está disponible, salvo en AE-1, donde se prefiere el
      verificador propio porque el kernel del modo 13600 compara 16 bits y AE-1 sólo
      guarda 1 byte de verificación.
    - **ZipCrypto**: se prefiere el camino propio. El kernel del modo 17200 descifra,
      descomprime y recalcula el CRC del archivo entero por cada candidato, y medido contra
      la misma lista el camino propio resultó ~3× más rápido en un solo proceso.
    """
    from .crack import crack as crack_python

    es_zipcrypto = _es_zipcrypto(entry)

    eleccion = backend
    if backend == "auto":
        tiene_hashcat = bool(hashcat_path or find_tool("hashcat"))
        tiene_john = bool(john_path or find_tool("john"))
        if es_zipcrypto:
            eleccion = "python"
        elif getattr(entry, "aes_version", None) == 1:
            # el kernel de hashcat compara 16 bits y AE-1 sólo guarda 1 byte de
            # verificación: no es fiable, así que no lo elegimos nosotros
            eleccion = "john" if tiene_john else "python"
        elif tiene_hashcat:
            eleccion = "hashcat"
        elif tiene_john:
            eleccion = "john"
        else:
            eleccion = "python"

    if eleccion == "hashcat":
        clave = hashcat_attack(
            entry,
            wordlist=wordlist,
            rules=rules,
            hashcat_path=hashcat_path,
            timeout=timeout,
        )
        return clave, "hashcat"

    if eleccion == "john":
        clave = john_attack(entry, wordlist=wordlist, john_path=john_path, timeout=timeout)
        return clave, "john"

    if eleccion == "python":
        if not wordlist:
            raise ValueError("el backend python necesita una wordlist")
        if es_zipcrypto:
            from .zipcrypto import crack as crack_zipcrypto

            return crack_zipcrypto(entry, wordlist_path=wordlist), "python-zipcrypto"
        return crack_python(entry, wordlist_path=wordlist), "python"

    raise ValueError(f"backend desconocido: {backend!r}")
