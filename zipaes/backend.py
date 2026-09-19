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
from .hashfmt import HASHCAT_MODE, emit_hash

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


def _leer_potfile(path: str, hash_line: str) -> str | None:
    """Extrae la contraseña del potfile para un hash dado."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            # el hash no contiene ":", así que la primera separación es la buena
            if line.startswith(hash_line + ":"):
                return line[len(hash_line) + 1 :]
            if ":" in line:
                posible_hash, posible_clave = line.split(":", 1)
                if posible_hash == hash_line:
                    return posible_clave
    return None


def _ejecutar(comando: list[str], timeout: int | None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise BackendError(f"la herramienta excedió el tiempo límite: {exc}") from exc
    except OSError as exc:
        raise BackendError(f"no se pudo ejecutar {comando[0]}: {exc}") from exc


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

    hash_line = emit_hash(entry)  # sin prefijo de nombre: hashcat no lo espera
    with open(hash_file, "w", encoding="utf-8") as handle:
        handle.write(hash_line + "\n")

    comando = [
        binario,
        "-m",
        str(HASHCAT_MODE),
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
    hash_line = f"{entry.name}:{emit_hash(entry)}"
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

    Devuelve ``(contraseña, backend_usado)``. Con ``backend="auto"`` se elige hashcat si
    está disponible — salvo en AE-1, donde se prefiere el verificador propio por la
    limitación de 16 bits del kernel.
    """
    from .crack import crack as crack_python

    eleccion = backend
    if backend == "auto":
        tiene_hashcat = bool(hashcat_path or find_tool("hashcat"))
        tiene_john = bool(john_path or find_tool("john"))
        if entry.aes_version == 1:
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
        return crack_python(entry, wordlist_path=wordlist), "python"

    raise ValueError(f"backend desconocido: {backend!r}")
