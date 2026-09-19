"""Backends externos: descubrimiento, orquestación y degradación.

Ninguna prueba de este archivo depende de que haya GPU: la orquestación se prueba con un
«hashcat de mentira» que escribe el potfile, y la integración real se activa sólo si el
binario está presente.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from zipaes import inspect
from zipaes.backend import (
    BackendError,
    Tool,
    _leer_potfile,
    detect_tools,
    find_tool,
    hashcat_attack,
    john_attack,
    recover,
)
from zipaes.hashfmt import emit_hash
from zipaes.testkit import write_aes_zip

ES_WINDOWS = sys.platform.startswith("win")


@pytest.fixture
def zip_objetivo(tmp_path):
    ruta = str(tmp_path / "objetivo.zip")
    write_aes_zip(ruta, {"a.txt": b"contenido"}, "clave-objetivo")
    return ruta


def _escribir_stub(tmp_path, nombre: str, contenido: str) -> str:
    ruta = tmp_path / nombre
    ruta.write_text(contenido, encoding="utf-8")
    ruta.chmod(ruta.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(ruta)


STUB_HASHCAT = """#!/bin/sh
# hashcat de mentira: encuentra el hash en los argumentos, escribe el potfile y sale
pot=""
hashfile=""
while [ $# -gt 0 ]; do
  case "$1" in
    --potfile-path) pot="$2"; shift 2 ;;
    *hash.txt) hashfile="$1"; shift ;;
    *) shift ;;
  esac
done
if [ -n "$pot" ] && [ -n "$hashfile" ]; then
  printf '%s:%s\\n' "$(cat "$hashfile")" "clave-del-stub" > "$pot"
fi
echo "Status...........: Cracked"
exit 0
"""

STUB_HASHCAT_FALLA = """#!/bin/sh
echo "OpenCL platform not found" >&2
exit 255
"""


# --- descubrimiento -------------------------------------------------------- #


def test_detect_tools_devuelve_un_diccionario():
    herramientas = detect_tools()
    assert isinstance(herramientas, dict)
    for nombre, tool in herramientas.items():
        assert nombre in ("hashcat", "john")
        assert isinstance(tool, Tool)


def test_find_tool_usa_la_variable_de_entorno(tmp_path, monkeypatch):
    if ES_WINDOWS:
        pytest.skip("el stub es un script de shell")
    ruta = _escribir_stub(tmp_path, "hashcat-falso", "#!/bin/sh\necho ok\n")
    monkeypatch.setenv("HASHCAT", ruta)
    assert find_tool("hashcat") == ruta


def test_find_tool_ignora_la_variable_si_no_existe(monkeypatch):
    monkeypatch.setenv("HASHCAT", "/ruta/que/no/existe")
    resultado = find_tool("hashcat", extra_paths=["/otra/que/no/existe"])
    assert resultado is None or os.access(resultado, os.X_OK)


def test_find_tool_rechaza_nombres_desconocidos():
    with pytest.raises(ValueError):
        find_tool("rm")


def test_tool_version_no_revienta():
    assert isinstance(Tool(name="hashcat", path="/no/existe").version(), str)


# --- lectura del potfile --------------------------------------------------- #


def test_leer_potfile_encuentra_la_clave(tmp_path):
    hash_line = "$zip2$*0*3*0*aa*bb*1*cc*dd*$/zip2$"
    pot = tmp_path / "h.pot"
    pot.write_text(f"otrohash:x\n{hash_line}:la-clave\n", encoding="utf-8")
    assert _leer_potfile(str(pot), hash_line) == "la-clave"


def test_leer_potfile_con_dos_puntos_en_la_clave(tmp_path):
    hash_line = "$zip2$*0*3*0*aa*bb*1*cc*dd*$/zip2$"
    pot = tmp_path / "h.pot"
    pot.write_text(f"{hash_line}:con:dos:puntos\n", encoding="utf-8")
    assert _leer_potfile(str(pot), hash_line) == "con:dos:puntos"


def test_leer_potfile_inexistente(tmp_path):
    assert _leer_potfile(str(tmp_path / "no.pot"), "x") is None


def test_leer_potfile_sin_coincidencias(tmp_path):
    pot = tmp_path / "h.pot"
    pot.write_text("otra:cosa\n", encoding="utf-8")
    assert _leer_potfile(str(pot), "$zip2$...") is None


# --- orquestación de hashcat ----------------------------------------------- #


def test_hashcat_exige_wordlist_o_mask(zip_objetivo):
    entry = inspect(zip_objetivo).aes[0]
    with pytest.raises(ValueError):
        hashcat_attack(entry)


def test_hashcat_sin_binario_da_un_error_claro(zip_objetivo, tmp_path):
    entry = inspect(zip_objetivo).aes[0]
    with pytest.raises(BackendError):
        hashcat_attack(
            entry,
            wordlist=str(tmp_path / "l.txt"),
            hashcat_path="/no/existe/hashcat",
        )


@pytest.mark.skipif(ES_WINDOWS, reason="el stub es un script de shell")
def test_hashcat_lee_la_clave_del_potfile(zip_objetivo, tmp_path):
    stub = _escribir_stub(tmp_path, "hashcat", STUB_HASHCAT)
    lista = tmp_path / "lista.txt"
    lista.write_text("uno\ndos\n", encoding="utf-8")
    entry = inspect(zip_objetivo).aes[0]
    clave = hashcat_attack(
        entry, wordlist=str(lista), hashcat_path=stub, workdir=str(tmp_path / "w")
    )
    assert clave == "clave-del-stub"


@pytest.mark.skipif(ES_WINDOWS, reason="el stub es un script de shell")
def test_hashcat_informa_del_fallo(zip_objetivo, tmp_path):
    stub = _escribir_stub(tmp_path, "hashcat-malo", STUB_HASHCAT_FALLA)
    lista = tmp_path / "lista.txt"
    lista.write_text("uno\n", encoding="utf-8")
    entry = inspect(zip_objetivo).aes[0]
    with pytest.raises(BackendError) as excinfo:
        hashcat_attack(entry, wordlist=str(lista), hashcat_path=stub, workdir=str(tmp_path / "w"))
    assert "OpenCL" in str(excinfo.value)


@pytest.mark.skipif(ES_WINDOWS, reason="el stub es un script de shell")
def test_hashcat_sin_resultado_devuelve_none(tmp_path, zip_objetivo):
    stub = _escribir_stub(tmp_path, "hashcat-vacio", "#!/bin/sh\necho 'Status: Exhausted'\n")
    lista = tmp_path / "lista.txt"
    lista.write_text("uno\n", encoding="utf-8")
    entry = inspect(zip_objetivo).aes[0]
    assert (
        hashcat_attack(entry, wordlist=str(lista), hashcat_path=stub, workdir=str(tmp_path / "w"))
        is None
    )


def test_john_sin_binario_da_un_error_claro(zip_objetivo):
    entry = inspect(zip_objetivo).aes[0]
    with pytest.raises(BackendError):
        john_attack(entry, john_path="/no/existe/john")


# --- selección de backend -------------------------------------------------- #


def test_recover_python_usa_el_verificador_propio(zip_objetivo, tmp_path):
    lista = tmp_path / "lista.txt"
    lista.write_text("uno\nclave-objetivo\n", encoding="utf-8")
    entry = inspect(zip_objetivo).aes[0]
    clave, usado = recover(entry, wordlist=str(lista), backend="python")
    assert clave == "clave-objetivo"
    assert usado == "python"


def test_recover_python_sin_wordlist_es_error(zip_objetivo):
    entry = inspect(zip_objetivo).aes[0]
    with pytest.raises(ValueError):
        recover(entry, backend="python")


def test_recover_auto_no_usa_hashcat_en_ae1(tmp_path, monkeypatch):
    """En AE-1 el kernel de hashcat compara 16 bits: no lo elegimos nosotros."""
    ruta = str(tmp_path / "ae1.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "secreta", aes_version=1)
    entry = inspect(ruta).aes[0]

    llamado = {}

    def falso_hashcat(entry, **kwargs):
        llamado["hashcat"] = True
        return None

    monkeypatch.setattr("zipaes.backend.hashcat_attack", falso_hashcat)
    # hashcat "existe", john no: en AE-1 debe caer igual al verificador propio
    monkeypatch.setattr(
        "zipaes.backend.find_tool",
        lambda name, extra_paths=None: "/falso" if name == "hashcat" else None,
    )

    lista = tmp_path / "l.txt"
    lista.write_text("secreta\n", encoding="utf-8")
    clave, usado = recover(entry, wordlist=str(lista), backend="auto")
    assert usado == "python"
    assert clave == "secreta"
    assert not llamado, "no debe intentarse hashcat con AE-1"


def test_recover_auto_prefiere_hashcat_en_ae2(tmp_path, monkeypatch):
    """Con AE-2 y hashcat disponible, la elección automática es la GPU."""
    ruta = str(tmp_path / "ae2.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "secreta", aes_version=2)
    entry = inspect(ruta).aes[0]

    monkeypatch.setattr(
        "zipaes.backend.find_tool",
        lambda name, extra_paths=None: "/falso" if name == "hashcat" else None,
    )
    monkeypatch.setattr(
        "zipaes.backend.hashcat_attack",
        lambda entry, **kwargs: "encontrada-por-gpu",
    )

    lista = tmp_path / "l.txt"
    lista.write_text("x\n", encoding="utf-8")
    clave, usado = recover(entry, wordlist=str(lista), backend="auto")
    assert usado == "hashcat"
    assert clave == "encontrada-por-gpu"


def test_recover_backend_desconocido(zip_objetivo, tmp_path):
    entry = inspect(zip_objetivo).aes[0]
    lista = tmp_path / "l.txt"
    lista.write_text("x\n", encoding="utf-8")
    with pytest.raises(ValueError):
        recover(entry, wordlist=str(lista), backend="cualquiera")


# --- integración real (sólo si hay hashcat) -------------------------------- #


@pytest.fixture
def hashcat_real():
    ruta = find_tool("hashcat")
    if not ruta:
        pytest.skip("hashcat no está instalado")
    if ES_WINDOWS:
        pytest.skip("no se ejecuta la integración real en Windows")
    return ruta


def test_integracion_real_con_hashcat(zip_objetivo, tmp_path, hashcat_real):
    """Si hay hashcat, la cadena completa debe recuperar la contraseña de verdad."""
    lista = tmp_path / "lista.txt"
    lista.write_text("uno\ndos\nclave-objetivo\ntres\n", encoding="utf-8")
    entry = inspect(zip_objetivo).aes[0]
    hash_line = emit_hash(entry)
    assert hash_line.startswith("$zip2$")

    clave = hashcat_attack(
        entry,
        wordlist=str(lista),
        hashcat_path=hashcat_real,
        workdir=str(tmp_path / "w"),
        timeout=300,
    )
    assert clave == "clave-objetivo"
    # y lo que devuelve hashcat se confirma con el verificador propio
    from zipaes import verify

    assert verify(entry, clave)
