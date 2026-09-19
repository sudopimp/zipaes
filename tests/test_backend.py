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
    modo_y_hash,
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


def test_leer_potfile_tolera_el_campo_pv_sin_ceros(tmp_path):
    """hashcat reescribe el valor de verificación sin ceros a la izquierda (issue #4200).

    Ocurre en ~1 de cada 16 hashes, porque el campo son dos bytes al azar. Sin tolerarlo,
    el ataque reporta "no encontrada" con la contraseña ya escrita en el potfile.
    """
    hash_line = f"$zip2$*0*3*0*{'ab' * 16}*0f81*9*6d42967b6a4d1ef5f7*{'cc' * 10}*$/zip2$"
    reescrito = hash_line.replace("*0f81*", "*f81*")  # lo que hashcat vuelca
    pot = tmp_path / "hc.pot"
    pot.write_text(f"{reescrito}:la-clave\n", encoding="utf-8")
    assert _leer_potfile(str(pot), hash_line) == "la-clave"


def test_leer_potfile_tolera_ceros_en_cualquier_posicion_del_campo(tmp_path):
    hash_line = f"$zip2$*0*3*0*{'ab' * 16}*00c3*9*6d42*{'cc' * 10}*$/zip2$"
    pot = tmp_path / "hc.pot"
    pot.write_text(f"{hash_line.replace('*00c3*', '*c3*')}:otra\n", encoding="utf-8")
    assert _leer_potfile(str(pot), hash_line) == "otra"


def test_leer_potfile_no_confunde_hashes_distintos(tmp_path):
    """La tolerancia al pv no debe aceptar un hash que no corresponde."""
    hash_line = f"$zip2$*0*3*0*{'ab' * 16}*0f81*9*6d42*{'cc' * 10}*$/zip2$"
    otro = f"$zip2$*0*3*0*{'ff' * 16}*0f81*9*6d42*{'cc' * 10}*$/zip2$"
    pot = tmp_path / "hc.pot"
    pot.write_text(f"{otro}:no-es-esta\n", encoding="utf-8")
    assert _leer_potfile(str(pot), hash_line) is None


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


def _salt_con_pv_cero(password: str, strength: int = 3, limite: int = 5000) -> bytes:
    """Busca un salt cuyo valor de verificación empiece con un byte nulo.

    Es el caso que dispara el issue #4200 de hashcat: al volcar al potfile reescribe el
    campo sin el cero inicial. Buscarlo hace que la prueba cubra ese camino **siempre**,
    en lugar de depender de que el azar lo elija (uno de cada dieciséis hashes).
    """
    from zipaes.crypto import derive_keys
    from zipaes.format import KEYLEN_BY_STRENGTH

    keylen = KEYLEN_BY_STRENGTH[strength]
    for semilla in range(limite):
        salt = semilla.to_bytes(16, "big")
        _, _, pv = derive_keys(password, salt, keylen, 2)
        if pv[0] == 0:
            return salt
    raise AssertionError("no se encontró un salt con pv de cero inicial")


def test_integracion_real_con_hashcat_pv_con_cero_inicial(tmp_path, hashcat_real):
    """End-to-end del camino que rompía: hashcat reescribe el pv sin el cero."""
    from zipaes import verify

    salt = _salt_con_pv_cero("clave-objetivo")
    ruta = str(tmp_path / "cero.zip")
    write_aes_zip(ruta, {"a.txt": b"contenido"}, "clave-objetivo", salt=salt)
    entry = inspect(ruta).aes[0]
    assert entry.pv.hex().startswith("0"), "la fixture debe tener el pv con cero inicial"

    lista = tmp_path / "lista.txt"
    lista.write_text("uno\nclave-objetivo\n", encoding="utf-8")
    clave = hashcat_attack(
        entry,
        wordlist=str(lista),
        hashcat_path=hashcat_real,
        workdir=str(tmp_path / "w"),
        timeout=300,
    )
    assert clave == "clave-objetivo"
    assert verify(entry, clave)

    # y el potfile realmente trae el campo reescrito, que es lo que había que tolerar
    pot = tmp_path / "w" / "hashcat.pot"
    assert pot.is_file()
    linea = pot.read_text(encoding="utf-8").strip()
    assert not linea.startswith(emit_hash(entry) + ":"), (
        "se esperaba que hashcat hubiera normalizado el pv"
    )


# --- ZipCrypto (modo 17200) ------------------------------------------------ #


def _entrada_zc(ruta, indice=0):
    import zipfile

    from zipaes.zipcrypto import parse_zipcrypto_entry

    with zipfile.ZipFile(ruta) as archivo, open(ruta, "rb") as handle:
        info = archivo.infolist()[indice]
        return parse_zipcrypto_entry(handle, info, csize=info.compress_size, usize=info.file_size)


def test_modo_y_hash_para_aes(zip_objetivo):
    modo, linea = modo_y_hash(inspect(zip_objetivo).aes[0])
    assert modo == 13600
    assert linea.startswith("$zip2$")
    assert linea == emit_hash(inspect(zip_objetivo).aes[0])


def test_modo_y_hash_para_zipcrypto(zip_zipcrypto_deflate):
    modo, linea = modo_y_hash(_entrada_zc(zip_zipcrypto_deflate))
    assert modo == 17200
    assert linea.startswith("$pkzip2$")


def test_recover_auto_usa_el_camino_propio_en_zipcrypto(
    zip_zipcrypto_deflate, tmp_path, monkeypatch, clave
):
    """En ZipCrypto la elección automática no pasa por hashcat: el kernel es más lento."""
    llamado = {}
    monkeypatch.setattr(
        "zipaes.backend.hashcat_attack",
        lambda entry, **kw: llamado.setdefault("hashcat", True),
    )
    lista = tmp_path / "l.txt"
    lista.write_text(f"uno\ndos\n{clave}\n", encoding="utf-8")

    encontrada, usado = recover(
        _entrada_zc(zip_zipcrypto_deflate), wordlist=str(lista), backend="auto"
    )
    assert usado == "python-zipcrypto"
    assert encontrada == clave
    assert not llamado, "no debería haberse invocado hashcat"


def test_recover_zipcrypto_acepta_hashcat_si_se_pide(
    zip_zipcrypto_deflate, tmp_path, monkeypatch, clave
):
    """Pedirlo explícitamente sí lo usa: la elección automática no quita opciones."""
    monkeypatch.setattr("zipaes.backend.hashcat_attack", lambda entry, **kw: "encontrada-por-gpu")
    lista = tmp_path / "l.txt"
    lista.write_text("x\n", encoding="utf-8")
    encontrada, usado = recover(
        _entrada_zc(zip_zipcrypto_deflate), wordlist=str(lista), backend="hashcat"
    )
    assert usado == "hashcat"
    assert encontrada == "encontrada-por-gpu"


def test_modo_y_hash_rechaza_zipcrypto_sin_deflate(zip_zipcrypto):
    entry = _entrada_zc(zip_zipcrypto)
    if entry.compression == 8:
        pytest.skip("la fixture resultó estar comprimida")
    with pytest.raises(ValueError, match="deflate"):
        modo_y_hash(entry)


def test_integracion_real_con_hashcat_zipcrypto(
    zip_zipcrypto_deflate, tmp_path, hashcat_real, clave
):
    """La cadena completa contra hashcat de verdad, modo 17200."""
    lista = tmp_path / "lista.txt"
    lista.write_text(f"uno\ndos\n{clave}\ntres\n", encoding="utf-8")

    entry = _entrada_zc(zip_zipcrypto_deflate)
    clave_encontrada = hashcat_attack(
        entry,
        wordlist=str(lista),
        hashcat_path=hashcat_real,
        workdir=str(tmp_path / "w"),
        timeout=600,
    )
    assert clave_encontrada == clave

    # y lo que devuelve hashcat se confirma con el verificador propio
    from zipaes.zipcrypto import verify as zc_verify

    assert zc_verify(entry, clave_encontrada)
