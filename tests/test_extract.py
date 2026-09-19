"""Extracción y seguridad de rutas."""

from __future__ import annotations

import os

import pytest

from zipaes import extract_all, extract_entry, inspect, safe_join
from zipaes.crypto import WrongPassword
from zipaes.testkit import write_aes_zip


def test_extrae_todo_el_contenido(zip_aes256, clave, contenido, tmp_path):
    destino = tmp_path / "salida"
    result = extract_all(zip_aes256, clave, str(destino))
    assert result.ok
    assert sorted(result.written) == sorted(contenido)
    for nombre, esperado in contenido.items():
        archivo = destino / nombre
        assert archivo.is_file()
        assert archivo.read_bytes() == esperado


def test_respeta_la_estructura_de_carpetas(zip_aes256, clave, tmp_path):
    destino = tmp_path / "salida"
    extract_all(zip_aes256, clave, str(destino))
    assert (destino / "carpeta" / "interno.json").is_file()


def test_contrasena_incorrecta_levanta_error(zip_aes256, tmp_path):
    with pytest.raises(WrongPassword):
        extract_all(zip_aes256, "no-es", str(tmp_path / "salida"))


def test_extrae_un_solo_archivo(zip_aes256, clave, tmp_path):
    entry = inspect(zip_aes256).aes[0]
    destino = tmp_path / "uno.txt"
    contenido = extract_entry(entry, clave, str(destino))
    assert destino.read_bytes() == contenido


def test_deflate_se_descomprime(tmp_path, clave):
    ruta = str(tmp_path / "z.zip")
    original = b"contenido repetitivo " * 200
    write_aes_zip(ruta, {"grande.txt": original}, clave, compression=8)
    entry = inspect(ruta).aes[0]
    assert entry.compression == 8
    assert entry.csize < len(original)  # se comprimió de verdad
    result = extract_all(ruta, clave, str(tmp_path / "salida"))
    assert (tmp_path / "salida" / "grande.txt").read_bytes() == original
    assert result.ok


def test_binario_sin_perdidas(zip_aes256, clave, tmp_path):
    extract_all(zip_aes256, clave, str(tmp_path / "salida"))
    assert (tmp_path / "salida" / "binario.dat").read_bytes() == bytes(range(256))


def test_ae1_se_extrae(tmp_path, clave):
    ruta = str(tmp_path / "ae1.zip")
    write_aes_zip(ruta, {"a.txt": b"datos"}, clave, aes_version=1)
    resultado = extract_all(ruta, clave, str(tmp_path / "salida"))
    assert resultado.ok
    assert (tmp_path / "salida" / "a.txt").read_bytes() == b"datos"


def test_archivo_zip_sin_cifrar_se_saltea(zip_sin_cifrar, clave, tmp_path):
    result = extract_all(zip_sin_cifrar, clave, str(tmp_path / "salida"))
    assert result.ok
    assert result.written == []
    assert result.skipped == ["hola.txt"]


# --- seguridad de rutas ---------------------------------------------------- #


def test_safe_join_permite_rutas_internas(tmp_path):
    assert safe_join(str(tmp_path), "a/b.txt").startswith(str(tmp_path))


def test_safe_join_bloquea_escape_con_punto_punto(tmp_path):
    with pytest.raises(ValueError):
        safe_join(str(tmp_path), "../../etc/passwd")


def test_safe_join_bloquea_ruta_absoluta(tmp_path):
    with pytest.raises(ValueError):
        safe_join(str(tmp_path), "/etc/passwd")


def test_un_zip_malicioso_no_escribe_fuera_del_destino(tmp_path):
    """Un nombre de entrada con traversal no debe escapar del directorio destino."""
    ruta = str(tmp_path / "malo.zip")
    write_aes_zip(ruta, {"../../fuera.txt": b"no deberia escribirse"}, "clave")
    destino = tmp_path / "salida"
    result = extract_all(ruta, "clave", str(destino))
    assert not result.ok
    assert result.failed
    assert not os.path.exists(tmp_path.parent / "fuera.txt")
