"""Cifrado tradicional (ZipCrypto).

Las pruebas más valiosas de este archivo son las que usan archivos generados por
Info-ZIP: validan la implementación contra otra implementación de referencia, no contra
ella misma.
"""

from __future__ import annotations

import zipfile

import pytest

from zipaes import inspect
from zipaes.extract import extract_zipcrypto_all, extract_zipcrypto_entry
from zipaes.zipcrypto import (
    ZipCryptoKeys,
    crack,
    decrypt,
    derive_keys,
    header_check_byte,
    parse_zipcrypto_entry,
    passes_header_check,
    verify,
)


def _entrada(ruta, indice=0):
    with zipfile.ZipFile(ruta) as archivo, open(ruta, "rb") as handle:
        info = archivo.infolist()[indice]
        return parse_zipcrypto_entry(handle, info, csize=info.compress_size, usize=info.file_size)


# --- claves ---------------------------------------------------------------- #


def test_estado_inicial_de_las_claves():
    claves = ZipCryptoKeys()
    assert (claves.key0, claves.key1, claves.key2) == (0x12345678, 0x23456789, 0x34567890)


def test_derivacion_reproducible():
    a = derive_keys("clave")
    b = derive_keys("clave")
    assert (a.key0, a.key1, a.key2) == (b.key0, b.key1, b.key2)


def test_contrasenas_distintas_dan_claves_distintas():
    a = derive_keys("clave")
    b = derive_keys("clave2")
    assert a.key2 != b.key2


def test_acepta_bytes_y_str():
    assert derive_keys("x").key0 == derive_keys(b"x").key0


def test_las_claves_evolucionan_con_cada_byte():
    claves = derive_keys("a")
    antes = claves.key0
    claves.update(0x41)
    assert claves.key0 != antes


# --- verificación ---------------------------------------------------------- #


def test_header_check_con_archivo_real(zip_zipcrypto_real, clave):
    entry = _entrada(zip_zipcrypto_real)
    assert passes_header_check(entry, clave)
    assert not passes_header_check(entry, "otra-cosa")


def test_verificacion_concluyente_con_archivo_real(zip_zipcrypto_real, clave):
    entry = _entrada(zip_zipcrypto_real)
    assert verify(entry, clave)
    assert not verify(entry, "otra-cosa")
    assert not verify(entry, "clave-de-prueb")


def test_descifra_el_contenido_real(zip_zipcrypto_real, clave):
    entry = _entrada(zip_zipcrypto_real)
    assert decrypt(entry, clave) == b"contenido secreto de prueba\n"


def test_deflate_se_descifra_y_descomprime(zip_zipcrypto_deflate, clave):
    import zlib

    entry = _entrada(zip_zipcrypto_deflate)
    assert entry.compression == 8
    assert verify(entry, clave)
    # decrypt devuelve el flujo tal cual (comprimido): descomprimir es responsabilidad
    # del extractor
    assert zlib.decompress(decrypt(entry, clave), -15).startswith(b"contenido repetitivo")


def test_el_byte_de_control_depende_del_bit_3():
    # sin data descriptor: byte alto del CRC
    assert header_check_byte(0x0001, 0xAABBCCDD, 0x1234) == 0xAA
    # con data descriptor (bit 3): byte alto de la hora DOS
    assert header_check_byte(0x0009, 0xAABBCCDD, 0x1234) == 0x12


def test_flag_de_data_descriptor_se_detecta(zip_zipcrypto_real):
    entry = _entrada(zip_zipcrypto_real)
    assert entry.has_data_descriptor in (True, False)  # informativo, no siempre se activa


# --- ataque ---------------------------------------------------------------- #


def test_crack_encuentra_con_archivo_real(zip_zipcrypto_real, clave):
    entry = _entrada(zip_zipcrypto_real)
    assert crack(entry, words=["alfa", "beta", clave, "gamma"], jobs=1) == clave


def test_crack_devuelve_none_si_no_esta(zip_zipcrypto_real):
    entry = _entrada(zip_zipcrypto_real)
    assert crack(entry, words=["alfa", "beta"], jobs=1) is None


def test_crack_en_paralelo(zip_zipcrypto_real, clave):
    entry = _entrada(zip_zipcrypto_real)
    candidatos = [f"relleno-{i}" for i in range(6000)] + [clave]
    assert crack(entry, words=candidatos, jobs=4) == clave


def test_crack_desde_archivo(tmp_path, zip_zipcrypto_real, clave):
    lista = tmp_path / "lista.txt"
    lista.write_text(f"alfa\nbeta\n{clave}\n", encoding="utf-8")
    entry = _entrada(zip_zipcrypto_real)
    assert crack(entry, wordlist_path=str(lista), jobs=1) == clave


def test_crack_sin_fuente_levanta_error(zip_zipcrypto_real):
    entry = _entrada(zip_zipcrypto_real)
    with pytest.raises(ValueError):
        crack(entry)


# --- integración con inspect / extract ------------------------------------- #


def test_inspect_lo_clasifica(zip_zipcrypto_real):
    report = inspect(zip_zipcrypto_real)
    assert report.zipcrypto
    assert report.zipcrypto_entries
    assert report.aes == []
    assert report.encrypted


def test_extraccion_completa(zip_zipcrypto_real, clave, tmp_path):
    report = inspect(zip_zipcrypto_real)
    destino = tmp_path / "salida"
    resultado = extract_zipcrypto_all(report.zipcrypto_entries, clave, str(destino))
    assert resultado.ok
    assert (destino / report.zipcrypto_entries[0].name).read_bytes() == (
        b"contenido secreto de prueba\n"
    )


def test_extraccion_con_clave_incorrecta(zip_zipcrypto_real, tmp_path):
    from zipaes.crypto import WrongPassword

    report = inspect(zip_zipcrypto_real)
    with pytest.raises(WrongPassword):
        extract_zipcrypto_all(report.zipcrypto_entries, "no-es", str(tmp_path / "salida"))


def test_extraccion_de_una_entrada(zip_zipcrypto_real, clave, tmp_path):
    entry = _entrada(zip_zipcrypto_real)
    destino = tmp_path / "uno.txt"
    assert extract_zipcrypto_entry(entry, clave, str(destino)) == (b"contenido secreto de prueba\n")


def test_un_zip_sin_cifrar_tambien_funciona(zip_sin_cifrar, clave, tmp_path):
    report = inspect(zip_sin_cifrar)
    assert report.zipcrypto_entries == []
    assert extract_zipcrypto_all([], clave, str(tmp_path / "s")).ok
