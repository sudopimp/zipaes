"""Emisión del hash $zip2$ y avisos de estrategia."""

from __future__ import annotations

import pytest

from zipaes import HASHCAT_MODE, check_hash_format, emit_hash, emit_hash_line, inspect
from zipaes.hashfmt import sanity_check
from zipaes.testkit import write_aes_zip


def test_el_modo_de_hashcat_es_el_correcto():
    assert HASHCAT_MODE == 13600


def test_estructura_del_hash(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    line = emit_hash(entry)
    tokens = line.split("*")
    assert tokens[0] == "$zip2$"
    assert tokens[-1] == "$/zip2$"
    assert tokens[1] == "0"  # tipo
    assert tokens[2] == "3"  # fuerza AES-256
    assert tokens[3] == "0"  # magic
    assert len(tokens) == 10


def test_el_salt_va_en_hex_del_largo_que_exige_hashcat(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    tokens = emit_hash(entry).split("*")
    assert tokens[4] == entry.salt.hex()
    assert len(tokens[4]) == 32  # AES-256 -> 16 bytes en hex


def test_el_auth_code_va_en_hex_de_20_caracteres(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    tokens = emit_hash(entry).split("*")
    assert tokens[8] == entry.auth_code.hex()
    assert len(tokens[8]) == 20


def test_el_largo_del_ciphertext_coincide(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    tokens = emit_hash(entry).split("*")
    assert int(tokens[6], 16) == entry.ct_len


def test_el_validador_acepta_un_hash_correcto(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    assert check_hash_format(emit_hash(entry), entry.strength) == []


def test_el_validador_rechaza_un_hash_roto(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    roto = emit_hash(entry).replace("$zip2$*0*3", "$zip2$*9*3")
    assert check_hash_format(roto, 3)
    assert check_hash_format("no-es-un-hash", 3)
    assert check_hash_format(emit_hash(entry).replace("$/zip2$", ""), 3)


def test_prefix_del_nombre(tmp_path, zip_aes256, clave):
    entry = inspect(zip_aes256).aes[0]
    line = emit_hash_line(entry, "/ruta/archivo.zip")
    assert line.startswith("/ruta/archivo.zip:$zip2$*")


def test_fuerzas_distintas_cambian_el_largo_del_salt(tmp_path):
    for strength, esperado in ((1, 16), (2, 24), (3, 32)):
        ruta = str(tmp_path / f"f{strength}.zip")
        write_aes_zip(ruta, {"a.txt": b"x"}, "clave", strength=strength)
        entry = inspect(ruta).aes[0]
        tokens = emit_hash(entry).split("*")
        assert len(tokens[4]) == esperado
        assert check_hash_format(emit_hash(entry), strength) == []
        # fuerza 1 = AES-128, 2 = AES-192, 3 = AES-256
        assert entry.keylen_bits == (strength + 1) * 64


def test_aviso_para_ae1(tmp_path):
    ruta = str(tmp_path / "ae1.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "clave", aes_version=1)
    avisos = sanity_check(inspect(ruta).aes[0])
    assert any("AE-1" in aviso for aviso in avisos)


def test_sin_avisos_para_ae2(zip_aes256):
    assert sanity_check(inspect(zip_aes256).aes[0]) == []


def test_rechaza_fuerza_invalida():
    from zipaes.format import AesEntry

    entry = AesEntry(
        name="x",
        header_offset=0,
        aes_version=2,
        strength=9,
        compression=0,
        crc=0,
        csize=0,
        usize=0,
        salt=b"",
        pv=b"",
        ciphertext=b"",
        auth_code=b"",
    )
    with pytest.raises(ValueError):
        emit_hash(entry)
