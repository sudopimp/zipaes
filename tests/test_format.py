"""Detección y parseo del formato."""

from __future__ import annotations

import zipfile

import pytest

from zipaes import inspect, looks_like_zip, parse_entry
from zipaes.format import (
    AUTH_CODE_LEN,
    NotAesError,
    NotEncryptedError,
    has_zip64_extra,
    salt_len_for,
)


def test_detecta_entradas_aes(zip_aes256):
    report = inspect(zip_aes256)
    assert len(report.aes) == 3
    assert report.encrypted
    assert report.total == 3


def test_lee_salt_pv_y_auth_code(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    assert len(entry.salt) == salt_len_for(3) == 16
    assert entry.salt_len == 16
    assert len(entry.auth_code) == AUTH_CODE_LEN
    assert entry.pv_len == 2
    assert entry.keylen_bits == 256
    assert entry.label == "AE-2"
    assert entry.ciphertext


def test_el_salt_depende_de_la_fuerza(tmp_path):
    from zipaes.testkit import write_aes_zip

    for strength, esperado in ((1, 8), (2, 12), (3, 16)):
        ruta = str(tmp_path / f"s{strength}.zip")
        write_aes_zip(ruta, {"a.txt": b"x"}, "clave", strength=strength)
        entry = inspect(ruta).aes[0]
        assert entry.salt_len == esperado
        assert entry.salt_len == salt_len_for(strength)


def test_ae1_usa_un_byte_de_verificacion(zip_ae1):
    entry = inspect(zip_ae1).aes[0]
    assert entry.aes_version == 1
    assert entry.pv_len == 1
    assert entry.label == "AE-1"


def test_reconoce_zip_sin_cifrar(zip_sin_cifrar):
    report = inspect(zip_sin_cifrar)
    assert not report.encrypted
    assert report.plain == ["hola.txt"]
    assert report.aes == []


def test_entrada_plana_levanta_not_encrypted(zip_sin_cifrar):
    with zipfile.ZipFile(zip_sin_cifrar) as archive, open(zip_sin_cifrar, "rb") as handle:
        info = archive.infolist()[0]
        with pytest.raises(NotEncryptedError):
            parse_entry(handle, info)


def test_entrada_no_aes_levanta_not_aes(zip_aes256, tmp_path):
    import struct

    from zipaes.format import EXTRA_AES

    with zipfile.ZipFile(zip_aes256) as archive, open(zip_aes256, "rb") as handle:
        info = archive.infolist()[0]
        # un extra field con el id de AES pero vendor distinto no debe aceptarse
        extra = struct.pack("<HH", EXTRA_AES, 7) + struct.pack("<H2sBH", 2, b"XX", 3, 0)
        info.extra = extra
        with pytest.raises(NotAesError):
            parse_entry(handle, info)


def test_el_resumen_tiene_los_campos_esperados(zip_aes256):
    summary = inspect(zip_aes256).summary()
    assert summary["aes"] == 3
    assert summary["entradas"] == 3
    assert summary["primera_entrada_aes"]


def test_looks_like_zip(tmp_path, zip_aes256):
    assert looks_like_zip(zip_aes256)
    assert not looks_like_zip(str(tmp_path / "no-existe.zip"))
    falso = tmp_path / "falso.zip"
    falso.write_bytes(b"no soy un zip")
    assert not looks_like_zip(str(falso))


def test_detecta_el_metodo_de_compresion(zip_deflate):
    entry = inspect(zip_deflate).aes[0]
    assert entry.compression == 8


# --- ZIP64 ----------------------------------------------------------------- #


def test_has_zip64_extra_detecta_el_extra_field():
    import struct

    info = zipfile.ZipInfo("x")
    info.extra = struct.pack("<HH", 0x0001, 8) + b"\x00" * 8
    assert has_zip64_extra(info)


def test_has_zip64_extra_ignora_otros_extra_fields():
    import struct

    from zipaes.format import EXTRA_AES

    info = zipfile.ZipInfo("x")
    # el extra field de AES (0x9901) no debe confundirse con ZIP64
    info.extra = struct.pack("<HH", EXTRA_AES, 7) + struct.pack("<H2sBH", 2, b"AE", 3, 0)
    assert not has_zip64_extra(info)
    info.extra = b""
    assert not has_zip64_extra(info)


def test_un_zip_normal_no_se_marca_como_zip64(zip_aes256):
    report = inspect(zip_aes256)
    assert report.zip64 is False
    assert report.zip64_entries == 0
    assert report.summary()["zip64_entradas"] == 0
