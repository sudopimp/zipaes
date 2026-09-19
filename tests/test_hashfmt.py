"""Emisión del hash $zip2$ y avisos de estrategia."""

from __future__ import annotations

import pytest

from zipaes import (
    HASHCAT_MODE,
    HASHCAT_MODE_ZIPCRYPTO,
    check_hash_format,
    emit_hash,
    emit_hash_line,
    emit_pkzip2,
    inspect,
)
from zipaes.hashfmt import sanity_check
from zipaes.testkit import write_aes_zip


def test_el_modo_de_hashcat_es_el_correcto():
    assert HASHCAT_MODE == 13600


def test_el_modo_de_zipcrypto_es_el_correcto():
    assert HASHCAT_MODE_ZIPCRYPTO == 17200


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


# --- $pkzip2$ (ZipCrypto) --------------------------------------------------- #


def _entrada_zc(ruta, indice=0):
    import zipfile

    from zipaes.zipcrypto import parse_zipcrypto_entry

    with zipfile.ZipFile(ruta) as archivo, open(ruta, "rb") as handle:
        info = archivo.infolist()[indice]
        return parse_zipcrypto_entry(handle, info, csize=info.compress_size, usize=info.file_size)


def test_pkzip2_estructura_del_hash(zip_zipcrypto_deflate):
    line = emit_pkzip2(_entrada_zc(zip_zipcrypto_deflate))
    assert line.startswith("$pkzip2$")
    assert line.endswith("$/pkzip2$")

    campos = line.split("*")
    assert campos[0] == "$pkzip2$1"  # firma + cantidad de hashes
    assert campos[1] == "1"  # largos de checksum
    assert campos[2] == "2"  # tipo de datos
    assert campos[3] == "0"  # tipo de magic
    assert campos[9] == "8"  # compresión: deflate, obligatorio
    assert campos[14] == "$/pkzip2$"


def test_pkzip2_los_checksums_van_desplazados(zip_zipcrypto_deflate):
    """El byte de control va en el byte ALTO del campo, no en el bajo.

    El kernel compara contra `checksum_from_crc >> 8`. Ponerlo en el byte bajo —que es lo
    intuitivo— produce un hash que hashcat acepta y nunca rompe.
    """
    entry = _entrada_zc(zip_zipcrypto_deflate)
    campos = emit_pkzip2(entry).split("*")

    assert int(campos[11], 16) == (entry.crc >> 16) & 0xFFFF
    assert int(campos[12], 16) == entry.dos_time & 0xFFFF
    # y el byte alto es, literalmente, el byte de control del formato
    assert entry.check_byte() in (int(campos[11], 16) >> 8, int(campos[12], 16) >> 8)


def test_pkzip2_los_datos_empiezan_con_la_cabecera_de_cifrado(zip_zipcrypto_deflate):
    entry = _entrada_zc(zip_zipcrypto_deflate)
    campos = emit_pkzip2(entry).split("*")
    datos = bytes.fromhex(campos[13])
    assert datos[:12] == entry.crypt_header
    assert datos[12:] == entry.data
    assert int(campos[10], 16) == len(datos)  # largo declarado == largo real


def test_pkzip2_los_largos_son_los_de_la_entrada(zip_zipcrypto_deflate):
    entry = _entrada_zc(zip_zipcrypto_deflate)
    campos = emit_pkzip2(entry).split("*")
    assert int(campos[4], 16) == entry.csize
    assert int(campos[5], 16) == entry.usize
    assert int(campos[6], 16) == entry.crc


def test_pkzip2_rechaza_entradas_almacenadas(zip_zipcrypto):
    """Sin deflate no hay kernel: hay que decirlo, no emitir un hash inútil."""
    entry = _entrada_zc(zip_zipcrypto)
    if entry.compression == 8:
        pytest.skip("la fixture resultó estar comprimida")
    with pytest.raises(ValueError, match="deflate"):
        emit_pkzip2(entry)


def test_pkzip2_rechaza_entradas_demasiado_grandes(zip_zipcrypto_deflate):
    with pytest.raises(ValueError, match="no se puede recortar"):
        emit_pkzip2(_entrada_zc(zip_zipcrypto_deflate), max_data=10)


def test_pkzip2_con_prefijo_de_nombre(zip_zipcrypto_deflate):
    entry = _entrada_zc(zip_zipcrypto_deflate)
    line = emit_pkzip2(entry, prefix_name=True)
    assert line.startswith(f"{entry.name}:$pkzip2$")


def test_pkzip2_no_es_el_hash_de_aes(zip_zipcrypto_deflate):
    assert "$zip2$" not in emit_pkzip2(_entrada_zc(zip_zipcrypto_deflate))


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
