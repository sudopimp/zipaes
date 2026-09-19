"""Criptografía: derivación, keystream, verificación y descifrado."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from zipaes import decrypt_ciphertext, derive_keys, inspect, keystream, verify
from zipaes.crypto import AES_BLOCK, WrongPassword, recover_plaintext


def test_derive_keys_devuelve_las_tres_partes():
    salt = bytes(range(16))
    enc_key, mac_key, pv = derive_keys("clave", salt, 32, 2)
    assert len(enc_key) == 32
    assert len(mac_key) == 32
    assert len(pv) == 2
    assert enc_key != mac_key


def test_derive_keys_es_reproducible():
    salt = b"\x01" * 16
    assert derive_keys("clave", salt, 32) == derive_keys("clave", salt, 32)


def test_derive_keys_coincide_con_pbkdf2_de_la_biblioteca_estandar():
    """La derivación es PBKDF2-HMAC-SHA1 con 1000 iteraciones, sin secretos."""
    salt = b"0123456789abcdef"
    enc_key, mac_key, pv = derive_keys("clave", salt, 32, 2)
    esperado = hashlib.pbkdf2_hmac("sha1", b"clave", salt, 1000, 66)
    assert enc_key + mac_key + pv == esperado


def test_keystream_es_el_contador_little_endian_cifrado():
    """El contador arranca en 1 y es little-endian, no el CTR estándar."""
    enc_key = bytes(range(32))
    flujo = keystream(enc_key, AES_BLOCK * 3)
    encryptor = Cipher(algorithms.AES(enc_key), modes.ECB()).encryptor()
    esperado = encryptor.update(
        (1).to_bytes(16, "little") + (2).to_bytes(16, "little") + (3).to_bytes(16, "little")
    )
    assert flujo == esperado


def test_keystream_recorta_al_largo_pedido():
    enc_key = b"\x02" * 32
    assert len(keystream(enc_key, 5)) == 5
    assert keystream(enc_key, 0) == b""


def test_keystream_repetible():
    enc_key = b"\x03" * 32
    assert keystream(enc_key, 40) == keystream(enc_key, 40)


def test_descifrar_y_cifrar_son_inversos():
    enc_key = b"\x04" * 32
    claro = b"texto de prueba" * 10
    cifrado = decrypt_ciphertext(enc_key, claro)
    assert cifrado != claro
    assert decrypt_ciphertext(enc_key, cifrado) == claro


def test_verify_acepta_la_clave_correcta(zip_aes256, clave):
    entry = inspect(zip_aes256).aes[0]
    assert verify(entry, clave)


def test_verify_rechaza_una_clave_incorrecta(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    assert not verify(entry, "otra-cosa")
    assert not verify(entry, "")
    assert not verify(entry, "clave-de-prueb")


def test_verify_funciona_con_ae1(zip_ae1, clave):
    entry = inspect(zip_ae1).aes[0]
    assert entry.pv_len == 1
    assert verify(entry, clave)
    assert not verify(entry, "otra-cosa")


def test_recover_plaintext_devuelve_el_contenido(zip_aes256, clave):
    entry = inspect(zip_aes256).aes[0]
    assert recover_plaintext(entry, clave) == b"contenido de prueba\n"


def test_recover_plaintext_con_clave_incorrecta(zip_aes256):
    entry = inspect(zip_aes256).aes[0]
    with pytest.raises(WrongPassword):
        recover_plaintext(entry, "no-es")


def test_acepta_contrasenas_en_bytes(zip_aes256, clave):
    entry = inspect(zip_aes256).aes[0]
    assert verify(entry, clave.encode("utf-8"))


def test_acepta_contrasenas_unicode(tmp_path):
    from zipaes.testkit import write_aes_zip

    ruta = str(tmp_path / "unicode.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "contraseña-con-ñ-y-acentos")
    entry = inspect(ruta).aes[0]
    assert verify(entry, "contraseña-con-ñ-y-acentos")
    assert not verify(entry, "contrasena-con-n-y-acentos")
