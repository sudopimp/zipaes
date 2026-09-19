"""Fixtures compartidas.

Todos los archivos de prueba se generan con ``zipaes.testkit``: el paquete se
autocomprueba sin depender de herramientas externas. Cuando 7-Zip está disponible, las
pruebas de interoperabilidad se activan; si no, se omiten.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from zipaes.testkit import write_aes_zip

#: contraseña de las fixtures. Material de prueba, no protege nada.
PASSWORD = "clave-de-prueba"

CONTENIDO = {
    "hola.txt": b"contenido de prueba\n",
    "carpeta/interno.json": b'{"a": 1}\n',
    "binario.dat": bytes(range(256)),
}


@pytest.fixture
def clave() -> str:
    """Contraseña de las fixtures."""
    return PASSWORD


@pytest.fixture
def contenido() -> dict:
    """Archivos y bytes esperados de las fixtures."""
    return CONTENIDO


@pytest.fixture
def zip_aes256(tmp_path):
    """Zip AE-2 / AES-256 / store con contraseña conocida."""
    path = tmp_path / "aes256.zip"
    write_aes_zip(str(path), CONTENIDO, PASSWORD, strength=3, aes_version=2)
    return str(path)


@pytest.fixture
def zip_ae1(tmp_path):
    """Zip AE-1 (valor de verificación de 1 byte) con contraseña conocida."""
    path = tmp_path / "ae1.zip"
    write_aes_zip(str(path), CONTENIDO, PASSWORD, strength=3, aes_version=1)
    return str(path)


@pytest.fixture
def zip_deflate(tmp_path):
    """Zip AES-256 con compresión deflate."""
    path = tmp_path / "deflate.zip"
    write_aes_zip(str(path), CONTENIDO, PASSWORD, strength=3, compression=8)
    return str(path)


@pytest.fixture
def zip_sin_cifrar(tmp_path):
    """Zip normal, sin cifrado (para comprobar que el paquete lo detecta)."""
    import zipfile

    path = tmp_path / "plano.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("hola.txt", "contenido\n")
    return str(path)


@pytest.fixture
def zip_zipcrypto(tmp_path):
    """Zip con cifrado tradicional (ZipCrypto): método 1 y bit de cifrado activo.

    No se construye con ``zipfile`` porque la biblioteca estándar no sabe escribir
    archivos cifrados; se arma el formato a mano, que es justo lo que hace falta para
    comprobar la clasificación.
    """
    import struct
    import zlib

    nombre = b"hola.txt"
    claro = b"contenido cifrado con zipcrypto\n"
    falso = bytes(range(12))  # 12 bytes "cifrados" de mentira
    crc = zlib.crc32(claro) & 0xFFFFFFFF
    salida = bytearray()

    salida += struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20,
        0x0001,
        1,
        0,
        0,
        crc,
        len(falso),
        len(claro),
        len(nombre),
        0,
    )
    salida += nombre + falso
    cd_offset = len(salida)  # inicio del directorio central
    directorio = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0x0001,
            1,
            0,
            0,
            crc,
            len(falso),
            len(claro),
            len(nombre),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + nombre
    )
    salida += directorio
    salida += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(directorio), cd_offset, 0)

    path = tmp_path / "zipcrypto.zip"
    path.write_bytes(bytes(salida))
    return str(path)


@pytest.fixture(scope="session")
def tiene_7z() -> bool:
    return shutil.which("7z") is not None


@pytest.fixture
def zip_de_7z(tmp_path, tiene_7z):
    """Zip AES creado por 7-Zip, para probar interoperabilidad real."""
    if not tiene_7z:
        pytest.skip("7-Zip no está instalado")
    origen = tmp_path / "origen.txt"
    origen.write_text("texto creado por 7z\n", encoding="utf-8")
    destino = tmp_path / "7z.zip"
    subprocess.run(
        ["7z", "a", "-tzip", "-mem=AES256", f"-p{PASSWORD}", str(destino), str(origen)],
        check=True,
        capture_output=True,
    )
    return str(destino)
