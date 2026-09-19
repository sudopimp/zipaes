"""Comportamiento del CLI: códigos de salida y formatos."""

from __future__ import annotations

import json

import pytest

from zipaes import __version__
from zipaes.cli import main
from zipaes.testkit import write_aes_zip


def test_version(capsys):
    with pytest.raises(SystemExit) as salida:
        main(["--version"])
    assert salida.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_selftest_sale_cero(capsys):
    assert main(["selftest"]) == 0
    assert "OK" in capsys.readouterr().out


def test_selftest_json(capsys):
    assert main(["--json", "selftest"]) == 0
    informe = json.loads(capsys.readouterr().out)
    assert informe["resultado"] == "ok"
    assert informe["pasos"]


def test_info_muestra_el_panorama(zip_aes256, capsys):
    assert main(["info", zip_aes256]) == 0
    salida = capsys.readouterr().out
    assert "ae" in salida.lower()
    assert "AES-256" in salida


def test_info_json(zip_aes256, capsys):
    assert main(["--json", "info", zip_aes256]) == 0
    datos = json.loads(capsys.readouterr().out)
    assert datos["aes"] == 3
    assert datos["detalle"]


def test_verify_correcta(zip_aes256, clave, capsys):
    assert main(["verify", zip_aes256, "-p", clave]) == 0
    assert "valida: si" in capsys.readouterr().out


def test_verify_incorrecta(zip_aes256, capsys):
    assert main(["verify", zip_aes256, "-p", "no-es"]) == 2
    assert "valida: no" in capsys.readouterr().out


def test_hash_emite_linea_valida(zip_aes256, capsys):
    assert main(["hash", zip_aes256]) == 0
    salida = capsys.readouterr().out.strip()
    assert "$zip2$*0*3*0*" in salida
    assert salida.endswith("$/zip2$")


def test_hash_todos(zip_aes256, capsys):
    assert main(["hash", zip_aes256, "--todos"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 3


def test_hash_json(zip_aes256, capsys):
    assert main(["--json", "hash", zip_aes256]) == 0
    datos = json.loads(capsys.readouterr().out)
    assert datos["hashcat_modo"] == 13600
    assert datos["hashes"]


def test_hash_avisa_sobre_ae1(zip_ae1, capsys):
    assert main(["hash", zip_ae1, "--avisos"]) == 0
    assert "AE-1" in capsys.readouterr().err


def test_crack_encuentra(tmp_path, clave, capsys):
    ruta = str(tmp_path / "x.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "objetivo")
    assert main(["crack", ruta, "--palabras", "uno", "dos", "objetivo"]) == 0
    assert "encontrada: si" in capsys.readouterr().out


def test_crack_no_encuentra(tmp_path, capsys):
    ruta = str(tmp_path / "x.zip")
    write_aes_zip(ruta, {"a.txt": b"x"}, "objetivo")
    assert main(["crack", ruta, "--palabras", "uno", "dos"]) == 0
    assert "encontrada: no" in capsys.readouterr().out


def test_crack_sin_fuente_es_error_de_uso(zip_aes256, capsys):
    assert main(["crack", zip_aes256]) == 1
    assert "wordlist" in capsys.readouterr().err


def test_extract_ok(zip_aes256, clave, tmp_path, capsys):
    destino = tmp_path / "salida"
    assert main(["extract", zip_aes256, "-p", clave, "-o", str(destino)]) == 0
    assert "extraidos: 3" in capsys.readouterr().out
    assert (destino / "hola.txt").is_file()


def test_extract_con_clave_mala(zip_aes256, tmp_path, capsys):
    assert main(["extract", zip_aes256, "-p", "no", "-o", str(tmp_path / "s")]) == 2
    assert "no verifica" in capsys.readouterr().err


def test_wordlist_genera_archivo(tmp_path, capsys):
    destino = tmp_path / "lista.txt"
    assert main(["wordlist", "-o", str(destino), "fer", "test"]) == 0
    contenido = destino.read_text(encoding="utf-8").splitlines()
    assert "fer" in contenido
    assert "FER123" in contenido


def test_archivo_inexistente(tmp_path, capsys):
    assert main(["info", str(tmp_path / "no.zip")]) == 1
    assert "no existe" in capsys.readouterr().err


def test_archivo_que_no_es_zip(tmp_path, capsys):
    falso = tmp_path / "falso.zip"
    falso.write_bytes(b"no soy zip")
    assert main(["info", str(falso)]) == 1
    assert "no parece un zip" in capsys.readouterr().err


def test_zip_sin_cifrar_avisa(zip_sin_cifrar, capsys):
    assert main(["info", zip_sin_cifrar]) == 1
    assert "no esta cifrado" in capsys.readouterr().err


def test_zip_zipcrypto_se_informa_como_tal(zip_zipcrypto, capsys):
    """ZipCrypto ya no es un caso derivado: se informa y se puede atacar."""
    assert main(["info", zip_zipcrypto]) == 0
    salida = capsys.readouterr().out
    assert "tipo: ZIPCRYPTO" in salida
    assert "formato=ZipCrypto" in salida


def test_hash_sobre_zipcrypto_almacenado_avisa(zip_zipcrypto, capsys):
    """El modo 17200 sólo ataca deflate: en una entrada almacenada hay que decirlo."""
    assert main(["hash", zip_zipcrypto]) == 1
    error = capsys.readouterr().err
    assert "deflate" in error


def test_hash_sobre_zipcrypto_deflate_emite_pkzip2(zip_zipcrypto_deflate, capsys):
    """Con deflate sí hay hash que emitir, y no es el de AES."""
    assert main(["hash", zip_zipcrypto_deflate]) == 0
    salida = capsys.readouterr().out.strip()
    assert salida.startswith("$pkzip2$")
    assert salida.endswith("$/pkzip2$")
    assert "$zip2$" not in salida


def test_hash_zipcrypto_en_json(zip_zipcrypto_deflate, capsys):
    import json

    assert main(["--json", "hash", zip_zipcrypto_deflate]) == 0
    datos = json.loads(capsys.readouterr().out)
    assert datos["hashcat_modo"] == 17200
    assert datos["hashes"][0].startswith("$pkzip2$")


def test_backend_lista_las_herramientas(capsys):
    assert main(["backend"]) == 0
    salida = capsys.readouterr().out
    assert "disponibles" in salida or "ausentes" in salida


def test_zip_zipcrypto_se_clasifica_como_tal(zip_zipcrypto):
    from zipaes import inspect

    report = inspect(zip_zipcrypto)
    assert report.zipcrypto == ["hola.txt"]
    assert report.aes == []
    assert report.encrypted


def test_archivo_corrupto_no_revienta(tmp_path, capsys):
    roto = tmp_path / "roto.zip"
    roto.write_bytes(b"PK\x03\x04" + b"\x00" * 20)
    assert main(["info", str(roto)]) == 1
    assert capsys.readouterr().err
