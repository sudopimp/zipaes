"""Autocomprobación de punta a punta e interoperabilidad con 7-Zip."""

from __future__ import annotations

import subprocess

import pytest

from zipaes import check_hash_format, inspect, run_selftest, verify
from zipaes.testkit import write_aes_zip


@pytest.mark.parametrize("strength", [1, 2, 3])
def test_selftest_pasa_en_todas_las_fuerzas(strength):
    report = run_selftest(strength=strength)
    assert report["resultado"] == "ok", report["pasos"]
    assert all(paso["ok"] for paso in report["pasos"])


@pytest.mark.parametrize("aes_version", [1, 2])
def test_selftest_pasa_en_ambas_variantes(aes_version):
    report = run_selftest(aes_version=aes_version)
    assert report["resultado"] == "ok", report["pasos"]
    assert report["variante"] == f"AE-{aes_version}"


@pytest.mark.parametrize("compression", [0, 8])
def test_selftest_pasa_en_ambos_metodos(compression):
    report = run_selftest(compression=compression)
    assert report["resultado"] == "ok", report["pasos"]


def test_el_selftest_incluye_los_pasos_clave():
    nombres = {paso["paso"] for paso in run_selftest()["pasos"]}
    assert "formato $zip2$ valido para hashcat" in nombres
    assert "aceptar la clave correcta" in nombres
    assert "rechazar una clave incorrecta" in nombres
    assert "el contenido coincide byte a byte" in nombres


def test_el_validador_detecta_un_auth_code_corto():
    problemas = check_hash_format("$zip2$*0*3*0*" + "ab" * 16 + "*abcd*1*ff*abcd*$/zip2$", 3)
    assert any("auth code" in p for p in problemas)


# --- interoperabilidad con 7-Zip ------------------------------------------- #


def test_7z_puede_abrir_lo_que_escribe_el_kit(tmp_path, tiene_7z):
    """Si 7-Zip acepta nuestro archivo, el formato está bien construido."""
    if not tiene_7z:
        pytest.skip("7-Zip no está instalado")
    ruta = str(tmp_path / "nuestro.zip")
    write_aes_zip(ruta, {"a.txt": b"contenido"}, "clave-7z")
    proceso = subprocess.run(["7z", "t", "-pclave-7z", ruta], capture_output=True, text=True)
    assert proceso.returncode == 0, proceso.stdout + proceso.stderr


def test_el_paquete_abre_lo_que_escribe_7z(zip_de_7z, clave):
    report = inspect(zip_de_7z)
    assert report.aes
    entry = report.aes[0]
    assert entry.label == "AE-2"
    assert verify(entry, clave)
    assert not verify(entry, "otra")


def test_nuestro_hash_de_un_archivo_de_7z_es_valido(zip_de_7z, clave):
    from zipaes import emit_hash

    entry = inspect(zip_de_7z).aes[0]
    assert check_hash_format(emit_hash(entry), entry.strength) == []


def test_tambien_lee_un_zip_escrito_con_7z_y_deflate(tmp_path, tiene_7z):
    if not tiene_7z:
        pytest.skip("7-Zip no está instalado")
    origen = tmp_path / "texto.txt"
    origen.write_text("x" * 500, encoding="utf-8")
    destino = tmp_path / "deflate7z.zip"
    subprocess.run(
        ["7z", "a", "-tzip", "-mem=AES256", "-mx9", "-pclave2", str(destino), str(origen)],
        check=True,
        capture_output=True,
    )
    from zipaes import extract_all

    result = extract_all(str(destino), "clave2", str(tmp_path / "salida"))
    assert result.ok
    assert (tmp_path / "salida" / "texto.txt").read_text() == "x" * 500
