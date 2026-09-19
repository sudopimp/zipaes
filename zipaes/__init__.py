"""zipaes — auditoría y recuperación de archivos ZIP con cifrado AES (WinZip).

La biblioteca estándar de Python no puede abrir zips con cifrado AES: ``zipfile``
informa ``RuntimeError: ... is encrypted`` y las herramientas ``unzip`` suelen fallar
igual. Este paquete sí puede, porque implementa el formato directamente.

Capacidades:

* identificar el tipo de cifrado de cada entrada del archivo;
* verificar una contraseña de forma concluyente (recalculando el auth code);
* emitir el hash ``$zip2$`` para hashcat (modo 13600) o John the Ripper;
* atacar por diccionario en paralelo con el verificador propio;
* extraer el contenido una vez recuperada la contraseña;
* autocomprobarse de punta a punta con un archivo de contraseña conocida.

Uso responsable: pensado para recuperar **tus propios** archivos o aquellos sobre los
que tengas autorización explícita. Ver ``docs/ETICA-Y-LEGAL.md``.
"""

from __future__ import annotations

__version__ = "1.1.1"

from .candidates import (  # noqa: E402
    MarkovModel,
    build_candidates,
    compose,
    leet,
    mangle,
    train,
    years,
)
from .crack import build_wordlist, crack, crack_entry  # noqa: E402
from .crypto import (  # noqa: E402
    WrongPassword,
    decrypt_ciphertext,
    derive_keys,
    keystream,
    recover_plaintext,
    verify,
)
from .extract import extract_all, extract_entry, list_entries, safe_join  # noqa: E402
from .format import (  # noqa: E402
    AesEntry,
    ArchiveReport,
    NotAesError,
    NotEncryptedError,
    UnsupportedZipError,
    detect_zip64,
    has_zip64_extra,
    inspect,
    looks_like_zip,
    parse_entry,
)
from .hashfmt import HASHCAT_MODE, emit_hash, emit_hash_line, sanity_check  # noqa: E402
from .selftest import check_hash_format, run_selftest  # noqa: E402
from .testkit import write_aes_zip  # noqa: E402
from .zipcrypto import (  # noqa: E402
    ZipCryptoEntry,
    ZipCryptoKeys,
    parse_zipcrypto_entry,
)

__all__ = [
    "__version__",
    # formato
    "AesEntry",
    "ArchiveReport",
    "inspect",
    "parse_entry",
    "looks_like_zip",
    "detect_zip64",
    "has_zip64_extra",
    "NotAesError",
    "NotEncryptedError",
    "UnsupportedZipError",
    # cripto AES
    "derive_keys",
    "keystream",
    "decrypt_ciphertext",
    "recover_plaintext",
    "verify",
    "WrongPassword",
    # ZipCrypto
    "ZipCryptoEntry",
    "ZipCryptoKeys",
    "parse_zipcrypto_entry",
    # hash
    "emit_hash",
    "emit_hash_line",
    "sanity_check",
    "HASHCAT_MODE",
    # ataque
    "crack",
    "crack_entry",
    "build_wordlist",
    # candidatos
    "MarkovModel",
    "train",
    "mangle",
    "leet",
    "compose",
    "years",
    "build_candidates",
    # extraccion
    "extract_all",
    "extract_entry",
    "list_entries",
    "safe_join",
    # pruebas / autocomprobacion
    "write_aes_zip",
    "run_selftest",
    "check_hash_format",
]
