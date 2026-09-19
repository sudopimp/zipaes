"""Generador neuronal: PassGPT, el modelo publicado, sin reentrenar nada.

`javirandor/passgpt-10characters` es el modelo del paper *PassGPT: Password Modeling and
(Guided) Generation with Large Language Models* (Rando, Perez-Cruz, Hitaj — arXiv:2306.01545),
publicado por sus autores en HuggingFace. Es un GPT-2 entrenado sobre filtraciones de
contraseñas, y es la referencia de generación neuronal en esta área.

Dos cosas que conviene tener claras antes de mirar los números:

- **Sólo produce contraseñas de hasta 10 caracteres** (de ahí el nombre). La versión de 16
  requiere aprobación de los autores. Por eso su curva se mide sobre el subconjunto del test
  con esa longitud, y se reporta aparte.
- **Fue entrenado sobre datos derivados de RockYou**, que es el mismo corpus que usamos para
  evaluar. Eso significa que la partición de test puede estar parcialmente memorizada por el
  modelo, y su ventaja puede estar inflada por memorización en vez de por generalización. Está
  declarado en el informe, y por eso el `eval` incluye la variante con filtro de longitud, que
  hace imposible la memorización de la cadena completa.

Torch no es una dependencia del paquete: se importa sólo si se usa este módulo.
"""

from __future__ import annotations

from collections.abc import Iterator

__all__ = ["generar_passgpt", "cargar_modelo", "MODELO_POR_DEFECTO"]

MODELO_POR_DEFECTO = "javirandor/passgpt-10characters"


def cargar_modelo(nombre: str = MODELO_POR_DEFECTO, *, dispositivo: str | None = None):
    """Carga el tokenizador y el modelo, en GPU si hay."""
    try:
        import torch
        from transformers import GPT2LMHeadModel, RobertaTokenizerFast
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise RuntimeError(
            "hace falta torch y transformers para el generador neuronal: pip install -e '.[eval]'"
        ) from exc

    tokenizador = RobertaTokenizerFast.from_pretrained(
        nombre,
        max_len=12,
        padding="max_length",
        truncation=True,
        do_lower_case=False,
        strip_accents=False,
        mask_token="<mask>",
        unk_token="<unk>",
        pad_token="<pad>",
        truncation_side="right",
    )
    modelo = GPT2LMHeadModel.from_pretrained(nombre).eval()

    if dispositivo is None:
        dispositivo = "cuda" if torch.cuda.is_available() else "cpu"
    modelo.to(dispositivo)

    return modelo, tokenizador, dispositivo, torch


def generar_passgpt(
    limite: int,
    *,
    modelo: str = MODELO_POR_DEFECTO,
    lote: int = 4096,
    dispositivo: str | None = None,
) -> Iterator[str]:
    """Samplea contraseñas del modelo, en lotes, hasta ``limite`` candidatos.

    El muestreo es estocástico igual que en el paper: no hay un orden de prioridad intrínseco,
    así que la curva se lee como "cuántas se recuperan en los primeros N muestreos".
    """
    red, tokenizador, disp, torch = cargar_modelo(modelo, dispositivo=dispositivo)

    generados = 0
    arranque = torch.tensor([[tokenizador.bos_token_id]], device=disp)

    while generados < limite:
        cuantos = min(lote, limite - generados)
        salida = red.generate(
            arranque,
            do_sample=True,
            num_return_sequences=cuantos,
            max_length=12,
            pad_token_id=tokenizador.pad_token_id,
            bad_words_ids=[[tokenizador.bos_token_id]],
        )
        salida = salida[:, 1:]
        decodificadas = tokenizador.batch_decode(salida.tolist())
        for cruda in decodificadas:
            candidato = cruda.split("</s>")[0]
            if candidato:
                generados += 1
                yield candidato
                if generados >= limite:
                    return
