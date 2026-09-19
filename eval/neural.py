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

__all__ = [
    "generar_passgpt",
    "generar_passgpt_ordenado",
    "cargar_modelo",
    "MODELO_POR_DEFECTO",
]

MODELO_POR_DEFECTO = "javirandor/passgpt-10characters"

#: cuántos caracteres se consideran por expansión en el decodificado ordenado
RAMAS_POR_DEFECTO = 16

#: prefijos que se evalúan por pasada de GPU
LOTE_POR_DEFECTO = 2048


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


def _distribucion_siguiente(red, torch, dispositivo, prefijos: list[tuple[int, ...]]):
    """Log-probabilidades del próximo token para cada prefijo, en una sola pasada.

    El tensor exige que todas las secuencias midan lo mismo, así que los prefijos se agrupan
    por largo. Rellenar sería más simple pero **incorrecto** acá: GPT-2 usa embeddings de
    posición absolutos y aprendidos, así que el relleno corre las posiciones de los tokens
    reales y cambia la distribución. Agrupar no cuesta nada y es exacto.
    """
    salida: list = [None] * len(prefijos)
    orden = sorted(range(len(prefijos)), key=lambda indice: len(prefijos[indice]))

    inicio = 0
    while inicio < len(orden):
        largo = len(prefijos[orden[inicio]])
        fin = inicio
        while fin < len(orden) and len(prefijos[orden[fin]]) == largo:
            fin += 1

        grupo = [prefijos[indice] for indice in orden[inicio:fin]]
        with torch.no_grad():
            logits = red(torch.tensor(grupo, device=dispositivo)).logits[:, -1, :]
            distribucion = torch.log_softmax(logits.float(), dim=-1)
        for indice, fila in zip(orden[inicio:fin], distribucion, strict=True):
            salida[indice] = fila
        inicio = fin

    return torch.stack(salida)


def generar_passgpt_ordenado(
    limite: int,
    *,
    modelo: str = MODELO_POR_DEFECTO,
    ramas: int = RAMAS_POR_DEFECTO,
    lote: int = LOTE_POR_DEFECTO,
    max_len: int = 12,
    dispositivo: str | None = None,
) -> Iterator[str]:
    """Enumera PassGPT **en orden decreciente de probabilidad**, sin samplear.

    Es el mismo recorrido mejor-primero que ``MarkovModel.iter_ordenado``, pero con el modelo
    neuronal como puntuador. La motivación está medida: PassGPT pierde contra la enumeración
    determinista **porque samplea**, no porque su distribución sea mala. Acá se enumera su
    distribución en vez de extraer de ella.

    Un prefijo es cota superior de todos sus descendientes (la probabilidad sólo baja al
    alargar), así que sacar de la cola en orden de probabilidad hace que lo emitido salga en
    ese mismo orden.

    La evaluación de los prefijos se hace **en lotes** para aprovechar la GPU. Eso vuelve el
    orden exacto en la cabeza —la parte que decide una recuperación— y aproximado donde los
    lotes se intercalan, que es una zona de probabilidad ya muy baja. Está declarado.
    """
    import heapq

    red, tokenizador, disp, torch = cargar_modelo(modelo, dispositivo=dispositivo)
    bos = tokenizador.bos_token_id
    eos = tokenizador.sep_token_id

    # la clave es -log P acumulada: el heap saca primero la secuencia más probable
    cola: list[tuple[float, tuple[int, ...]]] = [(0.0, (bos,))]
    emitidos = 0

    while cola and emitidos < limite:
        cuantos = min(lote, len(cola))
        actuales = [heapq.heappop(cola) for _ in range(cuantos)]
        prefijos = [prefijo for _, prefijo in actuales]

        distribuciones = _distribucion_siguiente(red, torch, disp, prefijos)
        mejores = distribuciones.topk(ramas, dim=-1)

        for (coste, prefijo), valores, indices in zip(
            actuales, mejores.values.tolist(), mejores.indices.tolist(), strict=True
        ):
            for logp, token in zip(valores, indices, strict=True):
                if logp <= -1e9:
                    continue
                nuevo_coste = coste - logp
                if token == eos:
                    candidato = tokenizador.decode(list(prefijo[1:])).split("</s>")[0]
                    if candidato:
                        # se emite al sacarlo de la cola, para respetar el orden global
                        heapq.heappush(cola, (nuevo_coste, (*prefijo, eos)))
                    continue
                if len(prefijo) < max_len:
                    heapq.heappush(cola, (nuevo_coste, (*prefijo, token)))

        # los que terminan se separan de los que siguen creciendo
        while cola and cola[0][1][-1] == eos:
            _, prefijo = heapq.heappop(cola)
            candidato = tokenizador.decode(list(prefijo[1:-1])).split("</s>")[0]
            if candidato:
                emitidos += 1
                yield candidato
                if emitidos >= limite:
                    return
