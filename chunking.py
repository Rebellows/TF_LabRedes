"""
Segmentacao de arquivo em pacotes de dados, seguindo a semantica do
campo Length da especificacao:

  Length = 255  -> pacote intermediario; receiver bufferiza e aguarda.
  Length < 255  -> ultimo pacote do stream; receiver entrega o buffer (push).
  Length = 0    -> edge case: arquivo e multiplo exato de 255 bytes;
                   sinaliza fim de stream sem payload residual.
"""

from . import packet


def split_into_packets(data: bytes):
    """
    Recebe os bytes do arquivo e devolve uma lista de tuplas
    (payload, length) ja prontas para virar pacotes de dados.

    Regras:
      - Cada chunk cheio tem 255 bytes -> Length = 255 (intermediario).
      - Se o arquivo NAO e multiplo de 255, o ultimo chunk tem
        Length < 255 -> sinaliza fim de stream.
      - Se o arquivo E multiplo de 255 (e nao vazio), todos os chunks
        sao de 255 bytes (todos intermediarios), entao adicionamos um
        pacote terminador (b"", Length = 0).
      - Arquivo vazio -> um unico pacote (b"", Length = 0).
    """
    out = []

    if len(data) == 0:
        out.append((b"", 0))
        return out

    for i in range(0, len(data), packet.MAX_PAYLOAD):
        chunk = data[i:i + packet.MAX_PAYLOAD]
        out.append((chunk, len(chunk)))  # 255 se cheio, <255 se ultimo parcial

    if len(data) % packet.MAX_PAYLOAD == 0:
        # ultimo chunk tinha 255 bytes (intermediario); precisa de terminador
        out.append((b"", 0))

    return out


def is_terminator(length: int) -> bool:
    """True se este Length sinaliza fim de stream (push)."""
    return length < packet.MAX_PAYLOAD  # cobre tanto 0..254
