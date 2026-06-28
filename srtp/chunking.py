from . import packet

def split_into_packets(data: bytes):
    """Retorna uma lista de tuplas (bytes, length)."""
    out = []

    # Se o arquivo for vazio, precisa enviar um pacote de terminacao (payload vazio)
    if len(data) == 0:
        out.append((b"", 0))
        return out

    # Divide o arquivo em chunks de 255 bytes, cada um com seu tamanho (255 se cheio, <255 se ultimo parcial)
    for i in range(0, len(data), packet.MAX_PAYLOAD):
        chunk = data[i:i + packet.MAX_PAYLOAD]
        out.append((chunk, len(chunk)))  

    if len(data) % packet.MAX_PAYLOAD == 0:
        # ultimo chunk tinha 255 bytes (intermediario); precisa de terminador
        out.append((b"", 0))

    return out
