"""
Definicao do pacote RTP (Simple Reliable Transport Protocol).

Cabecalho de 9 bytes:

     0                   1                   2
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
    |S|F|     SEQ (14 bits)     |A|N|     ACK (14 bits)    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
    |   Length (8 bits)    |          CRC32 (32 bits)      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...

Os 4 primeiros bytes formam uma palavra de 32 bits (big-endian):
    bit 0 (MSB) : SYN
    bit 1       : FIN
    bits 2..15  : SEQ (14 bits)
    bit 16      : ACK flag
    bit 17      : NACK
    bits 18..31 : ACK (14 bits)
Em seguida: Length (1 byte) e CRC32 (4 bytes). Total = 4 + 1 + 4 = 9 bytes.
"""

import struct
import zlib
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constantes do protocolo
# ---------------------------------------------------------------------------
HEADER_SIZE = 9            # tamanho do cabecalho em bytes
MAX_PAYLOAD = 255          # bytes de payload por pacote de dados (cheio)
SEQ_BITS = 14              # espaco de numero de sequencia
SEQ_SPACE = 1 << SEQ_BITS  # 16384 -> valores 0..16383
SEQ_MASK = SEQ_SPACE - 1   # 0x3FFF
TIMEOUT = 0.1              # 100 ms, timeout fixo de retransmissao

# Formato struct: palavra de 32 bits + Length (1 byte) + CRC32 (4 bytes), big-endian
_STRUCT_FMT = ">IBI"


def _pack_word(seq, ack, syn, fin, ack_flag, nack):
    """Monta a palavra de 32 bits com os campos do cabecalho."""
    return (
        ((syn & 1) << 31)
        | ((fin & 1) << 30)
        | ((seq & SEQ_MASK) << 16)
        | ((ack_flag & 1) << 15)
        | ((nack & 1) << 14)
        | (ack & SEQ_MASK)
    )


def _make_header(seq, ack, syn, fin, ack_flag, nack, length, crc):
    word = _pack_word(seq, ack, syn, fin, ack_flag, nack)
    return struct.pack(_STRUCT_FMT, word, length & 0xFF, crc & 0xFFFFFFFF)


@dataclass
class Packet:
    """Representa um pacote RTP ja decodificado."""
    seq: int = 0
    ack: int = 0
    syn: int = 0
    fin: int = 0
    ack_flag: int = 0
    nack: int = 0
    length: int = 0
    crc: int = 0
    payload: bytes = b""
    valid: bool = True   # CRC32 confere?

    def to_bytes(self):
        """Serializa o pacote, calculando o CRC32 sobre cabecalho+payload."""
        # 1) cabecalho com campo CRC zerado
        header_zero = _make_header(
            self.seq, self.ack, self.syn, self.fin,
            self.ack_flag, self.nack, self.length, crc=0,
        )
        # 2) CRC32 sobre (cabecalho zerado || payload)
        crc = zlib.crc32(header_zero + self.payload) & 0xFFFFFFFF
        # 3) cabecalho definitivo com o CRC correto
        header = _make_header(
            self.seq, self.ack, self.syn, self.fin,
            self.ack_flag, self.nack, self.length, crc=crc,
        )
        return header + self.payload

    # --- atalhos de classificacao ---------------------------------------
    @property
    def is_syn_only(self):
        return self.syn and not self.ack_flag

    @property
    def is_syn_ack(self):
        return self.syn and self.ack_flag

    @property
    def is_fin(self):
        return self.fin and not self.ack_flag

    @property
    def is_fin_ack(self):
        return self.fin and self.ack_flag

    @property
    def is_pure_ack(self):
        """ACK/NACK puro de controle (sem dados, sem SYN/FIN)."""
        return (self.ack_flag or self.nack) and not self.syn and not self.fin

    @property
    def is_data(self):
        """Pacote de dados: nao tem flags de controle ativadas."""
        return not (self.syn or self.fin or self.ack_flag or self.nack)


def parse(data):
    """
    Decodifica bytes recebidos em um Packet.

    Retorna None se for menor que o cabecalho. Caso contrario retorna um
    Packet com o campo .valid indicando se o CRC32 confere.
    """
    if len(data) < HEADER_SIZE:
        return None

    word, length, crc = struct.unpack(_STRUCT_FMT, data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:]

    syn = (word >> 31) & 1
    fin = (word >> 30) & 1
    seq = (word >> 16) & SEQ_MASK
    ack_flag = (word >> 15) & 1
    nack = (word >> 14) & 1
    ack = word & SEQ_MASK

    # Recalcula o CRC32 com o campo CRC zerado para validar
    header_zero = _make_header(seq, ack, syn, fin, ack_flag, nack, length, crc=0)
    computed = zlib.crc32(header_zero + payload) & 0xFFFFFFFF
    valid = (computed == crc)

    return Packet(seq, ack, syn, fin, ack_flag, nack, length, crc, payload, valid)


# ---------------------------------------------------------------------------
# Construtores de conveniencia
# ---------------------------------------------------------------------------
def make_syn(window):
    """SYN do iniciador. Length carrega a janela proposta."""
    return Packet(seq=0, ack=0, syn=1, length=window)


def make_syn_ack(window):
    """SYN+ACK do receiver. Length carrega a janela proposta."""
    return Packet(seq=0, ack=0, syn=1, ack_flag=1, length=window)


def make_handshake_ack():
    """Terceiro passo do handshake: ACK puro com SEQ/ACK = 0."""
    return Packet(seq=0, ack=0, ack_flag=1, length=0)


def make_data(seq, payload, length):
    """Pacote de dados. length segue a semantica do campo Length."""
    return Packet(seq=seq, payload=payload, length=length)


def make_ack(ack_num):
    """ACK puro confirmando um numero de sequencia."""
    return Packet(seq=0, ack=ack_num, ack_flag=1, length=0)


def make_nack(seq_esperado):
    """NACK carregando, no campo ACK, o numero de sequencia esperado/faltante."""
    return Packet(seq=0, ack=seq_esperado, nack=1, length=0)


def make_fin():
    return Packet(seq=0, ack=0, fin=1, length=0)


def make_fin_ack():
    return Packet(seq=0, ack=0, fin=1, ack_flag=1, length=0)


# ---------------------------------------------------------------------------
# Utilitarios de numero de sequencia (wrap-around de 14 bits)
# ---------------------------------------------------------------------------
def seq_next(seq):
    return (seq + 1) & SEQ_MASK


def seq_add(seq, n):
    return (seq + n) & SEQ_MASK


def seq_in_window(seq, base, size):
    """
    Verifica se 'seq' esta dentro de [base, base+size) no espaco circular
    de 14 bits. Usado por GBN/SR para validar pacotes/ACKs com wrap-around.
    """
    diff = (seq - base) & SEQ_MASK
    return diff < size
