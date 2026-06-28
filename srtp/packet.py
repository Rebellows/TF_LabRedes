import struct
import zlib
from dataclasses import dataclass


# --- Constantes do protocolo ---
HEADER_SIZE = 9            # tamanho do cabecalho em bytes
MAX_PAYLOAD = 255          # bytes de payload por pacote de dados (cheio)
SEQ_BITS = 14              # espaco de numero de sequencia
SEQ_SPACE = 1 << SEQ_BITS  # 16384 -> valores 0..16383
SEQ_MASK = SEQ_SPACE - 1   # 0x3FFF
TIMEOUT = 0.1              # 100 ms, timeout fixo de retransmissao

# Formato struct: palavra de 32 bits + Length (1 byte) + CRC32 (4 bytes), big-endian
_STRUCT_FMT = ">IBI"


def _pack_word(seq, ack, syn, fin, ack_flag, nack):
    """Monta a palavra de 32 bits com os campos do cabecalho, ainda sem CRC"""
    return (
        ((syn & 1) << 31)
        | ((fin & 1) << 30)
        | ((seq & SEQ_MASK) << 16)
        | ((ack_flag & 1) << 15)
        | ((nack & 1) << 14)
        | (ack & SEQ_MASK)
    )

# [SYN(1) FIN(1) SEQ(14) ACKflag(1) NACK(1) ACK(14)] [Length(8)] [CRC32(32)]
def _make_header(seq, ack, syn, fin, ack_flag, nack, length, crc):
    # Monta o cabecalho
    word = _pack_word(seq, ack, syn, fin, ack_flag, nack)
    # Retorna os bytes do cabecalho com o CRC fornecido (ou 0 se ainda nao calculado)
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
        # cabecalho inicial, sem CRC
        header_zero = _make_header(
            self.seq, self.ack, self.syn, self.fin,
            self.ack_flag, self.nack, self.length, crc=0,
        )
        # computa o CRC32 sobre cabecalho+payload com o campo CRC zerado
        crc = zlib.crc32(header_zero + self.payload) & 0xFFFFFFFF
        # monta o cabecalho final com o CRC calculado
        header = _make_header(
            self.seq, self.ack, self.syn, self.fin,
            self.ack_flag, self.nack, self.length, crc=crc,
        )
        return header + self.payload

    # --- propriedades para analise de flags, para simplificar o codigo do sender/receiver --- 
    @property
    def is_syn_only(self): # sender inicia handshake: SYN puro, sem ACK
        return self.syn and not self.ack_flag

    @property
    def is_syn_ack(self): # receiver responde handshake: SYN+ACK
        return self.syn and self.ack_flag

    @property
    def is_fin(self): # sender inicia encerramento: FIN puro, sem ACK
        return self.fin and not self.ack_flag

    @property
    def is_fin_ack(self): # receiver responde encerramento: FIN+ACK
        return self.fin and self.ack_flag

    @property
    def is_pure_ack(self): # ACK puro, sem SYN/FIN/NACK, confirma recebimento ou retransmissao de um pacote
        return (self.ack_flag or self.nack) and not self.syn and not self.fin

    @property
    def is_data(self): # pacote de dados
        return not (self.syn or self.fin or self.ack_flag or self.nack)


def parse(data):
    """Decodifica bytes recebidos em um pacote Packet, validando o CRC32."""
    if len(data) < HEADER_SIZE:
        return None

    # Desmonta o cabecalho, inverso da funcao _make_header
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


# --- Construtores de pacotes para o sender/receiver, simplificando a criacao de pacotes com flags e campos corretos ---

def make_syn(window): # SYN do sender
    return Packet(seq=0, ack=0, syn=1, length=window)



def make_syn_ack(window): # SYN+ACK do receiver
    return Packet(seq=0, ack=0, syn=1, ack_flag=1, length=window)


def make_handshake_ack(): # ACK do handshake
    return Packet(seq=0, ack=0, ack_flag=1, length=0)


def make_data(seq, payload, length): # pacote de dados, com cabecalho e payload
    return Packet(seq=seq, payload=payload, length=length)


def make_ack(ack_num): # ACK puro, carregando o numero de sequencia a ser confirmado
    return Packet(seq=0, ack=ack_num, ack_flag=1, length=0)


def make_nack(seq_esperado): # NACK puro, carregando o numero de sequencia esperado
    return Packet(seq=0, ack=seq_esperado, nack=1, length=0)


def make_fin(): # FIN do sender
    return Packet(seq=0, ack=0, fin=1, length=0)


def make_fin_ack(): # FIN+ACK do receiver
    return Packet(seq=0, ack=0, fin=1, ack_flag=1, length=0)

def seq_next(seq): # retorna o proximo numero de sequencia, com wrap-around no espaco circular de 14 bits
    return (seq + 1) & SEQ_MASK


def seq_add(seq, n): # retorna o numero de sequencia somado a n, com wrap-around no espaco circular de 14 bits
    return (seq + n) & SEQ_MASK


def seq_in_window(seq, base, size): # verifica se o numero de sequencia seq esta dentro da janela [base, base+size), considerando wrap-around
    diff = (seq - base) & SEQ_MASK
    return diff < size
