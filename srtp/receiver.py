"""
Lado RECEIVER do RTP.

Fluxo geral:
    1. Escuta na porta P. Recebe SYN, responde SYN+ACK, recebe ACK final.
    2. Recebe os pacotes de dados conforme o modo (saw | gbn | sr),
       enviando ACK/NACK para (sender_ip, P+1).
    3. Recebe FIN e responde FIN+ACK.

Reconstrucao do arquivo: o receiver bufferiza payloads e faz o "push"
(grava o arquivo) ao receber o pacote terminador (Length < 255).
"""

import socket
import time

from . import packet
from . import chunking


class Receiver:
    def __init__(self, port, out_path, window, mode, verbose=True):
        self.port = port            # P
        self.ack_port = port + 1    # P+1 (destino dos ACKs)
        self.out_path = out_path
        self.window = window
        self.mode = mode
        self.verbose = verbose

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", port))

        self.sender_ip = None
        self.effective_window = window
        self.buffer = bytearray()

        # estatisticas
        self.data_packets_recv = 0
        self.corrupted = 0
        self.out_of_order = 0

    def log(self, *a):
        if self.verbose:
            print("[receiver]", *a)

    # ------------------------------------------------------------------
    def _ack_dst(self):
        """Destino dos pacotes de controle: (sender_ip, P+1)."""
        return (self.sender_ip, self.ack_port)

    def _send_ctrl(self, pkt, dst=None):
        self.sock.sendto(pkt.to_bytes(), dst or self._ack_dst())

    def _recv(self, timeout=None):
        """Recebe um pacote. Retorna (Packet, addr) ou (None, None) no timeout.
        Pacotes corrompidos sao contabilizados e descartados silenciosamente
        (sem NACK), e a funcao continua aguardando."""
        if timeout is not None:
            deadline = time.monotonic() + timeout
        while True:
            if timeout is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None, None
                self.sock.settimeout(remaining)
            else:
                self.sock.settimeout(None)
            try:
                data, addr = self.sock.recvfrom(packet.HEADER_SIZE + packet.MAX_PAYLOAD)
            except socket.timeout:
                return None, None
            pkt = packet.parse(data)
            if pkt is None:
                continue
            if not pkt.valid:
                # CRC32 invalido: descarta silenciosamente, SEM NACK
                self.corrupted += 1
                self.log("pacote corrompido descartado (CRC32 invalido)")
                continue
            return pkt, addr

    # ------------------------------------------------------------------
    # Handshake (lado receiver)
    # ------------------------------------------------------------------
    def handshake(self):
        # Espera o primeiro SYN
        while True:
            pkt, addr = self._recv(timeout=None)
            if pkt.is_syn_only:
                self.sender_ip = addr[0]
                peer_window = pkt.length
                self.effective_window = min(self.window, peer_window)
                self.log(f"SYN recebido de {addr} (janela proposta={peer_window}); "
                         f"janela efetiva={self.effective_window}")
                # Responde SYN+ACK para a origem do SYN (handshake)
                self._send_ctrl(packet.make_syn_ack(self.window), dst=addr)
                self.log("SYN+ACK enviado")
                break

        # Aguarda o ACK final OU o primeiro pacote de dados (ambos confirmam).
        # Se chegar um SYN duplicado, reenvia SYN+ACK.
        while True:
            pkt, addr = self._recv(timeout=packet.TIMEOUT)
            if pkt is None:
                # ACK final pode ter se perdido; assume estabelecido e segue.
                self.log("sem ACK final (timeout); assumindo conexao estabelecida")
                return None
            if pkt.is_syn_only:
                self._send_ctrl(packet.make_syn_ack(self.window), dst=addr)
                continue
            if pkt.is_pure_ack:
                self.log("ACK final recebido; conexao estabelecida")
                return None
            if pkt.is_data:
                # primeiro dado ja chegou: estabelece e processa esse pacote
                self.log("primeiro pacote de dados recebido; conexao estabelecida")
                return pkt

    # ------------------------------------------------------------------
    # Recepcao de dados
    # ------------------------------------------------------------------
    def receive_file(self, pending=None):
        if self.mode == "saw":
            self._recv_stop_and_wait(pending)
        elif self.mode == "gbn":
            self._recv_gbn(pending)
        elif self.mode == "sr":
            self._recv_sr(pending)
        else:
            raise ValueError(f"modo desconhecido: {self.mode}")

        with open(self.out_path, "wb") as f:
            f.write(self.buffer)
        self.log(f"arquivo gravado: {self.out_path} ({len(self.buffer)} bytes)")

    def _deliver(self, payload, length):
        """Aplica a semantica do campo Length. Retorna True se for o fim."""
        if length == packet.MAX_PAYLOAD:
            self.buffer.extend(payload)
            return False
        elif length == 0:
            # terminador sem payload residual
            return True
        else:
            # ultimo pacote parcial: usa apenas 'length' bytes
            self.buffer.extend(payload[:length])
            return True

    # ------------------------------------------------------------------
    # Stop-and-Wait (receiver)
    # ------------------------------------------------------------------
    def _recv_stop_and_wait(self, pending):
        expected = 0

        def process(pkt):
            nonlocal expected
            self.data_packets_recv += 1
            done = self._deliver(pkt.payload, pkt.length)
            self._send_ctrl(packet.make_ack(pkt.seq))
            expected = packet.seq_next(expected)
            return done

        if pending is not None:
            if pending.seq == expected:
                if process(pending):
                    return
            else:
                self.out_of_order += 1

        while True:
            pkt, _ = self._recv(timeout=None)
            if pkt.is_fin:
                self._handle_fin()
                return
            if not pkt.is_data:
                continue
            if pkt.seq == expected:
                if process(pkt):
                    return
            else:
                # fora de ordem: descarta silenciosamente, mas reenvia ACK
                # do ultimo recebido corretamente (ajuda em duplicatas)
                self.out_of_order += 1
                last = (expected - 1) & packet.SEQ_MASK
                self._send_ctrl(packet.make_ack(last))

    # ------------------------------------------------------------------
    # Go-Back-N (receiver): aceita somente em ordem; ACK cumulativo; NACK
    # ------------------------------------------------------------------
    def _recv_gbn(self, pending):
        expected = 0
        nack_sent_for = None

        def process(pkt):
            nonlocal expected, nack_sent_for
            self.data_packets_recv += 1
            done = self._deliver(pkt.payload, pkt.length)
            self._send_ctrl(packet.make_ack(pkt.seq))  # ACK cumulativo = ultimo em ordem
            expected = packet.seq_next(expected)
            nack_sent_for = None
            return done

        def handle(pkt):
            nonlocal nack_sent_for
            if pkt.seq == expected:
                return process(pkt)
            else:
                # fora de ordem: descarta e envia NACK com o SEQ esperado
                self.out_of_order += 1
                if nack_sent_for != expected:
                    self._send_ctrl(packet.make_nack(expected))
                    nack_sent_for = expected
                return False

        if pending is not None:
            if handle(pending):
                return

        while True:
            pkt, _ = self._recv(timeout=None)
            if pkt.is_fin:
                self._handle_fin()
                return
            if not pkt.is_data:
                continue
            if handle(pkt):
                return

    # ------------------------------------------------------------------
    # Selective Repeat (receiver): bufferiza fora de ordem; ACK individual
    # ------------------------------------------------------------------
    def _recv_sr(self, pending):
        N = self.effective_window
        expected = 0                 # base da janela de recepcao
        recv_buf = {}                # seq -> (payload, length)
        finished = False

        def slide_and_deliver():
            """Entrega em ordem a partir de 'expected' enquanto houver."""
            nonlocal expected, finished
            while expected in recv_buf:
                payload, length = recv_buf.pop(expected)
                if self._deliver(payload, length):
                    finished = True
                    return
                expected = packet.seq_next(expected)

        def handle(pkt):
            nonlocal expected
            # janela de recepcao: [expected, expected+N)
            if packet.seq_in_window(pkt.seq, expected, N):
                if pkt.seq not in recv_buf and pkt.seq != _already(expected):
                    recv_buf[pkt.seq] = (pkt.payload, pkt.length)
                # ACK individual sempre (mesmo duplicado)
                self._send_ctrl(packet.make_ack(pkt.seq))
                if pkt.seq != expected:
                    self.out_of_order += 1
                    # lacuna detectada: NACK com o SEQ faltante (expected)
                    self._send_ctrl(packet.make_nack(expected))
                self.data_packets_recv += 1
                slide_and_deliver()
            elif packet.seq_in_window(pkt.seq,
                                      (expected - N) & packet.SEQ_MASK, N):
                # ja entregue (janela anterior): reenvia ACK
                self._send_ctrl(packet.make_ack(pkt.seq))
            # senao: fora de qualquer janela -> ignora

        if pending is not None:
            handle(pending)
            if finished:
                return

        while not finished:
            pkt, _ = self._recv(timeout=None)
            if pkt.is_fin:
                self._handle_fin()
                return
            if not pkt.is_data:
                continue
            handle(pkt)

    # ------------------------------------------------------------------
    def _handle_fin(self):
        self.log("FIN recebido; enviando FIN+ACK e encerrando")
        self._send_ctrl(packet.make_fin_ack())

    def close(self):
        self.sock.close()

    def run(self):
        try:
            pending = self.handshake()
            self.receive_file(pending)
            # Apos gravar: continua respondendo enquanto o sender nao encerra.
            self._finalize()
        finally:
            self.log("---- estatisticas ----")
            self.log(f"modo                 : {self.mode}")
            self.log(f"pacotes de dados     : {self.data_packets_recv}")
            self.log(f"pacotes corrompidos  : {self.corrupted}")
            self.log(f"fora de ordem        : {self.out_of_order}")
            self.close()

    def _finalize(self):
        """
        Apos a entrega completa, o sender pode nao ter recebido o ACK do
        ultimo pacote (ACK perdido) e continuar retransmitindo o ultimo dado.
        Aqui:
          - re-ACKamos qualquer pacote de dados retransmitido;
          - respondemos FIN com FIN+ACK;
          - encerramos apos um periodo de quietude depois do FIN.
        Como o ultimo pacote ja foi entregue, NAO o reprocessamos no buffer.
        """
        fin_seen = False
        # Espera generosa enquanto o sender ainda retransmite o ultimo dado;
        # encurta apos ver o primeiro FIN.
        while True:
            timeout = (2 * packet.TIMEOUT) if fin_seen else (20 * packet.TIMEOUT)
            pkt, _ = self._recv(timeout=timeout)
            if pkt is None:
                return
            if pkt.is_fin:
                self._send_ctrl(packet.make_fin_ack())
                fin_seen = True
            elif pkt.is_data:
                # ultimo dado retransmitido: apenas re-ACKa (nao re-bufferiza)
                self._send_ctrl(packet.make_ack(pkt.seq))


def _already(expected):
    # helper para legibilidade; nunca igual a expected, evita falso positivo
    return (expected - 1) & packet.SEQ_MASK
