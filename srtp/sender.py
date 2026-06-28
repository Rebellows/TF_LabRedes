import socket
import time

from . import packet
from . import chunking


class Sender:
    def __init__(self, host, port, window, mode, verbose=True):
        self.host = host
        self.port = port              # porta P do receiver (envio de dados)
        self.ack_port = port + 1      # porta P+1 (escuta de ACKs/NACKs)
        self.window = window
        self.mode = mode
        self.verbose = verbose

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # bind em P+1: e a porta de origem e tambem a de escuta de ACKs
        self.sock.bind(("", self.ack_port))

        self.dst = (host, port)       # destino dos dados / handshake
        self.effective_window = window

        # estatisticas
        self.retransmissions = 0
        self.data_packets_sent = 0
        self.bytes_sent = 0

    def log(self, *a): # log de debug
        if self.verbose:
            print("[sender]", *a)

    def _send(self, pkt): # envia um pacote
        self.sock.sendto(pkt.to_bytes(), self.dst)

    def _recv(self, timeout): # recebe um pacote, validando CRC32
        deadline = time.monotonic() + timeout
        while True: # aguarda pacote
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(remaining)
            try: # recebe pacote de dados (header + payload)
                data, _ = self.sock.recvfrom(packet.HEADER_SIZE + packet.MAX_PAYLOAD)
            except socket.timeout:
                return None
            except ConnectionResetError:
                continue
            pkt = packet.parse(data)
            if pkt is None or not pkt.valid:
                # pacote corrompido/curto: ignora e segue aguardando
                continue
            return pkt

    def handshake(self): # primeiro passo: SYN
        syn = packet.make_syn(self.window)
        while True: # aguarda SYN+ACK
            self._send(syn)
            self.log(f"SYN enviado (janela proposta={self.window})")
            reply = self._recv(packet.TIMEOUT)
            if reply is None: # timeout
                self.log("timeout aguardando SYN+ACK, reenviando SYN")
                continue
            if reply.is_syn_ack: # SYN+ACK
                peer_window = reply.length
                self.effective_window = min(self.window, peer_window)
                self.log(f"SYN+ACK recebido (janela do peer={peer_window}); "f"janela efetiva={self.effective_window}")
                break
        # terceiro passo: ACK
        self._send(packet.make_handshake_ack())
        self.log("ACK do handshake enviado; conexao estabelecida")

    def teardown(self): # quarto passo: FIN
        fin = packet.make_fin()
        while True: # aguarda FIN+ACK
            self._send(fin)
            self.log("FIN enviado")
            reply = self._recv(packet.TIMEOUT)
            if reply is None:
                self.log("timeout aguardando FIN+ACK, reenviando FIN")
                continue
            if reply.is_fin_ack: # FIN+ACK
                self.log("FIN+ACK recebido; conexao encerrada")
                return

    def send_file(self, path): # envia o arquivo em pacotes de dados
        with open(path, "rb") as f:
            data = f.read()
        pkts = chunking.split_into_packets(data) # divide em pacotes
        self.log(f"arquivo: {len(data)} bytes -> {len(pkts)} pacotes de dados")

        start = time.monotonic()
        if self.mode == "saw":
            self._send_stop_and_wait(pkts)
        elif self.mode == "gbn":
            self._send_sliding(pkts, selective=False)
        elif self.mode == "sr":
            self._send_sliding(pkts, selective=True)
        else:
            raise ValueError(f"modo desconhecido: {self.mode}")
        elapsed = time.monotonic() - start

        self.bytes_sent = len(data)
        self._report(elapsed)

    def _report(self, elapsed):
        thr = (self.bytes_sent * 8 / elapsed) if elapsed > 0 else 0
        self.log("---- estatisticas ----")
        self.log(f"modo                 : {self.mode}")
        self.log(f"janela efetiva       : {self.effective_window}")
        self.log(f"bytes transferidos   : {self.bytes_sent}")
        self.log(f"pacotes de dados     : {self.data_packets_sent}")
        self.log(f"retransmissoes       : {self.retransmissions}")
        self.log(f"tempo                : {elapsed:.4f} s")
        self.log(f"throughput           : {thr/1e6:.4f} Mbit/s "
                 f"({self.bytes_sent/elapsed/1024:.2f} KB/s)" if elapsed > 0 else "n/a")

    # stop-and-wait
    def _send_stop_and_wait(self, pkts): # envia pacotes de dados e aguarda ACK
        seq = 0
        for payload, length in pkts: # envia todos os pacotes
            pkt = packet.make_data(seq, payload, length)
            first = True
            while True: # aguarda ACK do pacote atual
                self._send(pkt)
                self.data_packets_sent += 1
                if not first: # retransmissao
                    self.retransmissions += 1
                first = False
                reply = self._recv(packet.TIMEOUT)
                if reply is None: # timeout
                    self.log(f"timeout no SEQ={seq}, retransmitindo")
                    continue
                if reply.ack_flag and reply.ack == seq: # ACK do pacote
                    break
                # ACK de outro numero / NACK: retransmite
                if reply.nack:
                    self.log(f"NACK recebido para SEQ={seq}, retransmitindo")
            seq = packet.seq_next(seq)

    # Go-Back-N e Selective Repeat (janela deslizante)
    def _send_sliding(self, pkts, selective):
        N = self.effective_window
        total = len(pkts)

        base = 0          # indice (na lista pkts) do primeiro nao confirmado
        next_idx = 0      # proximo indice a enviar
        # SEQ correspondente ao indice 0 e 0; SEQ do indice i = i mod SEQ_SPACE
        acked = [False] * total
        send_time = {}    # indice -> instante de envio (para timeout)

        def seq_of(i): # retorna o SEQ correspondente ao indice
            return i & packet.SEQ_MASK

        def send_idx(i): # envia o pacote de indice i
            payload, length = pkts[i]
            self._send(packet.make_data(seq_of(i), payload, length))
            send_time[i] = time.monotonic()
            self.data_packets_sent += 1

        while base < total: # envia todos os pacotes
            # 1) preenche a janela
            while next_idx < base + N and next_idx < total:
                send_idx(next_idx)
                next_idx += 1

            # 2) aguarda ACK/NACK ate o timeout do pacote base
            elapsed = time.monotonic() - send_time.get(base, time.monotonic())
            wait = max(0.0, packet.TIMEOUT - elapsed)
            reply = self._recv(wait)

            if reply is None:
                # timeout
                if selective:
                    # SR: retransmite apenas o pacote base (nao confirmado)
                    self.log(f"[SR] timeout, retransmite base SEQ={seq_of(base)}")
                    send_idx(base)
                    self.retransmissions += 1
                else:
                    # GBN: retransmite toda a janela a partir de base
                    self.log(f"[GBN] timeout, retransmite janela a partir de "f"SEQ={seq_of(base)}")
                    for i in range(base, next_idx):
                        send_idx(i)
                        self.retransmissions += 1
                continue

            if reply.nack:
                # NACK: campo ACK carrega o SEQ esperado/faltante
                self._handle_nack(reply, base, next_idx, selective,
                                   send_idx, seq_of)
                continue

            if reply.ack_flag:
                self._handle_ack(reply, acked, total, seq_of, selective)
                # avanca a base sobre pacotes ja confirmados
                while base < total and acked[base]:
                    base += 1

    def _handle_ack(self, reply, acked, total, seq_of, selective):
        if not selective:
            # GBN: ACK cumulativo -> confirma tudo ate reply.ack inclusive.
            for i in range(total):
                if seq_of(i) == reply.ack:
                    for j in range(0, i + 1):
                        acked[j] = True
                    break
        else:
            # SR: ACK individual -> confirma apenas reply.ack
            for i in range(total):
                if seq_of(i) == reply.ack and not acked[i]:
                    acked[i] = True
                    break

    def _handle_nack(self, reply, base, next_idx, selective, send_idx, seq_of):
        if selective:
            # SR: retransmite somente o pacote faltante indicado no NACK
            for i in range(base, next_idx):
                if seq_of(i) == reply.ack:
                    self.log(f"[SR] NACK -> retransmite SEQ={reply.ack}")
                    send_idx(i)
                    self.retransmissions += 1
                    return
        else:
            # GBN: NACK -> retransmite a partir do esperado
            self.log(f"[GBN] NACK -> retransmite a partir de SEQ={reply.ack}")
            for i in range(base, next_idx):
                if seq_of(i) == reply.ack:
                    for j in range(i, next_idx):
                        send_idx(j)
                        self.retransmissions += 1
                    return

    def close(self):
        self.sock.close()

    # ------------------------------------------------------------------
    def run(self, path):
        try:
            self.handshake()
            self.send_file(path)
            self.teardown()
        finally:
            self.close()