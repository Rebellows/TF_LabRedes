import argparse
import sys

from srtp.sender import Sender
from srtp.receiver import Receiver


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="SRTP - protocolo de transporte confiavel sobre UDP")
    p.add_argument("--listen", action="store_true",
                   help="opera em modo receiver (escuta na porta P)")
    p.add_argument("--host", default=None,
                   help="IP do receiver (modo sender)")
    p.add_argument("--port", type=int, required=True,
                   help="porta P (receiver escuta em P; sender escuta ACKs em P+1)")
    p.add_argument("--file", default=None,
                   help="arquivo a transferir (modo sender)")
    p.add_argument("--out", default="recebido.bin",
                   help="arquivo de saida (modo receiver)")
    p.add_argument("--mode", choices=["saw", "gbn", "sr"], default="saw",
                   help="mecanismo de confiabilidade")
    p.add_argument("--window", type=int, default=16,
                   help="tamanho de janela proposto (1..255). Ignorado no saw.")
    p.add_argument("--quiet", action="store_true", help="silencia logs")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    verbose = not args.quiet

    if args.mode == "saw":
        # stop-and-wait equivale a janela 1, valor fixo
        window = 1
    else:
        window = max(1, min(255, args.window)) # janela variavel

    if args.listen:
        recv = Receiver(args.port, args.out, window, args.mode, verbose=verbose)
        recv.run()
    else:
        if not args.host:
            print("erro: --host eh obrigatorio no modo sender", file=sys.stderr)
            return 2
        if not args.file:
            print("erro: --file eh obrigatorio no modo sender", file=sys.stderr)
            return 2
        sender = Sender(args.host, args.port, window, args.mode, verbose=verbose)
        sender.run(args.file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
