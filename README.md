# SRTP — Simple Reliable Transport Protocol sobre UDP

Protocolo de transporte confiável sobre UDP, com três variantes de controle de
erros e fluxo selecionáveis em tempo de execução: **stop-and-wait (saw)**,
**Go-Back-N (gbn)** e **Selective Repeat (sr)**. O mesmo binário suporta os três
modos via argumento `--mode`.

## Requisitos

- Python 3.8+ (somente biblioteca padrão: `socket`, `struct`, `zlib`, `argparse`).
- Não há etapa de compilação. O "binário" é o interpretador Python executando
  `main.py`.

## Estrutura

```
main.py            # ponto de entrada / CLI
srtp/
  __init__.py
  packet.py        # cabeçalho de 9 bytes, CRC32, (de)serialização, wrap-around do SEQ
  chunking.py      # segmentação do arquivo + semântica do campo Length
  sender.py        # handshake, transferência (saw/gbn/sr), encerramento
  receiver.py      # recepção (saw/gbn/sr), reconstrução do arquivo
capturas/          # arquivos .pcapng dos cenários de teste
```

## Execução

### Receiver (modo listen, escuta na porta P)

```
python3 main.py --listen --port 6000 --mode saw --out recebido.bin
```

### Sender (modo connect, conecta ao receiver na porta P)

```
python3 main.py --host 192.168.1.10 --port 6000 --mode saw --file arquivo.bin
```

Para GBN/SR, escolha o modo e a janela (negociada no handshake; a janela efetiva
da sessão é o menor valor proposto pelos dois lados):

```
# receiver
python3 main.py --listen --port 6000 --mode sr --window 16 --out recebido.bin
# sender
python3 main.py --host 192.168.1.10 --port 6000 --mode sr --window 16 --file arquivo.bin
```

## Argumentos de linha de comando

| Argumento    | Modo      | Descrição                                                        |
|--------------|-----------|------------------------------------------------------------------|
| `--listen`   | receiver  | Opera como receiver, escutando na porta P. Sua ausência = sender.|
| `--host`     | sender    | IP do receiver.                                                  |
| `--port`     | ambos     | Porta P. Receiver escuta em P; sender escuta ACKs/NACKs em P+1.  |
| `--file`     | sender    | Caminho do arquivo a transferir.                                 |
| `--out`      | receiver  | Caminho do arquivo de saída (padrão: `recebido.bin`).            |
| `--mode`     | ambos     | `saw`, `gbn` ou `sr` (padrão: `saw`).                            |
| `--window`   | ambos     | Janela proposta no handshake, 1–255 (ignorado no `saw`).         |
| `--quiet`    | ambos     | Silencia os logs.                                                |

> Os dois lados devem usar o **mesmo `--mode`** e o **mesmo `--port`**.

## Modelo de portas

- Receiver escuta na porta **P**.
- Sender usa **P+1** como porta de origem e de escuta de ACKs/NACKs; envia dados e
  handshake para o receiver em **P**. O receiver responde os ACKs/NACKs de dados
  para `(sender_ip, P+1)`.

## Resumo do protocolo

- **Cabeçalho (9 bytes):** SYN(1) FIN(1) SEQ(14) ACKflag(1) NACK(1) ACK(14)
  Length(8) CRC32(32).
- **CRC32** sobre o cabeçalho (com o campo CRC zerado) concatenado ao payload.
  Pacotes com CRC inválido são descartados silenciosamente (sem NACK); o timeout
  do sender dispara a retransmissão.
- **SEQ** em pacotes (não em bytes), 14 bits com wrap-around, inicia em 0.
- **Length:** 255 = pacote intermediário (bufferiza); <255 = último pacote (push);
  0 = arquivo múltiplo exato de 255 (fim de stream sem payload residual).
- **Handshake** three-way (SYN / SYN+ACK / ACK), janela negociada como o mínimo.
- **Encerramento** two-way (FIN / FIN+ACK).
- **Timeout fixo:** 100 ms.

## Verificação de integridade

Após a transferência, compare os hashes:

```
sha256sum arquivo.bin recebido.bin
```

Os dois valores devem ser idênticos (critério do teste de interoperabilidade).
