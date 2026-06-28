# SRTP - Simple Reliable Transport Protocol sobre UDP

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

## Configuração de rede

O protocolo utiliza **duas portas UDP**:

- **Porta P** - receiver escuta dados e handshake.
- **Porta P+1** - sender escuta ACKs/NACKs (e usa como porta de origem de todos os envios).

Ambas as portas precisam estar abertas no firewall de **ambas as máquinas**.

### Windows - liberar portas no firewall (executar como Administrador)

Na máquina **receiver** (porta P e P+1 de entrada):

```powershell
netsh advfirewall firewall add rule name="SRTP UDP 6000" protocol=UDP dir=in localport=6000 action=allow
netsh advfirewall firewall add rule name="SRTP UDP 6001" protocol=UDP dir=in localport=6001 action=allow
```

Na máquina **sender** (porta P+1 de entrada, para receber os ACKs):

```powershell
netsh advfirewall firewall add rule name="SRTP UDP 6001" protocol=UDP dir=in localport=6001 action=allow
```

> Se usar uma porta diferente de 6000, substitua os valores de `localport` e `name` adequadamente.

### Verificar o IP da máquina receiver

```powershell
ipconfig
```

Procure o endereço IPv4 sob o adaptador WiFi (ex: `192.168.0.134`). Esse é o IP a
passar no argumento `--host` do sender.

## Gerar arquivo de teste

Para transferências com pelo menos 50 pacotes de dados (mínimo exigido nos testes),
gere um arquivo binário aleatório de 50.000 bytes no **sender**:

```powershell
$bytes = New-Object byte[] 50000
(New-Object Random).NextBytes($bytes)
[IO.File]::WriteAllBytes("testfile.bin", $bytes)
```

O receiver não precisa do arquivo original - apenas o sender usa `--file`.

## Execução

### Receiver (modo listen, escuta na porta P)

```powershell
python main.py --listen --port 6000 --mode saw --out recebido.bin
```

### Sender (modo connect, conecta ao receiver na porta P)

```powershell
python main.py --host 192.168.0.134 --port 6000 --mode saw --file testfile.bin
```

### GBN e SR (com janela)

```powershell
# receiver
python main.py --listen --port 6000 --mode gbn --window 16 --out recebido.bin

# sender
python main.py --host 192.168.0.134 --port 6000 --mode gbn --window 16 --file testfile.bin
```

> Os dois lados devem usar o **mesmo `--mode`**, o **mesmo `--port`** e o **mesmo `--window`**.

## Verificação de integridade

Após a transferência, compare os hashes SHA256 nas duas máquinas:

**Sender:**
```powershell
Get-FileHash testfile.bin -Algorithm SHA256
```

**Receiver:**
```powershell
Get-FileHash recebido.bin -Algorithm SHA256
```

Os dois valores devem ser idênticos. Essa é a forma utilizada no teste de
interoperabilidade entre grupos.

No Linux/macOS:
```bash
sha256sum testfile.bin
sha256sum recebido.bin
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

## Modelo de portas

- Receiver escuta na porta **P**.
- Sender usa **P+1** como porta de origem e de escuta de ACKs/NACKs; envia dados e
  handshake para o receiver em **P**. O receiver responde os ACKs/NACKs de dados
  para `(sender_ip, P+1)`.

## Resumo do protocolo

- **Cabeçalho (9 bytes):** SYN(1) FIN(1) SEQ(14) ACKflag(1) NACK(1) ACK(14) Length(8) CRC32(32).
- **CRC32** sobre o cabeçalho (com o campo CRC zerado) concatenado ao payload.
  Pacotes com CRC inválido são descartados silenciosamente (sem NACK); o timeout
  do sender dispara a retransmissão.
- **SEQ** em pacotes (não em bytes), 14 bits com wrap-around, inicia em 0.
- **Length:** 255 = pacote intermediário (bufferiza); <255 = último pacote (push);
  0 = arquivo múltiplo exato de 255 (fim de stream sem payload residual).
- **Handshake** three-way (SYN / SYN+ACK / ACK), janela negociada como o mínimo entre os dois lados.
- **Encerramento** two-way (FIN / FIN+ACK).
- **Timeout fixo:** 100 ms.

## Problemas comuns

**Sender fica em loop enviando SYN sem receber SYN+ACK:**
O firewall do sender está bloqueando a porta P+1. Execute a regra de firewall
na máquina sender para liberar a porta de entrada dos ACKs.

**Receiver não recebe nada:**
O firewall do receiver está bloqueando a porta P. Execute a regra de firewall
na máquina receiver para liberar a porta de entrada dos dados.

**`ConnectionResetError: [WinError 10054]` no receiver:**
Comportamento normal no Windows - ocorre quando o sender envia para uma porta
fechada e o sistema retorna um ICMP "port unreachable". O código já trata esse
erro com `except ConnectionResetError: continue` no loop de recepção.

**`ModuleNotFoundError: No module named 'srtp'`:**
O diretório `srtp/` precisa conter um arquivo `__init__.py`. Verifique se ele
está presente. Execute sempre a partir do diretório raiz do projeto (onde está `main.py`).