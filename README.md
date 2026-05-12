# Sincronizador

Ferramenta para sincronizar pastas específicas entre computadores Windows e um servidor Ubuntu, via interface gráfica simples. Abre, configura a pasta de origem e destino, e manda — sem precisar lembrar nenhum comando.

## Por que isso existe

Tenho um servidor Ubuntu rodando em casa que centraliza tudo. Entre ele e meus computadores, preciso mandar arquivos frequentemente: imagens de treino para minha [rede neural de classificação de fotos](https://github.com/leobarayoyoyo1-creator/cnn-photo-apk), builds do app Android, arquivos de projeto entre máquinas.

`scp` e `rsync` funcionam, mas esqueço as flags, esqueço o caminho do servidor, esqueço o usuário. Com 4+ computadores mandando pra mesma máquina, repetir isso toda hora é chato. Esse projeto resolve isso: as pastas ficam salvas, é só abrir e clicar.

## Como a conexão funciona

O servidor **nunca fica exposto diretamente na internet**. A conexão usa [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) para criar um túnel seguro:

```
Cliente (Windows) ──HTTPS──► Cloudflare ──túnel──► cloudflared ──localhost──► servidor Flask
```

- O servidor Flask escuta **apenas em `127.0.0.1`** — sem exposição local
- O cloudflared cria o túnel e é a única entrada externa
- **Sem senha → sem token → sem acesso.** O cliente autentica com senha, recebe um token de sessão, e todos os requests usam esse token

O túnel pode ficar permanente (via serviço systemd do cloudflared) ou ser aberto só quando necessário — a segurança está na autenticação, não em ligar/desligar o túnel.

## Estrutura

```
sincronizador/
├── server.py                # Daemon Flask (roda no Ubuntu Server)
├── main.py                  # Entry point do cliente desktop
├── config.example.json      # Modelo de configuração
├── pyproject.toml           # Metadata + deps + ferramentas
├── Sincronizador.spec       # PyInstaller spec
├── requirements.txt         # Deps do servidor
├── client/
│   ├── __main__.py          # python -m client
│   ├── desktop.py           # Argparse + dispatch GUI/CLI
│   ├── gui.py               # Interface (CustomTkinter)
│   ├── http.py              # Client HTTP (auth, upload, download, archive)
│   ├── sync_logic.py        # Diff, batching, push, pull
│   ├── config.py            # Leitura/escrita do config.json local
│   ├── constants.py         # Threads, batch sizes, chunk sizes
│   ├── logger.py            # Logging rotativo em %APPDATA%/Sincronizador
│   ├── utils.py             # fmt_bytes, fmt_eta, fmt_speed, is_name_safe
│   └── requirements.txt     # Deps do cliente
└── tests/                   # pytest (utils, hashing, sync_logic, _safe_path)
```

## Configuração do servidor (Ubuntu)

**1. Instalar dependências**
```bash
pip install -r requirements.txt
# ou via pyproject:
pip install -e ".[server]"
```

**2. Definir senha**
```bash
python server.py setpassword
```
A senha é armazenada como PBKDF2-SHA256 com salt aleatório em `config.json`.

**3. Iniciar o daemon**
```bash
python server.py daemon --port 5000
```
Por padrão bind em `127.0.0.1` — não expõe nada externamente.

**4. Configurar como serviço systemd** (opcional, para iniciar com o servidor)
```ini
[Unit]
Description=Sincronizador daemon
After=network.target

[Service]
ExecStart=/usr/bin/python3 /caminho/para/server.py daemon --port 5000 --bind 127.0.0.1
Restart=always
User=seuusuario

[Install]
WantedBy=multi-user.target
```

**5. Configurar cloudflared**

Siga a documentação oficial para criar um tunnel e apontar para `http://127.0.0.1:5000`. Com isso você terá um domínio fixo que o cliente usa.

## Configuração do cliente (Windows)

**GUI:**
```bash
python main.py
```

Ou use o executável compilado em `dist/Sincronizador.exe` (gerado pelo CI ou via `pyinstaller Sincronizador.spec`).

**CLI** (sem GUI, útil para scripts):
```bash
# enviar
python -m client push "C:\caminho\local" https://sync.exemplo.com /sistemas/destino --password X

# receber
python -m client pull https://sync.exemplo.com /sistemas/origem "C:\caminho\local" --password X
```

Defina `SYNC_PASSWORD` no ambiente para evitar `--password`.

O servidor só aceita caminhos dentro de `/sistemas` — qualquer tentativa fora disso retorna 403.

## Como a sincronização funciona

1. **Manifesto**: o cliente pede ao servidor a lista de arquivos (nome, tamanho, mtime) da pasta de destino
2. **Diff**: compara com os arquivos locais — só envia o que mudou ou não existe no servidor (tolerância de mtime: 2s)
3. **Transferência**:
   - **≤ 3 arquivos**: download/upload paralelo um a um
   - **> 3 arquivos**: lote único em tar stream comprimido com **zstd nível 1**
   - Lotes grandes são quebrados em batches de até 800 arquivos ou 50 MB
4. **Limite**: uploads aceitam até 10 GB por operação (validado tanto em `/file` quanto em `/archive`)
5. **Cancelamento**: o botão *Cancelar* interrompe a operação no próximo arquivo

## Segurança

| Mecanismo | Detalhe |
|-----------|---------|
| Senha | PBKDF2-SHA256, 600.000 iterações, salt de 32 bytes |
| Token de sessão | `secrets.token_hex(32)`, TTL de 24h, expirado automaticamente |
| Comparação segura | `hmac.compare_digest` para evitar timing attacks |
| Rate limit em `/auth` | 5 tentativas por IP por 60s, retorna 429 |
| Path traversal | Todos os caminhos validados contra `/sistemas` antes de qualquer operação |
| Limite de upload | 10 GB hard cap em `/file` e `/archive`, com leitura limitada |
| Bind local | Flask escuta só em `127.0.0.1` por padrão |
| Identificação de origem | `X-Forwarded-For` (atrás do cloudflared) usado para rate limit e logs |

## Logs

O cliente escreve um log rotativo em `%APPDATA%\Sincronizador\client.log` (Windows) ou `~/.sincronizador/client.log` (Linux/macOS). O botão *Logs* na GUI abre a pasta.

O servidor loga em stdout — capture via `journalctl -u <serviço>` se rodando como systemd.

## Compilar o executável

```bash
pip install pyinstaller
pyinstaller Sincronizador.spec
```

O `.exe` gerado em `dist/` não precisa de Python instalado. O CI também publica binários automaticamente em push para `main` (veja `.github/workflows/ci.yml`).

## Testes

```bash
pip install -e ".[dev]"
pytest -v
```

Cobertura: utilitários de formatação, validação de path traversal, parser de tar safe names, hashing PBKDF2, diff de manifesto, batching, leitor limitado.

## Roadmap

- [ ] Filtro hierárquico (atualmente só nível raiz no push)
- [ ] Filtro também no pull
- [ ] Checksum sha256 opcional no manifesto (defesa em profundidade)
- [ ] Suporte a range requests para retomar downloads grandes
