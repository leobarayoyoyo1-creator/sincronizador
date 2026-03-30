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
├── server.py          # Daemon Flask (roda no Ubuntu Server)
├── main.py            # Entry point do cliente desktop
├── config.json        # Configuração: host, pastas de origem/destino
└── client/
    ├── gui.py         # Interface gráfica (tkinter)
    ├── sync_logic.py  # Lógica de sincronização (manifesto + diff)
    ├── http.py        # Client HTTP (auth, upload, download)
    └── config.py      # Leitura/escrita do config.json
```

## Configuração do servidor (Ubuntu)

**1. Instalar dependências**
```bash
pip install flask waitress zstandard
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
ExecStart=/usr/bin/python3 /caminho/para/server.py daemon --port 5000
Restart=always
User=seuusuario

[Install]
WantedBy=multi-user.target
```

**5. Configurar cloudflared**

Siga a documentação oficial para criar um tunnel e apontar para `http://127.0.0.1:5000`. Com isso você terá um domínio fixo (ex: `sync.seudominio.com`) que o cliente usa.

## Configuração do cliente (Windows)

nada, só abrir o .py!

O servidor só aceita caminhos dentro de `/sistemas` — qualquer tentativa fora disso retorna 403.

Execute o cliente:
```bash
python main.py
```

Ou use o executável compilado em `dist/Sincronizador.exe`.

## Como a sincronização funciona

1. **Manifesto**: o cliente pede ao servidor a lista de arquivos (nome, tamanho, mtime) da pasta de destino
2. **Diff**: compara com os arquivos locais — só envia o que mudou ou não existe no servidor
3. **Transferência**: arquivos são comprimidos com **zstd nível 1** (rápido, razoável compressão) e enviados como tar stream. Para downloads, o mesmo processo ao contrário
4. **Limite**: uploads aceitam até 10 GB por operação

## Segurança

| Mecanismo | Detalhe |
|-----------|---------|
| Senha | PBKDF2-SHA256, 600.000 iterações, salt de 32 bytes |
| Token de sessão | `secrets.token_hex(32)` por autenticação |
| Comparação segura | `hmac.compare_digest` para evitar timing attacks |
| Path traversal | Todos os caminhos são validados contra `/sistemas` antes de qualquer operação |
| Bind local | Flask escuta só em `127.0.0.1` por padrão |

## Compilar o executável

```bash
pip install pyinstaller
pyinstaller Sincronizador.spec
```

O `.exe` gerado em `dist/` não precisa de Python instalado.
