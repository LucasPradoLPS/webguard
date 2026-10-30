# WebGuard

Scanner **passivo** de postura de segurança web: cabeçalhos HTTP, cookies e TLS.
Python puro (somente biblioteca padrão, Python 3.9+), sem dependências.

> **Uso autorizado apenas.** Rode somente contra sistemas seus (lab próprio, Juice Shop local,
> VMs do VulnHub/HTB/THM) ou com autorização escrita. Documente escopo e autorização em todo
> relatório. Metodologia de referência: OWASP WSTG e PTES.

## O que verifica

| Área | Checagens |
|---|---|
| Transporte | HTTP puro, HSTS ausente/fraco |
| Cabeçalhos | CSP ausente / `unsafe-inline` / `unsafe-eval` / wildcard, clickjacking, nosniff, Referrer-Policy, Permissions-Policy |
| Vazamento | versões em `Server`, `X-Powered-By`, `X-AspNet-Version` |
| CORS | `*` e `*` com credenciais |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, prefixo `__Host-` |
| TLS | certificado inválido/expirado/perto de expirar, protocolo e cifra negociados |

Cada achado traz **por que importa** (o ataque mitigado), **como corrigir** e referência OWASP.
Nota de 0 a 100 e conceito A–F.

## Uso

```bash
python3 -m webguard https://meu-lab.local
python3 -m webguard https://192.168.56.10 --insecure --html relatorio.html --json relatorio.json
python3 -m webguard -f alvos.txt --fail-on medium     # lista de alvos; código de saída p/ CI
```

Ou instale: `pip install .` e use o comando `webguard`.

Códigos de saída: `0` ok, `1` achado >= `--fail-on` (padrão `high`), `2` erro/sem alvos.

## Controle de ruído

Um scan faz **1 GET + 1 handshake TLS** (HTTPS). Não há brute force, varredura de portas nem payloads.
O ruído é uma escolha definida pelo escopo:

| Flag | Efeito |
|---|---|
| `--delay N` | espera N s entre requisições (inclusive entre alvos) |
| `--jitter N` | soma 0..N s aleatórios ao delay |
| `--user-agent X` | troca o User-Agent (padrão: `WebGuard/1.0 (+authorized-security-scan)`, honesto) |
| `--stealth` | preset: UA de navegador, 3 s de delay, 2 s de jitter |
| `--no-tls` | pula o handshake TLS |

Use `--stealth` só quando evasão fizer parte do escopo (red team); registre no relatório o modo usado.
Em lab próprio ou pentest tradicional, o UA honesto facilita a correlação nos logs do cliente.

## Limitações

- Não testa quais versões de TLS o servidor *aceita*, só a negociada (evita requisições extras).
- Expiração do certificado só é lida quando ele valida (ou com `--insecure` e cert decodificável).
- Cookies vêm apenas da resposta final (após redirects).

## Demo antes/depois (Juice Shop)

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
python3 -m webguard http://localhost:3000 --html antes.html     # nota baixa
# coloque um Nginx reverse proxy adicionando os cabeçalhos (HSTS só vale sob HTTPS)
python3 -m webguard https://localhost:8443 --insecure --html depois.html
```

## Testes

```bash
python3 -m unittest discover -s tests -v
```

## Estender

Uma checagem é uma função `(Ctx) -> list[Finding]` em `webguard/headers.py`; adicione-a a `HEADER_CHECKS`.

## Licença

MIT
