# Servidor da Aggilli no Conecta

`conecta.py` roda ao lado do RustDesk (hbbs/hbbr) na instância `aggilli-conecta` (us-east-1), num contêiner
`python:3.12-alpine` em `127.0.0.1:8070`, atrás do Caddy. Só biblioteca padrão.

- Registro de acessos: `POST /api/audit/conn` e `GET /registro.json` (só para o IP do Controle), como em 20/10/2026.
  Agora cada sessão também traz `empresa` e `tecnico_login` quando o técnico entrou com usuário.
- Técnicos: `POST /api/login`, `/api/currentUser`, `/api/logout` no formato do RustDesk;
  `POST /api/aggilli/autorizar` é chamado pelo programa do técnico antes de cada conexão.
- Controle: `POST /api/aggilli/controle`, assinado com a chave Ed25519 do ecossistema
  (domínio `aggilli-conecta-clientes-v1`). Contrato no Controle em `docs/CONECTA_CLIENTES_CONTRATO.md`.

Dados em `/dados` (`/opt/conecta-auditoria/dados`): `acessos.jsonl` (o registro antigo, preservado) e `conecta.sqlite3`.
Senhas só como hash PBKDF2; a senha temporária volta uma única vez ao Controle.

Configuração (ambiente do contêiner):
- `CONECTA_CONTROLE_LICENCAS=1` liga a rota do Controle (sem isso responde 503).
- `CONECTA_CONTROLE_CHAVE_PUBLICA=<chave pública do ecossistema, base64url, 43 caracteres>`.

Limite: a trava fica no programa do técnico e no login deste servidor. O servidor de conexão do RustDesk gratuito
não sabe recusar um programa modificado; programas do técnico antigos (antes desta versão) continuam conectando.

Testes: `python -m unittest aggilli/servidor/test_conecta.py` (precisa de `cryptography` só para assinar nos testes).
