"""Aggilli Conecta: servidor da Aggilli ao lado do RustDesk (hbbs/hbbr), atrás do Caddy em 127.0.0.1:8070.

Registro de acessos (igual ao de 20/10/2026):
  POST /api/audit/conn  -> grava cada aviso (nova conexão, técnico, fim) em acessos.jsonl
  GET  /registro.json   -> sessões agrupadas, mais recentes primeiro (o Caddy só libera para o servidor do Controle)

Técnicos e licença (Conecta · Clientes no Controle):
  POST /api/login, /api/currentUser, /api/logout -> login do programa do técnico (formato do RustDesk)
  POST /api/aggilli/autorizar                    -> o programa do técnico pergunta antes de cada conexão
  POST /api/aggilli/controle                     -> pedidos assinados pelo Controle (Ed25519 do ecossistema)

Cada cliente é uma empresa com técnicos (login e senha). A empresa tem teste de 7 dias ou plano pago; vencida ou
cancelada, o técnico não entra e não conecta. Liberar e renovar só com cobrança paga de verdade confirmada pelo Controle.
Senha só como hash PBKDF2; a senha temporária volta uma única vez na resposta ao Controle e nunca vai para arquivo.
Somente biblioteca padrão.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DADOS = os.environ.get('DADOS', '/dados')
MAX_CORPO = 16 * 1024
DIA = 86400
TESTE_DIAS, TESTE_TECNICOS = 7, 3
PLANOS = {'Técnico': (1, 1), 'Equipe': (2, 20)}
PAGOS = ('manual', 'stripe_live')
MAX_VALIDADE = 400 * DIA
TOKEN_DIAS = 30
JANELA = 300
DOMINIO, CAMINHO = 'aggilli-conecta-clientes-v1', '/api/aggilli/controle'
TENTATIVAS, BLOQUEIO_SEG = 8, 15 * 60
TRAVA = threading.Lock()
NONCES_AUDIT = {}  # o programa pode reenviar o mesmo aviso de auditoria
FALHAS = {}        # (login, ip) -> [instantes das falhas]
MENSAGEM_BLOQUEIO = ('A licença do Aggilli Conecta da sua empresa está vencida ou cancelada. '
                     'Fale com a Aggilli para regularizar.')


class Recusa(Exception):
    def __init__(self, status, mensagem):
        super().__init__(mensagem)
        self.status = status


# Ed25519 (RFC 8032, só verificação) ---------------------------------------------------------------------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    A, B = (a[1] - a[0]) * (b[1] - b[0]) % _P, (a[1] + a[0]) * (b[1] + b[0]) % _P
    C, D = 2 * a[3] * b[3] * _D % _P, 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p, s = _add(p, p), s >> 1
    return q


def _igual(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _x(y, sinal):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sinal else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sinal:
        x = _P - x
    return x


def _ponto(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, 'little')
    sinal, y = y >> 255, y & ((1 << 255) - 1)
    x = _x(y, sinal)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_x(_GY, 0), _GY, 1, _x(_GY, 0) * _GY % _P)


def ed25519_verifica(publica, mensagem, assinatura):
    if len(publica) != 32 or len(assinatura) != 64:
        return False
    A, R = _ponto(publica), _ponto(assinatura[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(assinatura[32:], 'little')
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(assinatura[:32] + publica + mensagem).digest(), 'little') % _L
    return _igual(_mul(s, _G), _add(R, _mul(h, A)))


def _b64(texto):
    import base64
    return base64.urlsafe_b64decode(texto + '=' * (-len(texto) % 4))


def mensagem(pedido, data, nonce, ator):
    return '\n'.join([DOMINIO, 'conecta', 'POST', CAMINHO, data, nonce, ator, hashlib.sha256(pedido).hexdigest()]).encode()


# Senhas e tokens ---------------------------------------------------------------------------------------------
def hash_senha(senha, sal=None, voltas=310_000):
    sal = sal or secrets.token_bytes(16)
    d = hashlib.pbkdf2_hmac('sha256', senha.encode(), sal, voltas)
    return f'pbkdf2_sha256${voltas}${sal.hex()}${d.hex()}'


def confere_senha(senha, guardado):
    try:
        _, voltas, sal, d = guardado.split('$')
        calc = hashlib.pbkdf2_hmac('sha256', senha.encode(), bytes.fromhex(sal), int(voltas))
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(calc.hex(), d)


_FALSO = hash_senha('nao-existe', b'\0' * 16)


def senha_temporaria():
    letras = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789'
    return '-'.join(''.join(secrets.choice(letras) for _ in range(4)) for _ in range(4))


def _sha(texto):
    return hashlib.sha256(texto.encode() if isinstance(texto, str) else texto).hexdigest()


# Regras ------------------------------------------------------------------------------------------------------
def situacao(e, agora):
    if e['status'] == 'INTERNO':
        return 'interno'
    if e['status'] == 'SUSPENDED':
        return 'cancelado'
    return 'vencido' if (e['valido_ate'] or 0) <= agora else 'ativo'


def bloqueada(e, agora):
    return e is None or situacao(e, agora) in ('cancelado', 'vencido')


def _texto(v, nome, limite=120, minimo=2):
    if not isinstance(v, str) or not minimo <= len(v.strip()) <= limite:
        raise Recusa(422, f'Informe {nome}.')
    return v.strip()


def _inteiro(v, nome, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise Recusa(422, f'{nome} deve ficar entre {lo} e {hi}.')
    return v


def _email(v):
    e = _texto(v, 'o e-mail', 254).lower()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', e):
        raise Recusa(422, 'E-mail inválido.')
    return e


def _documento(v):
    d = re.sub(r'\D', '', _texto(v, 'o CPF ou CNPJ', 30))
    if len(d) not in (11, 14):
        raise Recusa(422, 'CPF ou CNPJ inválido.')
    return d


def aplicar(e, acao, c, agora, ativos=0):
    """Regras puras: devolve os campos novos da empresa (ou recusa). Não toca banco."""
    def motivo():
        _texto(c.get('motivo'), 'o motivo', 300, 3)

    def ate(dias):
        v = max(e['valido_ate'] or 0, agora) + dias * DIA
        if v - agora > MAX_VALIDADE:
            raise Recusa(409, 'A validade passaria de 400 dias.')
        return v

    if acao == 'prorrogar':
        motivo()
        dias = _inteiro(c.get('dias'), 'Dias', 1, 30)
        if e['status'] != 'TRIAL':
            raise Recusa(409, 'Só dá para prorrogar um teste ativo ou vencido.')
        return {'valido_ate': ate(dias)}
    if acao in ('liberar', 'renovar'):
        if c.get('modo') not in PAGOS or isinstance(c.get('centavos'), bool) or not isinstance(c.get('centavos'), int) \
                or c['centavos'] <= 0 or not re.fullmatch(r'\d{1,18}', str(c.get('cobranca') or '')):
            raise Recusa(422, 'Exige pagamento real confirmado pelo Controle.')
        faixa = PLANOS.get(c.get('plano'))
        if not faixa:
            raise Recusa(422, 'Plano inválido.')
        tecnicos = _inteiro(c.get('tecnicos'), 'Técnicos', *faixa)
        if tecnicos < ativos:
            raise Recusa(409, f'A empresa já tem {ativos} técnico(s); contrate pelo menos esse número.')
        dias = _inteiro(c.get('dias'), 'Dias', 1, 366)
        if acao == 'liberar' and e['status'] != 'TRIAL':
            raise Recusa(409, 'Só dá para liberar uma empresa em teste.')
        if acao == 'renovar' and e['status'] != 'PAID':
            raise Recusa(409, 'Só dá para renovar uma empresa paga e não cancelada.')
        valido = agora + dias * DIA if acao == 'liberar' else ate(dias)
        if valido - agora > MAX_VALIDADE:
            raise Recusa(409, 'A validade passaria de 400 dias.')
        return {'status': 'PAID', 'plano': c['plano'], 'tecnicos': tecnicos, 'valido_ate': valido}
    if acao == 'carencia':
        motivo()
        dias = _inteiro(c.get('dias'), 'Dias', 1, 30)
        if e['status'] != 'PAID':
            raise Recusa(409, 'Carência só para empresa paga e não cancelada.')
        return {'valido_ate': ate(dias)}
    if acao == 'cancelar':
        motivo()
        if e['status'] in ('SUSPENDED', 'INTERNO'):
            raise Recusa(409, 'Só dá para cancelar uma empresa em teste ou paga.')
        return {'status': 'SUSPENDED', 'anterior': e['status']}
    if acao == 'reativar':
        motivo()
        if e['status'] != 'SUSPENDED':
            raise Recusa(409, 'Só dá para reativar uma empresa cancelada.')
        return {'status': e['anterior'], 'anterior': None}
    raise Recusa(422, 'Ação desconhecida.')


# Banco -------------------------------------------------------------------------------------------------------
ESQUEMA = '''
CREATE TABLE IF NOT EXISTS empresas(id TEXT PRIMARY KEY, nome TEXT NOT NULL, documento TEXT UNIQUE, status TEXT NOT NULL,
  anterior TEXT, plano TEXT NOT NULL, tecnicos INTEGER NOT NULL, valido_ate INTEGER, origem TEXT NOT NULL,
  revisao INTEGER NOT NULL, criado_em INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tecnicos(id TEXT PRIMARY KEY, empresa TEXT NOT NULL REFERENCES empresas(id), login TEXT NOT NULL UNIQUE,
  nome TEXT NOT NULL, email TEXT NOT NULL, senha TEXT NOT NULL, ativo INTEGER NOT NULL DEFAULT 1, criado_em INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, tecnico TEXT NOT NULL REFERENCES tecnicos(id), expira INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS autorizacoes(rustdesk_id TEXT NOT NULL, tecnico TEXT NOT NULL, quando INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS autorizacoes_id ON autorizacoes(rustdesk_id, quando);
CREATE TABLE IF NOT EXISTS eventos(id TEXT PRIMARY KEY, hash TEXT NOT NULL, empresa TEXT, criado_em INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cobrancas(id TEXT PRIMARY KEY, empresa TEXT NOT NULL, evento TEXT NOT NULL, criado_em INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(id TEXT PRIMARY KEY, criado_em INTEGER NOT NULL);
'''


class Conecta:
    def __init__(self, dados=DADOS, env=None, relogio=lambda: int(time.time())):
        self.dados, self.env, self.relogio = dados, os.environ if env is None else env, relogio
        os.makedirs(dados, exist_ok=True)
        self.banco = os.path.join(dados, 'conecta.sqlite3')
        self.acessos = os.path.join(dados, 'acessos.jsonl')
        with self._db() as c:
            c.executescript(ESQUEMA)

    def _db(self):
        c = sqlite3.connect(self.banco, timeout=10, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        return _Transacao(c)

    def chave_publica(self):
        v = self.env.get('CONECTA_CONTROLE_CHAVE_PUBLICA', '')
        if self.env.get('CONECTA_CONTROLE_LICENCAS') != '1' or not re.fullmatch(r'[A-Za-z0-9_-]{43}', v):
            return None
        return _b64(v)

    # Programa do técnico -------------------------------------------------------------------------------------
    def login(self, corpo, ip):
        login = str(corpo.get('username') or '').strip().lower()[:80]
        senha = str(corpo.get('password') or '')[:200]
        agora = self.relogio()
        chave = (login, ip)
        with TRAVA:
            if len(FALHAS) > 10000:
                for k in [k for k, v in FALHAS.items() if not v or agora - v[-1] >= BLOQUEIO_SEG]:
                    del FALHAS[k]
            recentes = [t for t in FALHAS.get(chave, []) if agora - t < BLOQUEIO_SEG]
            FALHAS[chave] = recentes
        if len(recentes) >= TENTATIVAS:
            return {'error': 'Muitas tentativas. Aguarde 15 minutos e tente de novo.'}
        with self._db() as c:
            t = c.execute('SELECT * FROM tecnicos WHERE login=? AND ativo=1', (login,)).fetchone()
        if not confere_senha(senha, t['senha'] if t else _FALSO) or t is None:
            with TRAVA:
                FALHAS.setdefault(chave, []).append(agora)
            return {'error': 'Usuário ou senha incorretos.'}
        with TRAVA:
            FALHAS.pop(chave, None)
        with self._db() as c:
            e = c.execute('SELECT * FROM empresas WHERE id=?', (t['empresa'],)).fetchone()
            if bloqueada(e, agora):
                return {'error': MENSAGEM_BLOQUEIO}
            token = secrets.token_urlsafe(32)
            c.execute('DELETE FROM tokens WHERE expira<=?', (agora,))
            c.execute('INSERT INTO tokens VALUES(?,?,?)', (_sha(token), t['id'], agora + TOKEN_DIAS * DIA))
        return {'access_token': token, 'type': 'access_token', 'user': self._usuario(t, e)}

    @staticmethod
    def _usuario(t, e):
        return {'name': t['login'], 'display_name': t['nome'], 'email': t['email'], 'note': e['nome'], 'status': 1,
                'is_admin': False}

    def _pelo_token(self, autorizacao):
        if not autorizacao.startswith('Bearer ') or len(autorizacao) > 200:
            return None, None
        agora = self.relogio()
        with self._db() as c:
            t = c.execute('''SELECT t.* FROM tokens k JOIN tecnicos t ON t.id=k.tecnico
                             WHERE k.hash=? AND k.expira>? AND t.ativo=1''', (_sha(autorizacao[7:].strip()), agora)).fetchone()
            e = c.execute('SELECT * FROM empresas WHERE id=?', (t['empresa'],)).fetchone() if t else None
        return t, e

    def usuario_atual(self, autorizacao):
        t, e = self._pelo_token(autorizacao)
        if t is None or bloqueada(e, self.relogio()):
            raise Recusa(401, MENSAGEM_BLOQUEIO if t else 'Faça login de novo.')
        return self._usuario(t, e)

    def sair(self, autorizacao):
        if autorizacao.startswith('Bearer '):
            with self._db() as c:
                c.execute('DELETE FROM tokens WHERE hash=?', (_sha(autorizacao[7:].strip()),))
        return {}

    def autorizar(self, autorizacao, corpo):
        t, e = self._pelo_token(autorizacao)
        if t is None:
            raise Recusa(401, 'Aggilli Conecta: entre com o seu usuário de técnico (menu Conta) antes de conectar.')
        agora = self.relogio()
        if bloqueada(e, agora):
            raise Recusa(403, MENSAGEM_BLOQUEIO)
        meu = re.sub(r'\D', '', str(corpo.get('id') or ''))[:20]
        if meu:
            with self._db() as c:
                c.execute('INSERT INTO autorizacoes VALUES(?,?,?)', (meu, t['id'], agora))
                c.execute('DELETE FROM autorizacoes WHERE quando<?', (agora - 400 * DIA,))
        return {'ok': True, 'empresa': e['nome'], 'tecnico': t['login']}

    # Controle ------------------------------------------------------------------------------------------------
    def controle(self, cabecalhos, corpo_bruto):
        chave = self.chave_publica()
        if not chave:
            raise Recusa(503, 'Integração com o Controle desligada.')
        try:
            pedido = json.loads(corpo_bruto or b'{}').get('pedido')
        except (ValueError, AttributeError):
            raise Recusa(400, 'Pedido inválido.') from None
        if not isinstance(pedido, str) or len(pedido) > MAX_CORPO:
            raise Recusa(400, 'Pedido inválido.')
        h = lambda n: str(cabecalhos.get(n) or '')
        data, nonce, ator, assinatura = h('X-Aggilli-Data'), h('X-Aggilli-Nonce'), h('X-Aggilli-Ator'), h('X-Aggilli-Assinatura')
        agora = self.relogio()
        if not re.fullmatch(r'\d{10}', data) or abs(agora - int(data)) > JANELA or \
                not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', nonce) or ator != 'admin':
            raise Recusa(401, 'Pedido não autorizado.')
        try:
            ok = ed25519_verifica(chave, mensagem(pedido.encode(), data, nonce, ator), _b64(assinatura))
        except ValueError:
            ok = False
        if not ok:
            raise Recusa(401, 'Pedido não autorizado.')
        with self._db() as c:
            c.execute('DELETE FROM nonces WHERE criado_em<?', (agora - 2 * DIA,))
            try:
                c.execute('INSERT INTO nonces VALUES(?,?)', (nonce, agora))
            except sqlite3.IntegrityError:
                raise Recusa(409, 'Pedido repetido.') from None
        try:
            p = json.loads(pedido)
        except ValueError:
            raise Recusa(400, 'Pedido inválido.') from None
        if not isinstance(p, dict):
            raise Recusa(400, 'Pedido inválido.')
        return self.listar() if p.get('operacao') == 'listar' else self.mutar(p, pedido)

    def _vista(self, e, agora):
        return {'situacao': situacao(e, agora), 'status': e['status'], 'plano': e['plano'], 'tecnicos': e['tecnicos'],
                'valido_ate': e['valido_ate'], 'origem': e['origem'], 'revisao': e['revisao']}

    def listar(self):
        agora = self.relogio()
        with self._db() as c:
            empresas = c.execute('SELECT * FROM empresas ORDER BY criado_em').fetchall()
            tecnicos = c.execute('''SELECT t.id,t.empresa,t.login,t.nome,t.email,t.ativo,
                                    (SELECT MAX(quando) FROM autorizacoes a WHERE a.tecnico=t.id) ultimo
                                    FROM tecnicos t ORDER BY t.criado_em''').fetchall()
        por = {}
        for t in tecnicos:
            por.setdefault(t['empresa'], []).append({'id': t['id'], 'login': t['login'], 'nome': t['nome'], 'email': t['email'],
                                                     'ativo': bool(t['ativo']), 'ultimo_acesso': t['ultimo']})
        return {'empresas': [{'id': e['id'], 'nome': e['nome'], 'documento': e['documento'], 'criado_em': e['criado_em'],
                              'licenca': self._vista(e, agora), 'tecnicos': por.get(e['id'], [])} for e in empresas]}

    def mutar(self, p, pedido):
        evento = p.get('evento')
        if not isinstance(evento, str) or not re.fullmatch(r'[A-Za-z0-9._:-]{8,120}', evento):
            raise Recusa(422, 'Evento inválido.')
        hash_ = _sha(pedido)
        with TRAVA, self._db() as c:
            c.execute('BEGIN IMMEDIATE')
            antes = c.execute('SELECT * FROM eventos WHERE id=?', (evento,)).fetchone()
            if antes:
                if antes['hash'] != hash_:
                    raise Recusa(409, 'Evento repetido com conteúdo diferente.')
                e = c.execute('SELECT * FROM empresas WHERE id=?', (antes['empresa'],)).fetchone()
                return {'status': 'already_applied', 'id': antes['empresa'],
                        'licenca': self._vista(e, self.relogio()) if e else None}
            r = self._executar(c, p, evento)
            c.execute('INSERT INTO eventos VALUES(?,?,?,?)', (evento, hash_, r['id'], self.relogio()))
            return {'status': 'applied', **r}

    def _novo_tecnico(self, c, empresa, p, agora):
        email, nome = _email(p.get('email')), _texto(p.get('nome_tecnico') or p.get('nome'), 'o nome do técnico')
        if c.execute('SELECT 1 FROM tecnicos WHERE login=?', (email,)).fetchone():
            raise Recusa(409, 'Este e-mail já é login de um técnico.')
        senha, tid = senha_temporaria(), 'tec_' + secrets.token_hex(8)
        c.execute('INSERT INTO tecnicos VALUES(?,?,?,?,?,?,1,?)', (tid, empresa, email, nome, email, hash_senha(senha), agora))
        return {'id': tid, 'login': email, 'nome': nome, 'email': email}, senha

    def _executar(self, c, p, evento):
        agora, op = self.relogio(), p.get('operacao')
        if op in ('novo_teste', 'interno'):
            nome = _texto(p.get('nome'), 'o nome da empresa')
            if op == 'novo_teste':
                doc = _documento(p.get('documento'))
                if c.execute('SELECT 1 FROM empresas WHERE documento=?', (doc,)).fetchone():
                    raise Recusa(409, 'Já existe empresa com este CPF/CNPJ (um teste por documento).')
                linha = (doc, 'TRIAL', 'Teste', TESTE_TECNICOS, agora + TESTE_DIAS * DIA, 'controle')
            else:
                _texto(p.get('motivo'), 'o motivo', 300, 3)
                if c.execute("SELECT 1 FROM empresas WHERE status='INTERNO'").fetchone():
                    raise Recusa(409, 'A empresa interna da Aggilli já existe.')
                linha = (None, 'INTERNO', 'Interno', _inteiro(p.get('tecnicos'), 'Técnicos', 1, 50), None, 'interno')
            eid = 'emp_' + secrets.token_hex(8)
            c.execute('INSERT INTO empresas VALUES(?,?,?,?,NULL,?,?,?,?,1,?)', (eid, nome, linha[0], linha[1], linha[2], linha[3],
                                                                                 linha[4], linha[5], agora))
            tec, senha = self._novo_tecnico(c, eid, p, agora)
            e = c.execute('SELECT * FROM empresas WHERE id=?', (eid,)).fetchone()
            return {'id': eid, 'licenca': self._vista(e, agora), 'tecnico': tec, 'senha_temporaria': senha}
        e = c.execute('SELECT * FROM empresas WHERE id=?', (_texto(p.get('empresa'), 'a empresa', 40),)).fetchone()
        if e is None:
            raise Recusa(404, 'Empresa inexistente.')
        ativos = c.execute('SELECT COUNT(*) FROM tecnicos WHERE empresa=? AND ativo=1', (e['id'],)).fetchone()[0]
        if op == 'adicionar_tecnico':
            if bloqueada(e, agora):
                raise Recusa(409, 'Empresa vencida ou cancelada: regularize antes de adicionar técnicos.')
            if ativos >= e['tecnicos']:
                raise Recusa(409, f"A empresa já usa os {e['tecnicos']} técnico(s) contratados.")
            tec, senha = self._novo_tecnico(c, e['id'], p, agora)
            return {'id': e['id'], 'licenca': self._vista(e, agora), 'tecnico': tec, 'senha_temporaria': senha}
        if op in ('remover_tecnico', 'nova_senha'):
            t = c.execute('SELECT * FROM tecnicos WHERE id=? AND empresa=? AND ativo=1',
                          (_texto(p.get('tecnico'), 'o técnico', 40), e['id'])).fetchone()
            if t is None:
                raise Recusa(404, 'Técnico inexistente nesta empresa.')
            c.execute('DELETE FROM tokens WHERE tecnico=?', (t['id'],))
            if op == 'remover_tecnico':
                _texto(p.get('motivo'), 'o motivo', 300, 3)
                c.execute('UPDATE tecnicos SET ativo=0 WHERE id=?', (t['id'],))
                return {'id': e['id'], 'licenca': self._vista(e, agora)}
            senha = senha_temporaria()
            c.execute('UPDATE tecnicos SET senha=? WHERE id=?', (hash_senha(senha), t['id']))
            return {'id': e['id'], 'licenca': self._vista(e, agora), 'senha_temporaria': senha}
        if op != 'plano':
            raise Recusa(422, 'Operação desconhecida.')
        if e['status'] == 'INTERNO':
            raise Recusa(409, 'A empresa interna da Aggilli não tem plano.')
        acao = p.get('acao')
        novos = aplicar(e, acao, p, agora, ativos)
        if acao in ('liberar', 'renovar'):
            try:
                c.execute('INSERT INTO cobrancas VALUES(?,?,?,?)', (str(p['cobranca']), e['id'], evento, agora))
            except sqlite3.IntegrityError:
                raise Recusa(409, 'Cobrança já consumida.') from None
        if acao == 'cancelar':
            c.execute('DELETE FROM tokens WHERE tecnico IN (SELECT id FROM tecnicos WHERE empresa=?)', (e['id'],))
        sets = ', '.join(f'{k}=?' for k in novos)
        c.execute(f'UPDATE empresas SET {sets}, revisao=revisao+1 WHERE id=?', (*novos.values(), e['id']))
        e = c.execute('SELECT * FROM empresas WHERE id=?', (e['id'],)).fetchone()
        return {'id': e['id'], 'licenca': self._vista(e, agora)}

    # Registro de acessos -------------------------------------------------------------------------------------
    def gravar(self, tipo, aviso, origem):
        nonce = _corte(aviso.get('nonce'), 64)
        agora = time.time()
        with TRAVA:
            for chave in [n for n, t in NONCES_AUDIT.items() if agora - t > 600]:
                del NONCES_AUDIT[chave]
            if nonce and nonce in NONCES_AUDIT:
                return
            if nonce:
                NONCES_AUDIT[nonce] = agora
            peer = aviso.get('peer') if isinstance(aviso.get('peer'), list) else []
            linha = {
                'quando': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                'tipo': tipo,
                'acao': _corte(aviso.get('action'), 20),
                'id': _corte(aviso.get('id'), 20),
                'conn_id': _corte(aviso.get('conn_id'), 20),
                'sessao': _corte(aviso.get('session_id'), 40),
                'uuid': _corte(aviso.get('uuid'), 80),
                'ip': _corte(aviso.get('ip'), 60),
                'tecnico_id': _corte(peer[0] if len(peer) > 0 else '', 20),
                'tecnico_nome': _corte(peer[1] if len(peer) > 1 else '', 80),
                'modo': _corte(aviso.get('type'), 10),
                'origem': _corte(origem, 60),
            }
            with open(self.acessos, 'a', encoding='utf-8') as f:
                f.write(json.dumps(linha, ensure_ascii=False) + '\n')

    def registro(self, limite=500):
        sessoes = {}
        try:
            with open(self.acessos, encoding='utf-8') as f:
                linhas = f.readlines()[-20000:]
        except FileNotFoundError:
            linhas = []
        for bruta in linhas:
            try:
                a = json.loads(bruta)
            except ValueError:
                continue
            if a.get('tipo') != 'conn':
                continue
            chave = (a['uuid'] or a['id'], a['conn_id'])
            s = sessoes.get(chave)
            if s is None or (a['acao'] == 'new' and s.get('fim')):
                s = sessoes[chave] = {'cliente_id': a['id'], 'inicio': a['quando'], 'fim': '', 'ip_tecnico': '',
                                      'tecnico_id': '', 'tecnico_nome': '', 'modo': ''}
            if a['acao'] == 'new':
                s['inicio'] = a['quando']
                s['ip_tecnico'] = a['ip'] or a['origem']
            elif a['acao'] == 'close':
                s['fim'] = a['quando']
            if a['tecnico_id']:
                s['tecnico_id'] = a['tecnico_id']
                s['tecnico_nome'] = a['tecnico_nome']
                s['modo'] = MODOS.get(a['modo'], a['modo'])
        lista = sorted(sessoes.values(), key=lambda s: s['inicio'], reverse=True)[:limite]
        with self._db() as c:
            for s in lista:
                if s['fim']:
                    seg = (datetime.fromisoformat(s['fim']) - datetime.fromisoformat(s['inicio'])).total_seconds()
                    s['duracao_min'] = round(max(seg, 0) / 60, 1)
                else:
                    s['duracao_min'] = None
                s['empresa'], s['tecnico_login'] = '', ''
                if s['tecnico_id']:
                    inicio = int(datetime.fromisoformat(s['inicio']).timestamp())
                    q = c.execute('''SELECT t.login, e.nome FROM autorizacoes a JOIN tecnicos t ON t.id=a.tecnico
                                     JOIN empresas e ON e.id=t.empresa WHERE a.rustdesk_id=? AND a.quando<=?
                                     ORDER BY a.quando DESC LIMIT 1''', (s['tecnico_id'], inicio + 60)).fetchone()
                    if q:
                        s['tecnico_login'], s['empresa'] = q['login'], q['nome']
        return lista


MODOS = {'0': 'Controle da tela', '1': 'Arquivos', '2': 'Encaminhamento de porta', '3': 'Câmera', '4': 'Terminal'}


def _corte(valor, limite=120):
    return str(valor)[:limite] if valor is not None else ''


class _Transacao:
    def __init__(self, c):
        self.c = c

    def __enter__(self):
        return self.c

    def __exit__(self, tipo, *_):
        try:
            if self.c.in_transaction:
                self.c.execute('ROLLBACK' if tipo else 'COMMIT')
        finally:
            self.c.close()


# HTTP --------------------------------------------------------------------------------------------------------
def criar_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'aggilli-conecta'

        def _responder(self, codigo, corpo):
            dados = json.dumps(corpo, ensure_ascii=False).encode()
            self.send_response(codigo)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(dados)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(dados)

        def _ip(self):
            return (self.headers.get('X-Forwarded-For') or '').split(',')[0].strip()[:60] or self.client_address[0]

        def do_POST(self):
            tamanho = int(self.headers.get('Content-Length') or 0)
            if tamanho > MAX_CORPO:
                return self._responder(413, {'erro': 'grande demais'})
            bruto = self.rfile.read(tamanho) if tamanho else b''
            rota = self.path.split('?')[0]
            auth = self.headers.get('Authorization') or ''
            try:
                if rota == CAMINHO:
                    return self._responder(200, app.controle(self.headers, bruto))
                try:
                    corpo = json.loads(bruto or b'{}')
                    if not isinstance(corpo, dict):
                        raise ValueError
                except ValueError:
                    return self._responder(400, {'error': 'json invalido'})
                if rota.startswith('/api/audit/'):
                    app.gravar(rota.rsplit('/', 1)[-1][:10], corpo, self.headers.get('X-Forwarded-For', ''))
                    return self._responder(200, {})
                if rota == '/api/login':
                    return self._responder(200, app.login(corpo, self._ip()))
                if rota == '/api/currentUser':
                    return self._responder(200, app.usuario_atual(auth))
                if rota == '/api/logout':
                    return self._responder(200, app.sair(auth))
                if rota == '/api/aggilli/autorizar':
                    return self._responder(200, app.autorizar(auth, corpo))
                return self._responder(200, {})
            except Recusa as r:
                chave = 'detail' if rota == CAMINHO else 'error'
                return self._responder(r.status, {chave: str(r)})
            except Exception:
                return self._responder(500, {'error': 'Não foi possível concluir.'})

        def do_GET(self):
            rota = self.path.split('?')[0]
            if rota == '/registro.json':
                return self._responder(200, {'gerado_em': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                                             'sessoes': app.registro()})
            if rota == '/api/login-options':
                return self._responder(200, [])
            return self._responder(200, {})

        def log_message(self, *args):
            pass

    return Handler


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8070), criar_handler(Conecta())).serve_forever()
