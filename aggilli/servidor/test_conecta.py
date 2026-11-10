"""Servidor do Aggilli Conecta: login do técnico, trava por licença e pedidos assinados do Controle.

Rodar: python -m unittest aggilli/servidor/test_conecta.py (precisa do pacote cryptography só para assinar nos testes).
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conecta  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

DIA = conecta.DIA


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.chave = Ed25519PrivateKey.generate()
        pub = self.chave.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.agora = 1_800_000_000
        self.app = conecta.Conecta(self.tmp.name, env={'CONECTA_CONTROLE_LICENCAS': '1', 'CONECTA_CONTROLE_CHAVE_PUBLICA': b64(pub)},
                                   relogio=lambda: self.agora)
        conecta.FALHAS.clear()

    def pedir(self, payload, ator='admin', chave=None, data=None, nonce=None):
        pedido = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        data, nonce = data or str(self.agora), nonce or secrets.token_urlsafe(24)
        assin = (chave or self.chave).sign(conecta.mensagem(pedido.encode(), data, nonce, ator))
        h = {'X-Aggilli-Data': data, 'X-Aggilli-Nonce': nonce, 'X-Aggilli-Ator': ator, 'X-Aggilli-Assinatura': b64(assin)}
        return self.app.controle(h, json.dumps({'pedido': pedido}).encode())

    def criar(self, doc='12345678901', email='ana@suporte.test'):
        return self.pedir({'operacao': 'novo_teste', 'evento': 'controle-teste-' + secrets.token_hex(6), 'nome': 'Suporte Ana',
                           'documento': doc, 'email': email, 'nome_tecnico': 'Ana Souza'})

    def plano(self, emp, acao, evento=None, **extra):
        return self.pedir({'operacao': 'plano', 'empresa': emp, 'acao': acao,
                           'evento': evento or f'controle-{acao}-{secrets.token_hex(6)}', **extra})


class Ed25519Test(unittest.TestCase):
    def test_confere_com_a_biblioteca_e_recusa_alteracao(self):
        k = Ed25519PrivateKey.generate()
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        for msg in (b'', b'abc', os.urandom(300)):
            s = k.sign(msg)
            self.assertTrue(conecta.ed25519_verifica(pub, msg, s))
            self.assertFalse(conecta.ed25519_verifica(pub, msg + b'x', s))
            self.assertFalse(conecta.ed25519_verifica(pub, msg, s[:-1] + bytes([s[-1] ^ 1])))
        self.assertFalse(conecta.ed25519_verifica(pub, b'abc', b'\0' * 64))

    def test_vetor_rfc8032(self):
        pub = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        sig = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                            '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.assertTrue(conecta.ed25519_verifica(pub, b'', sig))


class ControleTest(Base):
    def test_assinatura_janela_ator_e_nonce(self):
        outra = Ed25519PrivateKey.generate()
        for kw in ({'chave': outra}, {'ator': 'gerente'}, {'data': str(self.agora - 301)}):
            with self.assertRaises(conecta.Recusa) as r:
                self.pedir({'operacao': 'listar'}, **kw)
            self.assertEqual(r.exception.status, 401, kw)
        self.pedir({'operacao': 'listar'}, nonce='n' * 20)
        with self.assertRaises(conecta.Recusa) as r:
            self.pedir({'operacao': 'listar'}, nonce='n' * 20)
        self.assertEqual(r.exception.status, 409)

    def test_desligado_sem_chave(self):
        app = conecta.Conecta(self.tmp.name, env={})
        with self.assertRaises(conecta.Recusa) as r:
            app.controle({}, b'{}')
        self.assertEqual(r.exception.status, 503)

    def test_novo_teste_um_por_documento_e_senha_so_na_resposta(self):
        r = self.criar()
        self.assertEqual(r['licenca']['status'], 'TRIAL')
        self.assertEqual(r['licenca']['valido_ate'], self.agora + 7 * DIA)
        self.assertEqual(r['licenca']['tecnicos'], 3)
        senha = r['senha_temporaria']
        dados = Path(self.tmp.name)
        for arq in dados.iterdir():
            self.assertNotIn(senha.encode(), arq.read_bytes(), arq)
        with self.assertRaises(conecta.Recusa) as x:
            self.criar(email='outra@suporte.test')
        self.assertEqual(x.exception.status, 409)
        lista = self.pedir({'operacao': 'listar'})['empresas']
        self.assertEqual([t['login'] for t in lista[0]['tecnicos']], ['ana@suporte.test'])
        self.assertNotIn('senha', json.dumps(lista))

    def test_evento_repetido_nao_duplica(self):
        payload = {'operacao': 'novo_teste', 'evento': 'controle-teste-fixo1', 'nome': 'Suporte Ana', 'documento': '12345678901',
                   'email': 'ana@suporte.test', 'nome_tecnico': 'Ana Souza'}
        r1 = self.pedir(payload)
        r2 = self.pedir(payload)
        self.assertEqual((r1['status'], r2['status']), ('applied', 'already_applied'))
        self.assertNotIn('senha_temporaria', r2)
        with self.assertRaises(conecta.Recusa):
            self.pedir({**payload, 'nome': 'Outro'})
        self.assertEqual(len(self.pedir({'operacao': 'listar'})['empresas']), 1)

    def test_limite_de_tecnicos(self):
        emp = self.criar()['id']
        for i in range(2):
            self.pedir({'operacao': 'adicionar_tecnico', 'evento': f'controle-tec-{i}xxxx', 'empresa': emp,
                        'email': f't{i}@suporte.test', 'nome_tecnico': f'Técnico {i}'})
        with self.assertRaises(conecta.Recusa) as r:
            self.pedir({'operacao': 'adicionar_tecnico', 'evento': 'controle-tec-9xxxx', 'empresa': emp,
                        'email': 't9@suporte.test', 'nome_tecnico': 'Técnico 9'})
        self.assertEqual(r.exception.status, 409)

    def test_liberar_so_pago_cobranca_uma_vez_e_renovar_empilha(self):
        emp = self.criar()['id']
        pago = {'plano': 'Equipe', 'tecnicos': 3, 'dias': 30, 'centavos': 13500, 'modo': 'manual'}
        for ruim in ({'modo': 'stripe_test'}, {'modo': None}, {'centavos': 0}, {'cobranca': 'abc'}, {'plano': 'Marca própria'},
                     {'tecnicos': 1}):
            with self.assertRaises(conecta.Recusa, msg=ruim):
                self.plano(emp, 'liberar', **{**pago, 'cobranca': '41', **ruim})
        r = self.plano(emp, 'liberar', evento='controle-cobranca-41', **pago, cobranca='41')
        self.assertEqual((r['licenca']['status'], r['licenca']['valido_ate']), ('PAID', self.agora + 30 * DIA))
        with self.assertRaises(conecta.Recusa) as x:
            self.plano(emp, 'renovar', **pago, cobranca='41')
        self.assertEqual(str(x.exception), 'Cobrança já consumida.')
        r = self.plano(emp, 'renovar', evento='controle-cobranca-42', **pago, cobranca='42')
        self.assertEqual(r['licenca']['valido_ate'], self.agora + 60 * DIA)

    def test_carencia_so_pago_cancelar_e_reativar(self):
        emp = self.criar()['id']
        with self.assertRaises(conecta.Recusa):
            self.plano(emp, 'carencia', dias=5, motivo='pediu')
        r = self.plano(emp, 'prorrogar', dias=5, motivo='pediu mais')
        self.assertEqual(r['licenca']['valido_ate'], self.agora + 12 * DIA)
        self.assertEqual(self.plano(emp, 'cancelar', motivo='desistiu')['licenca']['situacao'], 'cancelado')
        self.assertEqual(self.plano(emp, 'reativar', motivo='voltou')['licenca']['status'], 'TRIAL')

    def test_interno_uma_vez_sem_vencimento_e_sem_plano(self):
        r = self.pedir({'operacao': 'interno', 'evento': 'controle-interno-1', 'nome': 'Aggilli', 'tecnicos': 5,
                        'motivo': 'suporte da Aggilli', 'email': 'suporte@aggilli.test', 'nome_tecnico': 'Suporte'})
        self.assertEqual(r['licenca']['situacao'], 'interno')
        self.agora += 999 * DIA
        self.assertIn('access_token', self.app.login({'username': 'suporte@aggilli.test', 'password': r['senha_temporaria']}, '1.1.1.1'))
        with self.assertRaises(conecta.Recusa):
            self.plano(r['id'], 'cancelar', motivo='nao')
        with self.assertRaises(conecta.Recusa):
            self.pedir({'operacao': 'interno', 'evento': 'controle-interno-2', 'nome': 'Aggilli', 'tecnicos': 5,
                        'motivo': 'de novo', 'email': 'x@aggilli.test', 'nome_tecnico': 'X'})


class TecnicoTest(Base):
    def test_login_autorizar_e_trava_quando_vence(self):
        r = self.criar()
        login = self.app.login({'username': 'ANA@suporte.test', 'password': r['senha_temporaria']}, '9.9.9.9')
        self.assertEqual(login['type'], 'access_token')
        self.assertEqual(login['user']['note'], 'Suporte Ana')
        auth = 'Bearer ' + login['access_token']
        self.assertTrue(self.app.autorizar(auth, {'id': '123456789'})['ok'])
        self.assertEqual(self.app.usuario_atual(auth)['name'], 'ana@suporte.test')
        self.agora += 8 * DIA
        with self.assertRaises(conecta.Recusa) as x:
            self.app.autorizar(auth, {'id': '123456789'})
        self.assertEqual(x.exception.status, 403)
        with self.assertRaises(conecta.Recusa) as x:
            self.app.usuario_atual(auth)
        self.assertEqual(x.exception.status, 401)
        self.assertIn('vencida', self.app.login({'username': 'ana@suporte.test', 'password': r['senha_temporaria']}, '9.9.9.9')['error'])

    def test_sem_login_nao_autoriza_e_senha_errada_bloqueia(self):
        with self.assertRaises(conecta.Recusa) as x:
            self.app.autorizar('', {})
        self.assertEqual(x.exception.status, 401)
        r = self.criar()
        for _ in range(conecta.TENTATIVAS):
            self.assertIn('incorretos', self.app.login({'username': 'ana@suporte.test', 'password': 'errada'}, '8.8.8.8')['error'])
        self.assertIn('Muitas tentativas', self.app.login({'username': 'ana@suporte.test', 'password': r['senha_temporaria']}, '8.8.8.8')['error'])

    def test_remover_tecnico_derruba_o_login(self):
        r = self.criar()
        auth = 'Bearer ' + self.app.login({'username': 'ana@suporte.test', 'password': r['senha_temporaria']}, '1.1.1.1')['access_token']
        self.pedir({'operacao': 'remover_tecnico', 'evento': 'controle-rem-12345', 'empresa': r['id'], 'tecnico': r['tecnico']['id'],
                    'motivo': 'saiu da empresa'})
        with self.assertRaises(conecta.Recusa):
            self.app.autorizar(auth, {})

    def test_registro_mostra_empresa_do_tecnico(self):
        r = self.criar()
        auth = 'Bearer ' + self.app.login({'username': 'ana@suporte.test', 'password': r['senha_temporaria']}, '1.1.1.1')['access_token']
        from datetime import datetime, timezone
        real = datetime.now(timezone.utc).timestamp()
        self.agora = int(real)
        self.app.autorizar(auth, {'id': '555 666 777'})
        self.app.gravar('conn', {'action': 'new', 'id': '111', 'conn_id': '1', 'uuid': 'u', 'ip': '2.2.2.2'}, '')
        self.app.gravar('conn', {'action': '', 'id': '111', 'conn_id': '1', 'uuid': 'u', 'peer': ['555666777', 'Ana'], 'type': '0'}, '')
        s = self.app.registro()[0]
        self.assertEqual((s['empresa'], s['tecnico_login'], s['modo']), ('Suporte Ana', 'ana@suporte.test', 'Controle da tela'))


class HttpTest(Base):
    def test_rotas_http(self):
        srv = ThreadingHTTPServer(('127.0.0.1', 0), conecta.criar_handler(self.app))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close); self.addCleanup(srv.shutdown)
        url = f'http://127.0.0.1:{srv.server_port}'

        def post(rota, corpo, h=None):
            req = urllib.request.Request(url + rota, json.dumps(corpo).encode(), {'Content-Type': 'application/json', **(h or {})})
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        self.assertEqual(post('/api/login', {'username': 'x', 'password': 'y'}), (200, {'error': 'Usuário ou senha incorretos.'}))
        st, corpo = post('/api/aggilli/autorizar', {})
        self.assertEqual(st, 401)
        self.assertIn('error', corpo)
        self.assertEqual(post('/api/audit/conn', {'action': 'new', 'id': '1', 'conn_id': '2'}), (200, {}))
        self.assertEqual(post('/api/aggilli/controle', {'pedido': '{}'})[0], 401)
        with urllib.request.urlopen(url + '/api/login-options') as r:
            self.assertEqual(json.loads(r.read()), [])


if __name__ == '__main__':
    unittest.main()
