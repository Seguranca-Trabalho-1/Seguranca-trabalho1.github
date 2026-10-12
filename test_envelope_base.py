import json
import os
import subprocess
import tempfile
import unittest

import envelope_base as eb


class TestCodificacoes(unittest.TestCase):
    def test_ida_e_volta(self):
        dados = bytes(range(256))
        for cod in eb.CODIFICACOES_VALIDAS:
            self.assertEqual(eb.decodificar(eb.codificar(dados, cod), cod), dados)

    def test_invalidas(self):
        with self.assertRaises(eb.EnvelopeError):
            eb.codificar(b"x", "Base32")
        with self.assertRaises(eb.EnvelopeError):
            eb.decodificar("@@@", "Base64")
        with self.assertRaises(eb.EnvelopeError):
            eb.decodificar("zz", "Hex")
        with self.assertRaises(eb.EnvelopeError):
            eb.decodificar(123, "Hex")


class TestAES(unittest.TestCase):
    def test_vetor_nist_sp800_38a_f25(self):
        # AES-256 CBC, bloco 1 (NIST SP 800-38A, F.2.5)
        chave = bytes.fromhex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        ct = eb.cifrar_aes_cbc(pt, chave, iv)
        self.assertEqual(ct[:16].hex(), "f58c4c04d6e5f1ba779eabfb5f7bfbd6")

    def test_roundtrip_utf8_e_tamanhos(self):
        for texto in ["", "a", "x" * 15, "x" * 16, "x" * 17, "Olá, Segurança! çãõ 🔐"]:
            pt = texto.encode("utf-8")
            chave, iv = eb.gerar_chave_sessao(), eb.gerar_iv()
            ct = eb.cifrar_aes_cbc(pt, chave, iv)
            self.assertEqual(len(ct) % 16, 0)
            self.assertGreater(len(ct), len(pt))  # PKCS7 sempre acrescenta
            self.assertEqual(eb.decifrar_aes_cbc(ct, chave, iv), pt)

    def test_tamanhos_de_segredos(self):
        self.assertEqual(len(eb.gerar_chave_sessao()), 32)
        self.assertEqual(len(eb.gerar_iv()), 16)
        self.assertNotEqual(eb.gerar_iv(), eb.gerar_iv())

    def test_erros(self):
        chave, iv = eb.gerar_chave_sessao(), eb.gerar_iv()
        ct = eb.cifrar_aes_cbc(b"mensagem", chave, iv)
        with self.assertRaises(eb.EnvelopeError):
            eb.cifrar_aes_cbc(b"m", b"curta", iv)
        with self.assertRaises(eb.EnvelopeError):
            eb.cifrar_aes_cbc(b"m", chave, b"curto")
        with self.assertRaises(eb.EnvelopeError):
            eb.decifrar_aes_cbc(ct[:-1], chave, iv)       # tamanho inválido
        with self.assertRaises(eb.EnvelopeError):
            eb.decifrar_aes_cbc(b"", chave, iv)
        with self.assertRaises(eb.EnvelopeError):          # chave errada
            for _ in range(50):  # padding aleatório pode passar raramente
                eb.decifrar_aes_cbc(ct, eb.gerar_chave_sessao(), iv)

    def test_fluxo_completo(self):
        for cod in eb.CODIFICACOES_VALIDAS:
            pt = "Texto de teste ação".encode("utf-8")
            chave, iv, iv_c, ch_c, msg_c = eb.cifrar_mensagem(pt, cod)
            self.assertEqual(eb.decifrar_mensagem(msg_c, ch_c, iv_c, cod), pt)

    def test_interop_openssl(self):
        """O criptograma gerado deve ser decifrável pelo OpenSSL (e vice-versa)."""
        chave, iv = eb.gerar_chave_sessao(), eb.gerar_iv()
        pt = "interoperabilidade com OpenSSL".encode()
        ct = eb.cifrar_aes_cbc(pt, chave, iv)
        r = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-K", chave.hex(), "-iv", iv.hex()],
            input=ct, capture_output=True)
        self.assertEqual(r.stdout, pt)
        r = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-K", chave.hex(), "-iv", iv.hex()],
            input=pt, capture_output=True)
        self.assertEqual(r.stdout, ct)


class TestIO(unittest.TestCase):
    def test_arquivos(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "msg.txt")
            eb.gravar_arquivo(p, "olá".encode())
            self.assertEqual(eb.ler_texto_utf8(p), "olá".encode())
            with self.assertRaises(eb.EnvelopeError):
                eb.ler_texto_utf8(os.path.join(d, "nao_existe.txt"))
            with self.assertRaises(eb.EnvelopeError):
                eb.ler_texto_utf8(d)  # diretório
            bin_ = os.path.join(d, "bin.dat")
            eb.gravar_arquivo(bin_, b"\xff\xfe\xfa")
            with self.assertRaises(eb.EnvelopeError):
                eb.ler_texto_utf8(bin_)  # não UTF-8
            with self.assertRaises(eb.EnvelopeError):
                eb.gravar_arquivo(os.path.join(d, "x", "y.txt"), b"1")


class TestJSON(unittest.TestCase):
    def _env(self, cod="Base64"):
        return eb.montar_envelope("iv", "ch", "msg", "sig", codificacao=cod)

    def test_estrutura_igual_ao_enunciado(self):
        env = self._env()
        self.assertEqual(list(env), ["parametros", "envelope"])
        self.assertEqual(list(env["parametros"]), list(eb.CAMPOS_PARAMETROS))
        self.assertEqual(list(env["envelope"]), list(eb.CAMPOS_ENVELOPE))
        self.assertEqual(env["parametros"]["algoritmo_simetrico"], "AES-256-CBC")
        self.assertEqual(env["parametros"]["padding_simetrico"], "PKCS7")
        self.assertEqual(env["parametros"]["algoritmo_chave"], "RSA-OAEP")
        self.assertEqual(env["parametros"]["algoritmo_assinatura"], "RSA")

    def test_salvar_e_carregar(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "envelope.json")
            env = self._env("Hex")
            eb.salvar_envelope_json(p, env)
            self.assertEqual(eb.carregar_envelope_json(p), env)

    def test_json_invalido_e_campos_faltando(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "e.json")
            eb.gravar_arquivo(p, b"{ nao e json")
            with self.assertRaises(eb.EnvelopeError):
                eb.carregar_envelope_json(p)
            eb.gravar_arquivo(p, b"[]")
            with self.assertRaises(eb.EnvelopeError):
                eb.carregar_envelope_json(p)
            env = self._env()
            del env["envelope"]["iv"]
            eb.gravar_arquivo(p, json.dumps(env).encode())
            with self.assertRaises(eb.EnvelopeError):
                eb.carregar_envelope_json(p)
            env = self._env()
            env["parametros"]["hash_oaep"] = "MD5"
            eb.gravar_arquivo(p, json.dumps(env).encode())
            with self.assertRaises(eb.EnvelopeError):
                eb.carregar_envelope_json(p)
            env = self._env()
            env["parametros"]["codificacao"] = "Base32"
            eb.gravar_arquivo(p, json.dumps(env).encode())
            with self.assertRaises(eb.EnvelopeError):
                eb.carregar_envelope_json(p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
