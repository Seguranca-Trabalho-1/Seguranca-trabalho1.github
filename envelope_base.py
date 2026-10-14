import base64
import binascii
import json
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAMANHO_CHAVE = 32   # AES-256 -> 256 bits = 32 bytes
TAMANHO_IV = 16      # 128 bits = 16 bytes
TAMANHO_BLOCO = 128  # bits (PKCS#7 para AES)

CODIFICACOES_VALIDAS = ("Base64", "Hex")
HASHES_VALIDOS = ("SHA-256", "SHA-512")

ALGORITMO_SIMETRICO = "AES-256-CBC"
PADDING_SIMETRICO = "PKCS7"
ALGORITMO_CHAVE = "RSA-OAEP"
ALGORITMO_ASSINATURA = "RSA"

CAMPOS_PARAMETROS = (
    "algoritmo_simetrico",
    "padding_simetrico",
    "algoritmo_chave",
    "hash_oaep",
    "algoritmo_assinatura",
    "hash_assinatura",
    "codificacao",
)
CAMPOS_ENVELOPE = ("iv", "chave_sessao", "mensagem_cifrada", "assinatura")


class EnvelopeError(Exception):
    """Erro tratável, com mensagem pensada para o usuário corrigir o problema."""

def validar_codificacao(codificacao: str) -> str:
    if codificacao not in CODIFICACOES_VALIDAS:
        raise EnvelopeError(
            f"Codificação inválida: {codificacao!r}. "
            f"Use um dos valores: {', '.join(CODIFICACOES_VALIDAS)}."
        )
    return codificacao


def codificar(dados: bytes, codificacao: str) -> str:
    validar_codificacao(codificacao)
    if not isinstance(dados, (bytes, bytearray)):
        raise EnvelopeError("Os dados a codificar devem ser bytes.")
    if codificacao == "Base64":
        return base64.b64encode(bytes(dados)).decode("ascii")
    return bytes(dados).hex()


def decodificar(texto: str, codificacao: str, nome_campo: str = "campo") -> bytes:
    validar_codificacao(codificacao)
    if not isinstance(texto, str):
        raise EnvelopeError(f"O {nome_campo} deve ser uma string em {codificacao}.")
    texto = texto.strip()
    try:
        if codificacao == "Base64":
            return base64.b64decode(texto, validate=True)
        return bytes.fromhex(texto)
    except (binascii.Error, ValueError):
        raise EnvelopeError(
            f"O {nome_campo} não é um {codificacao} válido (dado corrompido ou "
            f"codificação diferente da declarada em 'parametros.codificacao')."
        )

def gerar_chave_sessao() -> bytes:
    return os.urandom(TAMANHO_CHAVE)


def gerar_iv() -> bytes:
    return os.urandom(TAMANHO_IV)

def _validar_chave_iv(chave: bytes, iv: bytes) -> None:
    if len(chave) != TAMANHO_CHAVE:
        raise EnvelopeError(
            f"Chave de sessão com tamanho inválido: {len(chave)} bytes "
            f"(esperado: {TAMANHO_CHAVE} bytes = AES-256)."
        )
    if len(iv) != TAMANHO_IV:
        raise EnvelopeError(
            f"IV com tamanho inválido: {len(iv)} bytes (esperado: {TAMANHO_IV} bytes)."
        )


def cifrar_aes_cbc(texto_claro: bytes, chave: bytes, iv: bytes) -> bytes:
    _validar_chave_iv(chave, iv)
    try:
        padder = padding.PKCS7(TAMANHO_BLOCO).padder()
        preenchido = padder.update(texto_claro) + padder.finalize()
        cifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
        return cifrador.update(preenchido) + cifrador.finalize()
    except Exception as e:  # falha inesperada da biblioteca
        raise EnvelopeError(f"Falha ao cifrar a mensagem com AES-256-CBC: {e}")


def decifrar_aes_cbc(criptograma: bytes, chave: bytes, iv: bytes) -> bytes:
    _validar_chave_iv(chave, iv)
    if len(criptograma) == 0 or len(criptograma) % 16 != 0:
        raise EnvelopeError(
            f"Criptograma com tamanho inválido ({len(criptograma)} bytes): "
            "deve ser um múltiplo de 16 bytes e não vazio. Dado possivelmente corrompido."
        )
    try:
        decifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
        preenchido = decifrador.update(criptograma) + decifrador.finalize()
        unpadder = padding.PKCS7(TAMANHO_BLOCO).unpadder()
        return unpadder.update(preenchido) + unpadder.finalize()
    except ValueError:
        raise EnvelopeError(
            "Falha ao remover o padding PKCS#7: chave de sessão ou IV incorretos, "
            "ou criptograma corrompido."
        )
    except Exception as e:
        raise EnvelopeError(f"Falha ao decifrar a mensagem com AES-256-CBC: {e}")

def ler_texto_utf8(caminho: str) -> bytes:
    """Lê o arquivo de texto em claro e garante que é UTF-8 válido. Retorna bytes."""
    try:
        with open(caminho, "rb") as f:
            dados = f.read()
    except FileNotFoundError:
        raise EnvelopeError(f"Arquivo não encontrado: {caminho!r}.")
    except IsADirectoryError:
        raise EnvelopeError(f"{caminho!r} é um diretório, informe um arquivo.")
    except PermissionError:
        raise EnvelopeError(f"Sem permissão para ler o arquivo: {caminho!r}.")
    except OSError as e:
        raise EnvelopeError(f"Erro ao ler {caminho!r}: {e.strerror or e}.")
    try:
        dados.decode("utf-8")
    except UnicodeDecodeError:
        raise EnvelopeError(f"O arquivo {caminho!r} não está em UTF-8 válido.")
    return dados


def gravar_arquivo(caminho: str, dados: bytes) -> None:
    try:
        with open(caminho, "wb") as f:
            f.write(dados)
    except IsADirectoryError:
        raise EnvelopeError(f"{caminho!r} é um diretório, informe um nome de arquivo.")
    except FileNotFoundError:
        raise EnvelopeError(f"Diretório de destino inexistente para {caminho!r}.")
    except PermissionError:
        raise EnvelopeError(f"Sem permissão para gravar em: {caminho!r}.")
    except OSError as e:
        raise EnvelopeError(f"Erro ao gravar {caminho!r}: {e.strerror or e}.")

def montar_envelope(
    iv: str,
    chave_sessao: str,
    mensagem_cifrada: str,
    assinatura: str,
    codificacao: str = "Base64",
    hash_oaep: str = "SHA-256",
    hash_assinatura: str = "SHA-256",
) -> dict:
    validar_codificacao(codificacao)
    for nome, valor in (("hash_oaep", hash_oaep), ("hash_assinatura", hash_assinatura)):
        if valor not in HASHES_VALIDOS:
            raise EnvelopeError(
                f"{nome} inválido: {valor!r}. Use: {', '.join(HASHES_VALIDOS)}."
            )
    return {
        "parametros": {
            "algoritmo_simetrico": ALGORITMO_SIMETRICO,
            "padding_simetrico": PADDING_SIMETRICO,
            "algoritmo_chave": ALGORITMO_CHAVE,
            "hash_oaep": hash_oaep,
            "algoritmo_assinatura": ALGORITMO_ASSINATURA,
            "hash_assinatura": hash_assinatura,
            "codificacao": codificacao,
        },
        "envelope": {
            "iv": iv,
            "chave_sessao": chave_sessao,
            "mensagem_cifrada": mensagem_cifrada,
            "assinatura": assinatura,
        },
    }


def salvar_envelope_json(caminho: str, envelope: dict) -> None:
    try:
        texto = json.dumps(envelope, indent=2, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise EnvelopeError(f"Não foi possível serializar o envelope em JSON: {e}")
    gravar_arquivo(caminho, (texto + "\n").encode("utf-8"))


def carregar_envelope_json(caminho: str) -> dict:
    bruto = ler_texto_utf8(caminho)
    try:
        env = json.loads(bruto.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise EnvelopeError(
            f"JSON inválido em {caminho!r}: {e.msg} (linha {e.lineno}, coluna {e.colno})."
        )
    validar_envelope(env)
    return env


def validar_envelope(env: dict) -> None:
    if not isinstance(env, dict):
        raise EnvelopeError("O JSON do envelope deve ser um objeto na raiz.")
    for secao, campos in (("parametros", CAMPOS_PARAMETROS), ("envelope", CAMPOS_ENVELOPE)):
        if not isinstance(env.get(secao), dict):
            raise EnvelopeError(f"Seção obrigatória ausente ou inválida: '{secao}'.")
        faltando = [c for c in campos if c not in env[secao]]
        if faltando:
            raise EnvelopeError(
                f"Campos ausentes em '{secao}': {', '.join(faltando)}."
            )

    p = env["parametros"]
    fixos = {
        "algoritmo_simetrico": ALGORITMO_SIMETRICO,
        "padding_simetrico": PADDING_SIMETRICO,
        "algoritmo_chave": ALGORITMO_CHAVE,
        "algoritmo_assinatura": ALGORITMO_ASSINATURA,
    }
    for campo, esperado in fixos.items():
        if p[campo] != esperado:
            raise EnvelopeError(
                f"parametros.{campo} = {p[campo]!r} não suportado (esperado: {esperado!r})."
            )
    for campo in ("hash_oaep", "hash_assinatura"):
        if p[campo] not in HASHES_VALIDOS:
            raise EnvelopeError(
                f"parametros.{campo} = {p[campo]!r} inválido. Use: {', '.join(HASHES_VALIDOS)}."
            )
    validar_codificacao(p["codificacao"])

    for campo in CAMPOS_ENVELOPE:
        if not isinstance(env["envelope"][campo], str):
            raise EnvelopeError(f"envelope.{campo} deve ser uma string.")

def cifrar_mensagem(texto_claro: bytes, codificacao: str):

    validar_codificacao(codificacao)
    chave = gerar_chave_sessao()
    iv = gerar_iv()
    criptograma = cifrar_aes_cbc(texto_claro, chave, iv)
    return (
        chave,
        iv,
        codificar(iv, codificacao),
        codificar(chave, codificacao),
        codificar(criptograma, codificacao),
    )


def decifrar_mensagem(mensagem_cifrada: str, chave_codificada: str, iv_codificado: str,
                      codificacao: str) -> bytes:
    chave = decodificar(chave_codificada, codificacao, "chave de sessão")
    iv = decodificar(iv_codificado, codificacao, "iv")
    criptograma = decodificar(mensagem_cifrada, codificacao, "mensagem_cifrada")
    return decifrar_aes_cbc(criptograma, chave, iv)
