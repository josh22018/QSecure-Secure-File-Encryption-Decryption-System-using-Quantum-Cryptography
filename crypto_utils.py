import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC


def aes_encrypt(data: bytes):
    key = get_random_bytes(16)
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    return key, iv, tag, ct


def aes_decrypt(key: bytes, iv: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)


def wrap_key_hybrid(key: bytes, rsa_pub_bytes: bytes) -> str:
    rsa = RSA.import_key(rsa_pub_bytes)
    cipher = PKCS1_OAEP.new(rsa)
    return cipher.encrypt(key).hex()


def unwrap_key_hybrid(wrapped_hex: str, rsa_priv_bytes: bytes) -> bytes:
    wrapped = bytes.fromhex(wrapped_hex)
    rsa = RSA.import_key(rsa_priv_bytes)
    cipher = PKCS1_OAEP.new(rsa)
    return cipher.decrypt(wrapped)


def wrap_key_xor(key: bytes, param_blob: str) -> str:
    kdf = SHA256.new(param_blob.encode()).digest()
    wrapped = bytes(key[i] ^ kdf[i] for i in range(len(key)))
    return wrapped.hex()


def unwrap_key_xor(wrapped_hex: str, param_blob: str) -> bytes:
    wrapped = bytes.fromhex(wrapped_hex)
    kdf = SHA256.new(param_blob.encode()).digest()
    return bytes(wrapped[i] ^ kdf[i] for i in range(len(wrapped)))


def hmac_params(params_json: str, key: bytes) -> str:
    h = HMAC.new(key, params_json.encode(), digestmod=SHA256)
    return h.hexdigest()


def verify_hmac_params(params_json: str, key: bytes, hmac_hex: str) -> bool:
    h = HMAC.new(key, params_json.encode(), digestmod=SHA256)
    try:
        h.verify(bytes.fromhex(hmac_hex))
        return True
    except ValueError:
        return False
