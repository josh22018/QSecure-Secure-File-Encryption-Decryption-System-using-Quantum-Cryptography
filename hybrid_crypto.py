# hybrid_crypto.py

import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def generate_keys(key_size: int = 4096):
    """
    Generates an RSA keypair of `key_size` bits.
    Returns (private_pem, public_pem).
    """
    key = RSA.generate(key_size)
    priv = key.export_key()
    pub  = key.publickey().export_key()
    return priv, pub

def encrypt_hybrid(data: bytes, public_pem: bytes) -> bytes:
    """
    Hybrid encrypt:
      1) AES-256-GCM of the data → iv||tag||ciphertext
      2) RSA-OAEP(SHA-256) wrap of the AES key
      3) Pack → 4-byte keylen || wrapped_key || iv || tag || ciphertext
    """
    # -- Symmetric layer
    aes_key = get_random_bytes(32)
    iv      = get_random_bytes(12)
    aes     = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = aes.encrypt_and_digest(data)

    # -- Asymmetric wrap
    rsa       = RSA.import_key(public_pem)
    oaep      = PKCS1_OAEP.new(rsa, hashAlgo=SHA256, mgfunc=lambda x,y: PKCS1_OAEP.MGF1(x,y,SHA256))
    wrapped   = oaep.encrypt(aes_key)

    # -- Package lengths + blobs
    blob = (
        struct.pack(">I", len(wrapped)) +
        wrapped +
        iv +
        tag +
        ciphertext
    )
    return blob

def decrypt_hybrid(blob: bytes, private_pem: bytes) -> bytes:
    """
    Unpacks and decrypts the blob from encrypt_hybrid().
    """
    # 1) read lengths
    keylen = struct.unpack(">I", blob[:4])[0]
    off    = 4
    wrapped = blob[off:off+keylen]; off += keylen
    iv      = blob[off:off+12];    off += 12
    tag     = blob[off:off+16];    off += 16
    ct      = blob[off:]

    # 2) RSA-OAEP unwrap
    rsa      = RSA.import_key(private_pem)
    oaep     = PKCS1_OAEP.new(rsa, hashAlgo=SHA256, mgfunc=lambda x,y: PKCS1_OAEP.MGF1(x,y,SHA256))
    aes_key  = oaep.decrypt(wrapped)

    # 3) AES-GCM decrypt+verify
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    return aes.decrypt_and_verify(ct, tag)
