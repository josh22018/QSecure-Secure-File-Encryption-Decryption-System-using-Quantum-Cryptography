# pq_kyber.py

import numpy as np
from hashlib import shake_256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def centered_binomial(n, k=3):
    a = np.random.randint(0, 2, size=(n, k))
    b = np.random.randint(0, 2, size=(n, k))
    return (a.sum(axis=1) - b.sum(axis=1)).tolist()

def generate_keypair_kyber(n=256, q=3329):
    """
    Simplified Kyber-KEM keygen:
      A ← seed-derived pseudorandom matrix
      s,e ← small noise vectors
      b = A⋅s + e  mod q
    Returns (public=(A_seed,b), secret_s=s).
    """
    seed = get_random_bytes(32)
    # derive A deterministically from seed via SHAKE
    shake = shake_256(seed)
    A = np.frombuffer(shake.digest(2*n*n), dtype=np.uint16) % q
    A = A.reshape((n, n)).tolist()
    s = centered_binomial(n)
    e = centered_binomial(n)
    b = (np.dot(A, s) + e) % q
    return (seed, b.tolist()), s

def encrypt_kyber(msg: bytes, public_key, q=3329) -> dict:
    """
    KEM + DEM:
      1) Derive A from seed
      2) r,e1,e2 ← small noise
      3) u = Aᵀ⋅r + e1  mod q
         v = b⋅r + e2   mod q
      4) shared = SHAKE-256(u||v) → 32-byte session key
      5) AES-GCM encrypt(msg) under session key
    """
    seed, b_list = public_key
    shake = shake_256(seed)
    A = np.frombuffer(shake.digest(2*len(b_list)*len(b_list)), dtype=np.uint16) % q
    A = A.reshape((len(b_list), len(b_list)))
    b = np.array(b_list)

    # noise
    r  = np.array(centered_binomial(len(b_list)))
    e1 = np.array(centered_binomial(len(b_list)))
    u  = (A.T.dot(r) + e1) % q
    e2 = int(centered_binomial(1)[0])
    v  = int((b.dot(r) + e2) % q)

    # KDF for session key
    u_bytes = b''.join(int.to_bytes(x, 2, 'big') for x in u)
    v_bytes = int.to_bytes(v, 2, 'big')
    session_key = shake_256(u_bytes + v_bytes).digest(32)

    # DEM: AES-GCM
    nonce = get_random_bytes(12)
    aes   = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = aes.encrypt_and_digest(msg)

    return {
      'u':      u.tolist(),
      'v':      v,
      'nonce':  nonce,
      'ct':     ct,
      'tag':    tag
    }

def decrypt_kyber(cipher: dict, secret_s, q=3329) -> bytes:
    """
    Decapsulate + DEM decrypt:
      1) recompute session_key = SHAKE-256(u||v)
      2) AES-GCM decrypt+verify
    """
    u      = np.array(cipher['u'])
    v      = cipher['v']
    nonce  = cipher['nonce']
    ct     = cipher['ct']
    tag    = cipher['tag']

    u_bytes = b''.join(int.to_bytes(x, 2, 'big') for x in u)
    v_bytes = int.to_bytes(v, 2, 'big')
    session_key = shake_256(u_bytes + v_bytes).digest(32)

    aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    return aes.decrypt_and_verify(ct, tag)
