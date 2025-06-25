# pq_ntru.py

import random

def _trim(poly):
    while len(poly)>1 and poly[-1]==0:
        poly.pop()
    return poly

def _add(a, b, mod):
    n = max(len(a), len(b))
    return _trim([((a[i] if i<len(a) else 0) + (b[i] if i<len(b) else 0)) % mod
                  for i in range(n)])

def _sub(a, b, mod):
    n = max(len(a), len(b))
    return _trim([((a[i] if i<len(a) else 0) - (b[i] if i<len(b) else 0)) % mod
                  for i in range(n)])

def _mul(a, b, mod, N):
    # Polynomial mult mod (X^N -1)
    c = [0]*N
    for i in range(len(a)):
        for j in range(len(b)):
            c[(i+j) % N] = (c[(i+j) % N] + a[i]*b[j]) % mod
    return _trim(c)

def _divmod(u, v, mod):
    # Polynomial long division u/v over GF(mod)
    u = u.copy()
    v = _trim(v.copy())
    if v == [0]:
        raise ZeroDivisionError()
    inv_lc = pow(v[-1], -1, mod)
    q = [0]*(max(len(u)-len(v)+1,0))
    while len(u) >= len(v):
        d = len(u)-len(v)
        coef = (u[-1] * inv_lc) % mod
        q[d] = coef
        for i in range(len(v)):
            u[d+i] = (u[d+i] - coef * v[i]) % mod
        _trim(u)
    return _trim(q), _trim(u)

def _ext_gcd(a, b, mod):
    # Extended Euclid for polynomials: returns (g, s, t) with s·a + t·b = g
    r0, r1 = _trim(a.copy()), _trim(b.copy())
    s0, s1 = [1], [0]
    t0, t1 = [0], [1]
    while r1 != [0]:
        q, r2 = _divmod(r0, r1, mod)
        s2 = _sub(s0, _mul(q, s1, mod, len(r0)), mod)
        t2 = _sub(t0, _mul(q, t1, mod, len(r0)), mod)
        r0, r1 = r1, r2
        s0, s1 = s1, s2
        t0, t1 = t1, t2
    return r0, s0, t0

def _inv_poly(f, mod, N):
    """
    Invert f mod (X^N -1, mod). Raises if not invertible.
    """
    # Build X^N -1 = [-1] + 0*(N-1) + [1]
    mod_poly = [-1] + [0]*(N-1) + [1]
    g, s, _ = _ext_gcd(f, mod_poly, mod)
    # g should be a constant ≡1; if not, divide s by g[0]
    if len(g)!=1 or g[0] % mod == 0:
        raise ValueError("f not invertible")
    inv_g0 = pow(g[0], -1, mod)
    inv = [(coef*inv_g0) % mod for coef in s]
    return inv[:N]

def generate_ntru_keys(N=11, p=3, q=2048, df=5, dg=5):
    """
    NTRU keygen:
       f, g ← small ternary polys of Hamming weight df/dg
       f_p_inv = f^{-1} mod (X^N−1, p)
       f_q_inv = f^{-1} mod (X^N−1, q)
       h = p·(f_q_inv ⋆ g) mod q
    Returns (h, private=(f, f_p_inv, f_q_inv)).
    """
    # small f, g
    def sample_poly(d): 
        poly = [1]*d + [-1]*d + [0]*(N-2*d)
        random.shuffle(poly)
        return poly

    f = sample_poly(df)
    g = sample_poly(dg)

    f_p_inv = _inv_poly(f, p, N)
    f_q_inv = _inv_poly(f, q, N)
    # public key h
    h = _mul([ (p * coeff) % q for coeff in f_q_inv ], g, q, N)
    return h, (f, f_p_inv, f_q_inv)

def encrypt_ntru(msg: str, h: list, p=3, q=2048) -> dict:
    """
    Encrypt a single character:
      r,e ← small noise
      c = r⋆h + m  (m = ord(msg) at coeff 0)
    """
    N = len(h)
    # small noise r
    r = [random.choice([-1,0,1]) for _ in range(N)]
    m_poly = [ord(msg)] + [0]*(N-1)
    c = _add(_mul(r, h, q, N), m_poly, q)
    return {'c': c}

def decrypt_ntru(cipher: dict, priv: tuple, p=3, q=2048) -> str:
    """
    Decrypt:
      a = f⋆c mod q
      m0 = center(a[0] mod q) mod p → character
    """
    f, f_p_inv, _ = priv
    N = len(f)
    c = cipher['c']
    a = _mul(f, c, q, N)
    # centered reduction mod q then mod p
    m0 = ((a[0] + q//2) % q) % p
    return chr(m0)
