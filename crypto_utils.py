import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# 快速幂模运算
def mod_exp(base, exponent, modulus):
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent % 2:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus
    return result

# Miller-Rabin 素性测试
def is_probable_prime(n, k=40):
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# 随机生成素数
def generate_prime(bits=512):
    while True:
        candidate = secrets.randbits(bits) | 1
        if is_probable_prime(candidate):
            return candidate

# 生成私钥
def generate_private_key(p):
    return secrets.randbelow(p - 2) + 2

# 生成公钥
def generate_public_key(g, private_key, p):
    return mod_exp(g, private_key, p)

# 计算共享密钥
def compute_shared_secret(peer_public_key, private_key, p):
    return mod_exp(peer_public_key, private_key, p)

# HMAC-SHA256
def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

# 派生共享密钥
def derive_key(shared_secret: int, salt: bytes = b"PAKE") -> bytes:
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return hashlib.pbkdf2_hmac('sha256', secret_bytes, salt, iterations=100000)



# === ECC (ECDSA) 支持 ===

# 生成 ECDSA 椭圆曲线密钥对
def generate_ecdsa_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# 使用 ECDSA 签名消息
def ecdsa_sign(message: bytes, private_key) -> bytes:
    return private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

# 使用 ECDSA 验证签名
def ecdsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False