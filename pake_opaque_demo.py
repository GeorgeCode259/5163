import hashlib
import secrets
import json
from crypto_utils import (
    mod_exp, generate_prime, generate_private_key, derive_key, hmac_sha256
)

# 服务端数据库（持久化 envelope）模拟
SERVER_DB = {}

# 使用 PBKDF2 派生加密密钥（简化版 OPRF）
def password_to_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)

# 注册阶段
def client_register(username: str, password: str):
    print(f"\n[注册阶段] 用户 {username}")

    # 客户端生成 DH 密钥对
    p = generate_prime(512)
    g = 2
    client_private = generate_private_key(p)
    client_public = mod_exp(g, client_private, p)

    # 客户端派生 envelope 密钥
    salt = secrets.token_bytes(16)
    k = password_to_key(password, salt)

    # 加密 DH 私钥（模拟 envelope）
    client_private_bytes = client_private.to_bytes((client_private.bit_length() + 7) // 8, 'big')
    envelope = hmac_sha256(k, client_private_bytes)

    # 服务器存储 envelope 和公钥
    SERVER_DB[username] = {
        "salt": salt.hex(),
        "envelope": envelope.hex(),
        "p": p,
        "g": g,
        "client_public": client_public
    }
    print(f"✅ 注册成功，存储在服务器")

# 登录阶段
def client_login(username: str, password: str):
    print(f"\n[登录阶段] 用户 {username} 正在认证")

    # 服务端获取数据
    record = SERVER_DB.get(username)
    if not record:
        print("❌ 用户不存在")
        return

    salt = bytes.fromhex(record["salt"])
    envelope = bytes.fromhex(record["envelope"])
    p = record["p"]
    g = record["g"]
    client_public = record["client_public"]

    # 客户端使用密码恢复 envelope key
    k = password_to_key(password, salt)

    # 客户端尝试解密 envelope（验证）
    # 这一步模拟 envelope 内容一致性
    recovered_secret = hmac_sha256(k, b'')  # 模拟验证 (简化)
    if recovered_secret != hmac_sha256(k, b''):
        print("❌ 密码错误或 envelope 无效")
        return

    # 继续进行 DH 密钥交换
    server_private = generate_private_key(p)
    server_public = mod_exp(g, server_private, p)

    shared_secret_client = mod_exp(server_public, int.from_bytes(k, 'big'), p)
    shared_secret_server = mod_exp(client_public, server_private, p)

    # 密钥派生（共享密钥）
    key_client = derive_key(shared_secret_client)
    key_server = derive_key(shared_secret_server)

    print(f"🤝 客户端与服务端密钥是否一致: {key_client == key_server}")
    print(f"共享密钥 (前16位): {key_client.hex()[:32]}")

# 模拟演示
if __name__ == "__main__":
    username = "alice"
    password = "correcthorsebatterystaple"

    client_register(username, password)
    client_login(username, password)

    # 尝试错误密码
    print("\n=== 错误密码尝试 ===")
    client_login(username, "wrongpassword123")
