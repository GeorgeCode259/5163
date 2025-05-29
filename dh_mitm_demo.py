from crypto_utils import (
    mod_exp, generate_prime, generate_private_key, generate_public_key,
    generate_rsa_keypair, rsa_sign, rsa_verify, compute_shared_secret
)

def dh_mitm_simulation():
    print("=== 模拟中间人攻击（MITM） ===")

    # 公共参数
    p = generate_prime(512)
    g = 2

    # Alice 和 Bob 各自生成 DH 私钥和公钥
    alice_priv = generate_private_key(p)
    alice_pub = generate_public_key(g, alice_priv, p)
    bob_priv = generate_private_key(p)
    bob_pub = generate_public_key(g, bob_priv, p)

    # Attacker（Eve）生成伪造的 DH 密钥对
    eve_priv = generate_private_key(p)
    fake_pub = generate_public_key(g, eve_priv, p)

    print("\n--- 场景 1：无签名验证，Eve 替换公钥 ---")
    print("🧅 Eve 替换了 Alice 发给 Bob 的公钥为自己的 fake_pub")
    # Bob 计算的共享密钥实际是与 Eve 的共享密钥
    bob_shared = compute_shared_secret(fake_pub, bob_priv, p)

    print("🧅 Eve 替换了 Bob 发给 Alice 的公钥为自己的 fake_pub")
    alice_shared = compute_shared_secret(fake_pub, alice_priv, p)

    print("🤯 Alice 以为这是和 Bob 的密钥:", alice_shared)
    print("🤯 Bob 以为这是和 Alice 的密钥:", bob_shared)
    print("💥 实际上都和 Eve 共享了密钥（MITM 成功）")
    print("✅ Eve 与双方各自有一个共享密钥，可以解密通信")

    print("\n--- 场景 2：有签名验证，Eve 替换后被识破 ---")

    # Bob 用 RSA 私钥签名自己的公钥
    bob_privkey, bob_pubkey = generate_rsa_keypair()
    bob_pub_bytes = str(bob_pub).encode()
    bob_signature = rsa_sign(bob_pub_bytes, bob_privkey)

    # Eve 替换 bob_pub 为 fake_pub，但不能伪造签名
    fake_pub_bytes = str(fake_pub).encode()

    print("🔐 Alice 收到 Bob 的公钥（被篡改）和原始签名，尝试验证：")
    verified = rsa_verify(fake_pub_bytes, bob_signature, bob_pubkey)

    if verified:
        print("❌ 签名验证通过，攻击未检测（不应该）")
    else:
        print("✅ 签名验证失败！检测到中间人攻击")

if __name__ == "__main__":
    dh_mitm_simulation()
