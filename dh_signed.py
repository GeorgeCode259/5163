from crypto_utils import (
    mod_exp, generate_prime, generate_private_key, generate_public_key, compute_shared_secret,
    generate_ecdsa_keypair, ecdsa_sign, ecdsa_verify
)

def signed_dh_demo():
    print("=== 带身份验证的 Diffie-Hellman（使用 ECC / ECDSA 签名） ===\n")

    # 公共参数
    p = generate_prime(512)
    g = 2
    print(f"[参数] p = {p}\n[参数] g = {g}\n")

    # 1. Alice 和 Bob 各自生成 ECDSA 密钥对
    alice_priv_key, alice_pub_key = generate_ecdsa_keypair()
    bob_priv_key, bob_pub_key = generate_ecdsa_keypair()

    print("🔐 Alice 生成了 ECDSA 密钥对")
    print("    公钥类型:", type(alice_pub_key))
    print("🔐 Bob 生成了 ECDSA 密钥对")
    print("    公钥类型:", type(bob_pub_key))
    print()

    # 2. Alice 生成 DH 公钥并签名
    a_priv = generate_private_key(p)
    a_pub = generate_public_key(g, a_priv, p)
    a_pub_bytes = str(a_pub).encode()
    a_signature = ecdsa_sign(a_pub_bytes, alice_priv_key)

    print("🔏 Alice 签名她的 DH 公钥:")
    print("    公钥值:", a_pub)
    print("    签名值:", a_signature.hex()[:64], "...(省略)")
    print()

    # 3. Bob 生成 DH 公钥并签名
    b_priv = generate_private_key(p)
    b_pub = generate_public_key(g, b_priv, p)
    b_pub_bytes = str(b_pub).encode()
    b_signature = ecdsa_sign(b_pub_bytes, bob_priv_key)

    print("🔏 Bob 签名他的 DH 公钥:")
    print("    公钥值:", b_pub)
    print("    签名值:", b_signature.hex()[:64], "...(省略)")
    print()

    # 4. Alice 验证 Bob 的签名
    print("🕵️ Alice 验证 Bob 的签名...")
    if ecdsa_verify(b_pub_bytes, b_signature, bob_pub_key):
        print("✅ Alice 验证 Bob 的签名成功\n")
    else:
        raise ValueError("❌ Alice 验证 Bob 签名失败")

    # 5. Bob 验证 Alice 的签名
    print("🕵️ Bob 验证 Alice 的签名...")
    if ecdsa_verify(a_pub_bytes, a_signature, alice_pub_key):
        print("✅ Bob 验证 Alice 的签名成功\n")
    else:
        raise ValueError("❌ Bob 验证 Alice 签名失败")

    # 6. 双方计算共享密钥
    a_secret = compute_shared_secret(b_pub, a_priv, p)
    b_secret = compute_shared_secret(a_pub, b_priv, p)

    print("🔑 Alice Shared Secret:", a_secret)
    print("🔑 Bob Shared Secret:  ", b_secret)

    assert a_secret == b_secret
    print("\n✅ 密钥一致，且 ECDSA 身份验证成功")

if __name__ == "__main__":
    signed_dh_demo()
