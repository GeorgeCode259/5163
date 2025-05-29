import secrets

# Fast modular exponentiation algorithm：base^exponent % modulus
def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus
    return result

# Miller-Rabin 
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

# generate bit
def generate_prime(bits=512):
    while True:
        p = secrets.randbits(bits) | 1 
        if is_probable_prime(p):
            return p

# generate pr_key
def generate_private_key(p):
    return secrets.randbelow(p - 2) + 2 

# generate pu_key g^a mod p
def generate_public_key(g, private_key, p):
    return mod_exp(g, private_key, p)

# compute shared key (B^a mod p)
def compute_shared_secret(peer_public_key, private_key, p):
    return mod_exp(peer_public_key, private_key, p)

# mian
def demo():

    p = generate_prime(bits=512)
    g = 2 

    print("=== public ===")
    print("p =", p)
    print("g =", g)

    # Alice
    a_private = generate_private_key(p)
    a_public = generate_public_key(g, a_private, p)

    # Bob
    b_private = generate_private_key(p)
    b_public = generate_public_key(g, b_private, p)

    # shared key
    a_secret = compute_shared_secret(b_public, a_private, p)
    b_secret = compute_shared_secret(a_public, b_private, p)

    print("\n=== public key exchange ===")
    print("Alice Public:", a_public)
    print("Bob Public:  ", b_public)

    print("\n=== shared key ===")
    print("Alice Shared Secret:", a_secret)
    print("Bob Shared Secret:  ", b_secret)

    assert a_secret == b_secret, "shared key is not valid"
    print("\n✅ successful")

if __name__ == "__main__":
    demo()
