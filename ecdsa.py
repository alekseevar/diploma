import collections
import hashlib
import random
import ecdhe


def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, ecc.curve.n)
    public_key = ecc.scalar_mult(private_key, ecc.curve.g)
    return private_key, public_key


def hash_message(message, curve):
    message_hash = hashlib.sha512(message).digest()
    e = int.from_bytes(message_hash, 'big')
    hash = e >> (e.bit_length() - curve.n.bit_length())
    assert hash.bit_length() <= curve.n.bit_length()
    return hash


def sign_message(private_key, message, curve):
    ecc = ecdhe.ECCKeyGenerator()
    hash = hash_message(message, curve)
    r = 0
    s = 0
    while not r or not s:
        k = random.randrange(1, curve.n)
        x, y = ecc.scalar_mult(k, curve.g)
        r = x % curve.n
        s = ((hash + r * int(private_key)) * ecc.extended_gcd(k, curve.n)) % curve.n
    return r, s


def verify_signature(public_key, message, signature, curve):
    ecc = ecdhe.ECCKeyGenerator()
    hash = hash_message(message, curve)
    r, s = signature
    w = ecc.extended_gcd(s, curve.n)
    u1 = (hash * w) % curve.n
    u2 = (r * w) % curve.n
    x, y = ecc.add_point(ecc.scalar_mult(u1, curve.g),
                     ecc.scalar_mult(u2, public_key))
    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    return 'invalid signature'


if __name__ == '__main__':
    ecc = ecdhe.ECCKeyGenerator()
    print('Curve:', ecc.curve.name)

    private, public = make_keypair()
    print("Private key:", hex(private))
    print("Public key: (0x{:x}, 0x{:x})".format(*public))

    msg = b'Hello!'
    signature = sign_message(private, msg, ecc.curve)

    print()
    print('Message:', msg)
    print('Signature: (0x{:x}, 0x{:x})'.format(*signature))
    print('Verification:', verify_signature(public, msg, signature, ecc.curve))

    msg = b'Hi there!'
    print()
    print('Message:', msg)
    print('Verification:', verify_signature(public, msg, signature, ecc.curve))

    private, public = make_keypair()

    msg = b'Hello!'
    print()
    print('Message:', msg)
    print("Public key: (0x{:x}, 0x{:x})".format(*public))
    print('Verification:', verify_signature(public, msg, signature, ecc.curve))