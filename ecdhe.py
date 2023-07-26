import collections
import random
from egcd import egcd

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

DEFAULT_ELLIPTIC_CURVE = EllipticCurve(
    'secp256k1',
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    a=0,
    b=7,
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    h=1,
)

ELLIPTIC_CURVE_160k1 = EllipticCurve(
    'secp160k1',
    p=0xfffffffffffffffffffffffffffffffeffffac73,
    a=0,
    b=7,
    g=(0x3b4c382ce37aa192a4019e763036f4f5dd4d7ebb,
       0x938cf935318fdced6bc28286531733c3f03c4fee),
    n=0x100000000000000000001b8fa16dfab9aca16b6b3,
    h=1,
)


ELLIPTIC_CURVE_192k1 = EllipticCurve(
    'secp192k1',
    p=0xfffffffffffffffffffffffffffffffffffffffeffffee37,
    a=0,
    b=3,
    g=(0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d,
       0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d),
    n=0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d,
    h=1,
)


ELLIPTIC_CURVE_224k1 = EllipticCurve(
    'secp224k1',
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffeffffe56d,
    a=0,
    b=5,
    g=(0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c,
       0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5),
    n=0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7,
    h=1,
)

curves = {"secp256k1": DEFAULT_ELLIPTIC_CURVE, "secp160k1":ELLIPTIC_CURVE_160k1, 'secp192k1':ELLIPTIC_CURVE_192k1,  'secp224k1':ELLIPTIC_CURVE_224k1}

class ECCKeyGenerator:
    def __init__(self, private_key=None, curve: EllipticCurve = DEFAULT_ELLIPTIC_CURVE) -> None:
        if private_key is None:
            private_key = random.randrange(1, curve.n)
        self.private_key = private_key
        self.curve = curve

    def gen_keypair(self):
        return self.private_key, self.scalar_mult(self.private_key, self.curve.g)

    @staticmethod
    def extended_gcd(k, p):
        if k == 0:
            raise ZeroDivisionError('division by zero')
        if k < 0:
            return p - ECCKeyGenerator.extended_gcd(-k, p)
        gcd, x, _ = egcd(k, p)
        assert gcd == 1
        assert (k * x) % p == 1
        return x % p


    def is_on_curve(self, point):
        if point is None:
            return True
        x, y = point
        return (y * y - x * x * x - self.curve.a * x - self.curve.b) % self.curve.p == 0


    def point_neg(self, point):
        assert self.is_on_curve(point)
        if point is None:
            return None
        x, y = point
        result = (x, -y % self.curve.p)
        assert self.is_on_curve(result)
        return result


    def add_point(self, point1, point2):
        assert self.is_on_curve(point1)
        assert self.is_on_curve(point2)

        if point1 is None:
            return point2
        if point2 is None:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2 and y1 != y2:
            return None
        if x1 != x2:
            lmd = (y1 - y2) * ECCKeyGenerator.extended_gcd(x1 - x2, self.curve.p)
        else:
            lmd = (3 * x1**2 + self.curve.a) * ECCKeyGenerator.extended_gcd(2 * y1, self.curve.p)

        x3 = lmd * lmd - x1 - x2
        y3 = y1 + lmd * (x3 - x1)
        result = (x3 % self.curve.p, -y3 % self.curve.p)
        assert self.is_on_curve(result)
        return result


    def scalar_mult(self, k, point):
        assert self.is_on_curve(point)
        if k % self.curve.n == 0 or point is None:
            return None
        if k < 0:
            return self.scalar_mult(-k, self.point_neg(point))

        result = None
        addend = point
        while k:
            if k & 1:
                result = self.add_point(result, addend)
            addend = self.add_point(addend, addend)
            k >>= 1
        assert self.is_on_curve(result)
        return result



if __name__ == "__main__":
    ecc = ECCKeyGenerator(curve=DEFAULT_ELLIPTIC_CURVE)
    print('Curve:', ecc.curve.name)
    private_key, public_key = ecc.gen_keypair()
    print(hex(private_key))
    print(hex(public_key[0]))
    print(hex(public_key[1]))



