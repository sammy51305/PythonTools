from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def derive_public_key_from_private_hex(d_hex: str):
    """
    根據私鑰 hex 字串（d_hex），回傳對應的公鑰 Qx, Qy（整數）。
    """
    d_int = int(d_hex, 16)
    curve = ec.SECP384R1()
    private_key = ec.derive_private_key(d_int, curve, default_backend())
    public_numbers = private_key.public_key().public_numbers()
    qx = public_numbers.x
    qy = public_numbers.y
    return qx, qy 