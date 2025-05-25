from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

d_hex = 'B7F23D407EB528266C1550131E77D205F435F395BEB4A2C96760AA3EAE1785E70A2891D510D71A5F1A5B2295D953895E'
d_int = int(d_hex, 16)
curve = ec.SECP384R1()
private_key = ec.derive_private_key(d_int, curve, default_backend())
public_numbers = private_key.public_key().public_numbers()
qx = public_numbers.x
qy = public_numbers.y

print(f'Qx: {hex(qx)}')
print(f'Qy: {hex(qy)}')

def sec_reverse_copy(dst: bytearray, src: bytes, num: int):
    """
    將 src 的前 num 個 bytes 反向複製到 dst。
    dst 必須是 bytearray，src 可以是 bytes 或 bytearray。
    """
    for offset in range(num):
        dst[offset] = src[num - 1 - offset]
    return dst

# 測試範例
if __name__ == '__main__':
    # 從 Sign_input.txt 讀取 d 欄位
    d_hex = None
    with open('Security/ECDSA/Sign_input.txt', 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip().startswith('d='):
                d_raw = line.strip().split('=', 1)[1]
                import re
                d_hex = re.sub(r'0x', '', d_raw, flags=re.IGNORECASE).replace(' ', '')
                break
    if d_hex is None:
        raise ValueError('Sign_input.txt 沒有 d 欄位')
    src = bytes.fromhex(d_hex)
    dst = bytearray(len(src))
    sec_reverse_copy(dst, src, len(src))
    print('src:', src.hex())
    print('dst:', dst.hex())  # 反向複製結果