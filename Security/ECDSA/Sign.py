from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend
import re

kat_p384_sha384 = {
    "Msg": "6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0c485dcca9f52d41b60161246039e42ec784d49400bffdb51459f5de654091301a09378f93464d52118b48d44b30d781eb1dbed09da11fb4c818dbd442d161aba4b9edc79f05e4b7e401651395b53bd8b5bd3f2aaa6a00877fa9b45cadb8e648550b4c6cbe",
    "d": "201b432d8df14324182d6261db3e4b3f46a8284482d52e370da41e6cbdf45ec2952f5db7ccbce3bc29449f4fb080ac97",
    "Qx": "c2b47944fb5de342d03285880177ca5f7d0f2fcad7678cce4229d6e1932fcac11bfc3c3e97d942a3c56bf34123013dbf",
    "Qy": "37257906a8223866eda0743c519616a76a758ae58aee81c5fd35fbf3a855b7754a36d4a0672df95d6c44a81cf7620c2d",
    "k": "dcedabf85978e090f733c6e16646fa34df9ded6e5ce28c6676a00f58a25283db8885e16ce5bf97f917c81e1f25c9c771", # k 僅供參考，驗證時不直接使用
    "R": "50835a9251bad008106177ef004b091a1e4235cd0da84fff54542b0ed755c1d6f251609d14ecf18f9e1ddfe69b946e32",
    "S": "0475f3d30c6463b646e8d3bf2455830314611cbde404be518b14464fdb195fdcc92eb222e61f426a4a592c00a6a89721"
}

def sign_message_from_file(input_file='Sign_input.txt'):
    """
    從 input_file 讀取 Msg, d，計算 Qx, Qy，簽章並回傳 Qx, Qy, R, S, signature_der(hex)
    """
    # 讀取 input.txt
    input_dict = {}
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            if '=' in line:
                k, v = line.strip().split('=', 1)
                # 將 0x 移除並去除空格
                v_clean = re.sub(r'0x', '', v, flags=re.IGNORECASE).replace(' ', '')
                input_dict[k.strip()] = v_clean

    # 取得訊息與私鑰
    msg_hex = kat_p384_sha384["Msg"]
    d_hex = kat_p384_sha384['d']
    # msg_hex = input_dict['Msg']
    # d_hex = input_dict['d']

    message_bytes = bytes.fromhex(msg_hex)
    d_int = int(d_hex, 16)

    # 建立私鑰物件
    curve = ec.SECP384R1()
    private_key = ec.derive_private_key(d_int, curve, default_backend())

    # 取得公鑰
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    qx = public_numbers.x
    qy = public_numbers.y

    # 簽章（自動產生隨機 k）
    signature_der = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA384())
    )

    # 解析 R, S
    r, s = decode_dss_signature(signature_der)

    # 印出結果
    print(f"Msg: {msg_hex}")
    print(f"d: {d_hex}")
    print(f"Qx: {hex(qx)}")
    print(f"Qy: {hex(qy)}")
    print(f"R: {hex(r)}")
    print(f"S: {hex(s)}")
    print(f"Signature (DER, hex): {signature_der.hex()}")

    # 輸出 Verify.py 需要的 input
    with open('Security/ECDSA/Sign_output.txt', 'w', encoding='utf-8') as fout:
        fout.write(f"Msg={msg_hex}\n")
        fout.write(f"Qx={qx:x}\n")
        fout.write(f"Qy={qy:x}\n")
        fout.write(f"Signature={signature_der.hex()}\n")

    return qx, qy, r, s, signature_der

# 若直接執行本檔案，則自動執行一次
if __name__ == '__main__':
    sign_message_from_file('./Security/ECDSA/Sign_input_spdm.txt')