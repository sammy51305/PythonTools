from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend
import re

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
    msg_hex = input_dict['Msg']
    d_hex = input_dict['d']

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
    sign_message_from_file('c:/Workspace/PythonTools/Security/ECDSA/Sign_input_spdm.txt')