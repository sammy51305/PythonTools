import re
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

def verify_signature_from_file(input_file='Verify_input.txt'):
    """
    從 input_file 讀取 Msg, Qx, Qy, Signature，驗證簽章，印出 Qx, Qy, public key (PEM)，回傳驗證結果
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

    # 取得訊息、Qx、Qy、Signature
    msg_hex = input_dict['Msg']
    qx_hex = input_dict['Qx']
    qy_hex = input_dict['Qy']
    sig_hex = input_dict['Signature']

    message_bytes = bytes.fromhex(msg_hex)
    qx = int(qx_hex, 16)
    qy = int(qy_hex, 16)
    signature_bytes = bytes.fromhex(sig_hex)

    # 建立公鑰物件
    curve = ec.SECP384R1()
    public_numbers = ec.EllipticCurvePublicNumbers(qx, qy, curve)
    public_key = public_numbers.public_key(default_backend())

    # 印出 Qx, Qy
    print(f"Qx: {hex(qx)}")
    print(f"Qy: {hex(qy)}")

    # 印出公鑰 PEM
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Public Key (PEM):\n" + pem.decode())

    # 驗證簽章（由 Sign.py 產生的隨機簽章）
    try:
        public_key.verify(
            signature_bytes,
            message_bytes,
            ec.ECDSA(hashes.SHA384())
        )
        print("Signature verification: SUCCESS ✅")
        return True, qx, qy, pem.decode()
    except InvalidSignature:
        print("Signature verification: FAILED ❌")
        return False, qx, qy, pem.decode()
    except Exception as e:
        print(f"Unexpected error during verification: {e}")
        return False, qx, qy, pem.decode()

# 若直接執行本檔案，則自動執行一次
if __name__ == '__main__':
    verify_signature_from_file('c:/Workspace/PythonTools/Security/ECDSA/Sign_output.txt') 