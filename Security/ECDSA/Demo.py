from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def generate_keys():
    """產生 ECDSA P-384 金鑰對"""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    """使用私鑰對訊息進行簽章 (SHA-384)"""
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA384())
    )
    return signature

def verify_signature(public_key, message, signature):
    """使用公鑰驗證簽章"""
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA384())
        )
        return True
    except InvalidSignature:
        return False

# --- 範例使用 ---

# 1. 產生金鑰對
private_key, public_key = generate_keys()
print("金鑰產生完成。")

# 2. 準備要簽章的訊息 (必須是 bytes)
message_to_sign = b"This is a very important message to be signed with ECDSA P-384 and SHA-384."
print(f"原始訊息: {message_to_sign.decode()}")

# 3. 使用私鑰簽章訊息
signature = sign_message(private_key, message_to_sign)
print(f"數位簽章 (十六進位): {signature.hex()}")

# 4. 使用公鑰驗證簽章
is_valid = verify_signature(public_key, message_to_sign, signature)

if is_valid:
    print("簽章驗證成功！訊息未被竄改。👍")
else:
    print("簽章驗證失敗！訊息可能已被竄改或金鑰不符。❌")

# --- 嘗試驗證一個錯誤的訊息 ---
print("\n--- 嘗試驗證一個被竄改的訊息 ---")
tampered_message = b"This is a tampered message."
is_valid_tampered = verify_signature(public_key, tampered_message, signature)

if is_valid_tampered:
    print("對竄改訊息的簽章驗證成功 (這不應該發生！)。")
else:
    print("對竄改訊息的簽章驗證失敗。✅")

# --- 嘗試使用不同的金鑰驗證 ---
print("\n--- 嘗試使用不同的公鑰驗證 ---")
_, another_public_key = generate_keys() # 產生另一對金鑰
is_valid_wrong_key = verify_signature(another_public_key, message_to_sign, signature)

if is_valid_wrong_key:
    print("使用錯誤公鑰的簽章驗證成功 (這不應該發生！)。")
else:
    print("使用錯誤公鑰的簽章驗證失敗。✅")