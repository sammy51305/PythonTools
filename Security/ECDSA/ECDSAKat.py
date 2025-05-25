from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Golden Pattern Values from your input
# 來自你的輸入的黃金樣本值
kat_p384_sha384 = {
    "Msg": "6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0c485dcca9f52d41b60161246039e42ec784d49400bffdb51459f5de654091301a09378f93464d52118b48d44b30d781eb1dbed09da11fb4c818dbd442d161aba4b9edc79f05e4b7e401651395b53bd8b5bd3f2aaa6a00877fa9b45cadb8e648550b4c6cbe",
    "d": "201b432d8df14324182d6261db3e4b3f46a8284482d52e370da41e6cbdf45ec2952f5db7ccbce3bc29449f4fb080ac97",
    "Qx": "c2b47944fb5de342d03285880177ca5f7d0f2fcad7678cce4229d6e1932fcac11bfc3c3e97d942a3c56bf34123013dbf",
    "Qy": "37257906a8223866eda0743c519616a76a758ae58aee81c5fd35fbf3a855b7754a36d4a0672df95d6c44a81cf7620c2d",
    "k": "dcedabf85978e090f733c6e16646fa34df9ded6e5ce28c6676a00f58a25283db8885e16ce5bf97f917c81e1f25c9c771", # k 僅供參考，驗證時不直接使用
    "R": "50835a9251bad008106177ef004b091a1e4235cd0da84fff54542b0ed755c1d6f251609d14ecf18f9e1ddfe69b946e32",
    "S": "0475f3d30c6463b646e8d3bf2455830314611cbde404be518b14464fdb195fdcc92eb222e61f426a4a592c00a6a89721"
}

def verify_kat_pattern(kat):
    print("/***** ECDSA KAT ECCP384 SHA384 Pattern Verification *****/\n")

    # 1. Parse values
    # 1. 解析數值
    msg_hex = kat["Msg"]
    qx_hex = kat["Qx"]
    qy_hex = kat["Qy"]
    r_hex = kat["R"]
    s_hex = kat["S"]
    # d_hex = kat["d"] # Private key, for signing

    # 2. Convert Msg from hex to bytes
    # 2. 將 Msg 從十六進制轉為位元組
    message_bytes = bytes.fromhex(msg_hex)
    print(f"Msg (bytes): {message_bytes.hex()}")

    # 3. Convert Qx, Qy, R, S from hex to integers
    # 3. 將 Qx、Qy、R、S 從十六進制轉為整數
    qx_int = int(qx_hex, 16)
    qy_int = int(qy_hex, 16)
    r_int = int(r_hex, 16)
    s_int = int(s_hex, 16)

    print(f"Qx (int): {qx_int}")
    print(f"Qy (int): {qy_int}")
    print(f"R (int): {r_int}")
    print(f"S (int): {s_int}")

    # 4. Reconstruct the public key
    # 4. 重建公鑰
    curve = ec.SECP384R1()
    public_numbers = ec.EllipticCurvePublicNumbers(qx_int, qy_int, curve)
    public_key = public_numbers.public_key(default_backend())
    print("\nPublic key reconstructed successfully.")

    # 5. DER-encode the signature (R, S)
    # 5. 將簽章 (R, S) 進行 DER 編碼
    # The cryptography library's verify() method expects a DER-encoded signature.
    der_signature = encode_dss_signature(r_int, s_int)
    print(f"DER-encoded Signature (hex): {der_signature.hex()}")

    # 6. Verify the signature
    # 6. 驗證簽章
    try:
        public_key.verify(
            der_signature,
            message_bytes,
            ec.ECDSA(hashes.SHA384())
        )
        print("\nSUCCESS: Signature VERIFIED successfully against the KAT pattern. ✅")
        # 驗證成功，簽章與 KAT 樣本一致
        return True
    except InvalidSignature:
        print("\nERROR: Signature verification FAILED. ❌")
        # 驗證失敗
        return False
    except Exception as e:
        print(f"\nAn unexpected error occurred during verification: {e}")
        # 驗證過程發生未預期錯誤
        return False

# --- Run the verification ---
# --- 執行驗證 ---
verification_result = verify_kat_pattern(kat_p384_sha384)

# --- Optional: Demonstrate signing with the private key (will produce a different R,S) ---
# --- 選用：用私鑰簽章（會產生不同的 R, S）---
# Note: The 'k' from the KAT is specific to the R,S provided.
# 注意：KAT 中的 'k' 僅對應於給定的 R, S。
# Standard signing will generate its own secure random 'k'.
# 標準簽章會自動產生安全隨機的 'k'。
print("\n\n--- Optional: Signing with the private key from KAT (will yield new R,S) ---")
d_hex = kat_p384_sha384["d"]
d_int = int(d_hex, 16)
message_to_sign = bytes.fromhex(kat_p384_sha384["Msg"])

# Reconstruct private key
# 重建私鑰
private_numbers = ec.EllipticCurvePrivateNumbers(d_int, ec.EllipticCurvePublicNumbers(
    int(kat_p384_sha384["Qx"], 16),
    int(kat_p384_sha384["Qy"], 16),
    ec.SECP384R1()
))
private_key_from_kat = private_numbers.private_key(default_backend())
print("Private key reconstructed from 'd'.")
# 私鑰已由 'd' 重建

# Sign the message
# 對訊息進行簽章
new_signature_der = private_key_from_kat.sign(
    message_to_sign,
    ec.ECDSA(hashes.SHA384())
)
print(f"Newly generated DER signature (hex): {new_signature_der.hex()}")
# 新產生的 DER 簽章

# Decode the new R and S to display them
# 解碼新的 R 和 S 以顯示
new_r, new_s = decode_dss_signature(new_signature_der)
print(f"New R: {new_r}")
print(f"New S: {new_s}")

# Verify this new signature (self-check)
# 驗證新產生的簽章（自我檢查）
try:
    public_key_from_kat = private_key_from_kat.public_key()
    public_key_from_kat.verify(
        new_signature_der,
        message_to_sign,
        ec.ECDSA(hashes.SHA384())
    )
    print("Verification of newly generated signature: SUCCESSFUL. 👍")
    # 新簽章驗證成功
except InvalidSignature:
    print("Verification of newly generated signature: FAILED. (Should not happen)")
    # 新簽章驗證失敗（不應發生）