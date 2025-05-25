from Sign import sign_message_from_file
from verify import verify_signature_from_file

if __name__ == '__main__':
    print('--- 執行簽章 ---')
    sign_message_from_file('Security/ECDSA/Sign_input.txt')
    print('\n--- 執行驗證 ---')
    result, qx, qy, pem = verify_signature_from_file('Security/ECDSA/Sign_output.txt')
    print(f'驗證結果: {"成功" if result else "失敗"}') 