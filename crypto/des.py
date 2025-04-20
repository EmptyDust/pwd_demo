from Crypto.Cipher import DES
import base64

def des_encrypt(text: str, key: str) -> str:
    try:
        # 确保密钥是 8 字节
        key = key.encode()[:8].ljust(8, b'\0')
        # 初始化 DES 加密
        cipher = DES.new(key, DES.MODE_ECB)
        # 填充文本到 8 字节的倍数
        padded_text = text.encode() + b'\0' * (8 - len(text.encode()) % 8)
        encrypted = cipher.encrypt(padded_text)
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        raise Exception(f"DES 加密错误: {str(e)}")

def des_decrypt(encrypted_text: str, key: str) -> str:
    try:
        # 确保密钥是 8 字节
        key = key.encode()[:8].ljust(8, b'\0')
        # 初始化 DES 解密
        cipher = DES.new(key, DES.MODE_ECB)
        # 解码并解密
        encrypted = base64.b64decode(encrypted_text)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.rstrip(b'\0').decode()
    except Exception as e:
        raise Exception(f"DES 解密错误: {str(e)}")