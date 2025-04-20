# -*- coding: utf-8 -*-
import random
import base64

# --- RSA 代码 ---

def check_prime(num, K=5):
    if num < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if num == p: return True
        if num % p == 0: return False
    if num % 2 == 0: return num == 2
    
    s = 0
    d = num - 1
    while d % 2 == 0:
        d //= 2
        s += 1
        
    for _ in range(K):
        a = random.randrange(2, num - 1)
        x = pow(a, d, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True

def get_prime(key_len):
    while True:
        n = random.randrange(1 << (key_len-1), 1 << key_len) | 1
        if check_prime(n):
            return n

def make_keys(key_len=512):
    print(f"正在生成 {key_len} 位密钥...")
    while True:
        p = get_prime(key_len // 2)
        q = get_prime(key_len // 2)
        if p == q:
            continue
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 65537
        if phi_n % e == 0:
             continue
        try:
            d = pow(e, -1, phi_n)
            pub_key = f"{e},{n}"
            priv_key = f"{d},{n}"
            print("密钥生成完毕。")
            return priv_key, pub_key
        except ValueError:
            print("计算出错，重试...")
            continue

def rsa_enc(msg, pub_key):
    try:
        e_str, n_str = pub_key.split(',')
        e = int(e_str)
        n = int(n_str)
        
        b_msg = msg.encode('utf-8')
        
        # 简单的长度检查
        max_len = (n.bit_length() - 1) // 8
        if len(b_msg) > max_len:
             raise ValueError(f"消息太长了，最多 {max_len} 字节")
             
        m_int = int.from_bytes(b_msg, 'big')
        if m_int >= n:
            raise ValueError("消息转成数字后不能大于 n")
            
        c_int = pow(m_int, e, n)
        b_enc = c_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        
        return base64.b64encode(b_enc).decode('ascii')
        
    except ValueError as err:
        print(f"加密出错: {err}")
        raise err
    except Exception as err:
        print(f"加密时发生未知错误: {err}")
        raise err

def rsa_dec(enc_msg, priv_key):
    try:
        d_str, n_str = priv_key.split(',')
        d = int(d_str)
        n = int(n_str)
        
        b_enc = base64.b64decode(enc_msg)
        c_int = int.from_bytes(b_enc, 'big')
        
        if c_int >= n:
             raise ValueError("密文数值错误")
             
        m_int = pow(c_int, d, n)
        num_bytes = (m_int.bit_length() + 7) // 8
        b_dec = m_int.to_bytes(num_bytes, 'big')
        
        return b_dec.decode('utf-8').lstrip('\x00')
        
    except (ValueError, base64.binascii.Error) as err:
        print(f"解密出错: 输入或密钥格式可能有问题 - {err}")
        raise err
    except UnicodeDecodeError:
         print("解密失败: 结果不是合法的 UTF-8 编码，可能是密钥错误或数据损坏。")
         raise ValueError("解码失败")
    except Exception as err:
        print(f"解密时发生未知错误: {err}")
        raise err

# --- 测试程序 ---
if __name__ == "__main__":
    print("--- RSA 测试 ---")

    # 1. 生成密钥
    k_len = 512 
    priv_key = None
    pub_key = None
    try:
        priv_key, pub_key = make_keys(k_len)
        print(f"\n公钥: {pub_key}")
        if priv_key:
             print(f"私钥: {priv_key[:15]}...{priv_key[-15:]}") # 显示部分私钥
    except Exception as e:
        print(f"\n生成密钥时出错: {e}")
        exit(1) 

    # 2. 定义明文
    p_text = "你好，世界！这是一个 RSA 测试。Hello World 123."
    print(f"\n原始明文: '{p_text}'")

    enc_b64 = None
    dec_text = None

    # 3. 加密
    if pub_key:
        try:
            print("\n正在加密...")
            enc_b64 = rsa_enc(p_text, pub_key)
            print(f"加密结果 (Base64): {enc_b64}")
        except Exception as e:
            print(f"加密失败") 

    # 4. 解密
    if enc_b64 and priv_key:
        try:
            print("\n正在解密...")
            dec_text = rsa_dec(enc_b64, priv_key)
            print(f"解密结果: '{dec_text}'")
        except Exception as e:
            print(f"解密失败") 

    # 5. 验证
    print("\n--- 验证 ---")
    if enc_b64 and dec_text:
        if p_text == dec_text:
            print("成功: 解密文本和原始明文一致。")
        else:
            print("失败: 解密文本和原始明文不一致。")
            print(f"  原始: '{p_text}'")
            print(f"  解密: '{dec_text}'")
    elif enc_b64 is None:
        print("加密未成功，跳过验证。")
    else:
         print("解密未成功，跳过验证。")

    # --- 测试长文本 ---
    print("\n--- 测试长文本 ---")
    long_text = "测测你的" * 80 
    if pub_key:
        try:
            print(f"尝试加密长文本 ({len(long_text.encode('utf-8'))} 字节)...")
            rsa_enc(long_text, pub_key)
            print("长文本加密居然成功了？")
        except ValueError as e:
            print(f"长文本加密失败 (符合预期): {e}")
        except Exception as e:
            print(f"长文本测试出错: {e}")

    print("\n--- 测试结束 ---")