# -*- coding: utf-8 -*-
import base64

def left_rotate(n, b):
    # 把 n 向左循环移位 b 位 (32 位)
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1_hash(text: str) -> str:
    # 初始哈希值 H0-H4
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    # 预处理
    msg_bytes = text.encode('utf-8') # 文本转字节
    msg_len_bits = len(msg_bytes) * 8 # 计算原始消息的位数
    
    # 填充
    msg_bytes += b'\x80' # 先加一个 1 bit (即 0x80)
    # 再加 0 bit，直到长度满足 (L + 1 + K) mod 512 = 448
    while (len(msg_bytes) * 8) % 512 != 448:
        msg_bytes += b'\x00' 
    # 最后加上原始消息长度的 64 位表示
    msg_bytes += msg_len_bits.to_bytes(8, 'big')
    
    # 按 512 位 (64 字节) 分块处理
    for k in range(0, len(msg_bytes), 64):
        chunk = msg_bytes[k:k+64] # 当前块
        
        # 准备 80 个字 W[0]-W[79]
        w = [0] * 80
        # 前 16 个字直接从块中获取
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], 'big')
        # 后面的字通过前面的字计算得到
        for j in range(16, 80):
            val = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
            w[j] = left_rotate(val, 1)
            
        # 初始化内部状态变量 a, b, c, d, e
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        
        # 80 轮迭代
        for j in range(80):
            # 根据不同的轮数选择不同的逻辑函数 f 和常量 k
            if 0 <= j <= 19:
                f = (b & c) | (~b & d)
                k_const = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k_const = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k_const = 0x8F1BBCDC
            else: # 60 <= j <= 79
                f = b ^ c ^ d
                k_const = 0xCA62C1D6
                
            # 计算临时值 temp
            temp = (left_rotate(a, 5) + f + e + k_const + w[j]) & 0xffffffff
            # 更新状态变量
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp
            
        # 将这一块的结果加到总的哈希值上
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        
    # 把最终的 5 个哈希值拼接起来，格式化为 40 字符的十六进制字符串
    hash_result = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}"
    return hash_result

# --- 测试函数 ---
def test_sha1():
    print("--- SHA-1 测试 ---")
    
    # 测试用例 1: 空字符串
    test_str1 = ""
    hash1 = sha1_hash(test_str1)
    # 空字符串的标准 SHA-1 值
    expected1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709" 
    print(f"输入: '{test_str1}'")
    print(f"输出: {hash1}")
    if hash1 == expected1:
        print("结果: 正确")
    else:
        print(f"结果: 错误! 期望值: {expected1}")
    print("-" * 20)

    # 测试用例 2: 简单字符串
    test_str2 = "Hello World"
    hash2 = sha1_hash(test_str2)
    expected2 = "0a4d55a8d778e5022fab701977c5d840bbc486d0" # "Hello World" 标准值
    print(f"输入: '{test_str2}'")
    print(f"输出: {hash2}")
    if hash2 == expected2:
        print("结果: 正确")
    else:
        print(f"结果: 错误! 期望值: {expected2}")
    print("-" * 20)

    # 测试用例 3: 区分大小写
    test_str3 = "hello world"
    hash3 = sha1_hash(test_str3)
    expected3 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" # "hello world" 标准值
    print(f"输入: '{test_str3}'")
    print(f"输出: {hash3}")
    if hash3 == expected3:
        print("结果: 正确")
    else:
        print(f"结果: 错误! 期望值: {expected3}")
    print("-" * 20)
    
    # 测试用例 4: 包含中文
    test_str4 = "你好，世界"
    hash4 = sha1_hash(test_str4)
    expected4 = "3becb03b015ed48050611c8d7afe4b88f70d5a20" # "你好，世界" 标准值
    print(f"输入: '{test_str4}'")
    print(f"输出: {hash4}") 
    if hash4 == expected4:
        print("结果: 正确")
    else:
        print(f"结果: 错误! 期望值: {expected4}")
    print("-" * 20)
    
    print("--- 测试结束 ---")

if __name__ == "__main__":
    test_sha1()