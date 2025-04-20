# -*- coding: utf-8 -*-
import base64

# --- DES 常量 (0 索引) ---

IP = [57, 49, 41, 33, 25, 17, 9,  1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7,
      56, 48, 40, 32, 24, 16, 8,  0,
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6] # 初始置换

FP = [39,  7, 47, 15, 55, 23, 63, 31,
      38,  6, 46, 14, 54, 22, 62, 30,
      37,  5, 45, 13, 53, 21, 61, 29,
      36,  4, 44, 12, 52, 20, 60, 28,
      35,  3, 43, 11, 51, 19, 59, 27,
      34,  2, 42, 10, 50, 18, 58, 26,
      33,  1, 41,  9, 49, 17, 57, 25,
      32,  0, 40,  8, 48, 16, 56, 24] # 末尾置换 (IP 的逆)

E = [31,  0,  1,  2,  3,  4,
      3,  4,  5,  6,  7,  8,
      7,  8,  9, 10, 11, 12,
     11, 12, 13, 14, 15, 16,
     15, 16, 17, 18, 19, 20,
     19, 20, 21, 22, 23, 24,
     23, 24, 25, 26, 27, 28,
     27, 28, 29, 30, 31,  0] # 扩展置换

P = [15,  6, 19, 20, 28, 11, 27, 16,
      0, 14, 22, 25,  4, 17, 30,  9,
      1,  7, 23, 13, 31, 26,  2,  8,
     18, 12, 29,  5, 21, 10,  3, 24] # P 盒置换

S_BOX = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]], # S1
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]], # S2
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]], # S3
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]], # S4
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]], # S5
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]], # S6
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]], # S7
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]] # S8
]

PC1 = [56, 48, 40, 32, 24, 16, 8,
        0, 57, 49, 41, 33, 25, 17,
        9,  1, 58, 50, 42, 34, 26,
       18, 10,  2, 59, 51, 43, 35,
       62, 54, 46, 38, 30, 22, 14,
        6, 61, 53, 45, 37, 29, 21,
       13,  5, 60, 52, 44, 36, 28,
       20, 12,  4, 27, 19, 11,  3] # 置换选择 1 (密钥生成)

PC2 = [13, 16, 10, 23,  0,  4,
        2, 27, 14,  5, 20,  9,
       22, 18, 11,  3, 25,  7,
       15,  6, 26, 19, 12,  1,
       40, 51, 30, 36, 46, 54,
       29, 39, 50, 44, 32, 47,
       43, 48, 38, 55, 33, 52,
       45, 41, 49, 35, 28, 31] # 置换选择 2 (密钥生成)

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1] # 循环左移位数表

# --- 工具函数 ---

def permute(block, table):
    # 根据表置换块中的位
    return [block[x] for x in table]

def xor(bits1, bits2):
    # 两个位列表的异或操作
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def bits_to_bytes(bits):
    # 将位列表转换为字节串
    byte_chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]
    byte_list = []
    for chunk in byte_chunks:
        byte_val = 0
        for bit in chunk:
            byte_val = (byte_val << 1) | bit
        byte_list.append(byte_val)
    return bytes(byte_list)

def bytes_to_bits(byte_data):
    # 将字节串转换为位列表
    bits = []
    for byte in byte_data:
        byte_bits = bin(byte)[2:].zfill(8) # 转换为 8 位二进制字符串
        bits.extend([int(b) for b in byte_bits]) # 添加到列表
    return bits

def left_circular_shift(bits, n):
    # 列表循环左移 n 位
    return bits[n:] + bits[:n]

def split_block(block, size):
    # 将列表按指定大小分块
    return [block[i:i+size] for i in range(0, len(block), size)]

# --- 填充函数 (PKCS#7) ---

def pad(data: bytes, block_size: int) -> bytes:
    # 对数据进行 PKCS#7 填充
    padding_len = block_size - (len(data) % block_size) # 计算需要填充的长度
    padding = bytes([padding_len] * padding_len) # 创建填充字节串
    return data + padding

def unpad(padded_data: bytes, block_size: int) -> bytes:
    # 去除 PKCS#7 填充
    if not padded_data:
        raise ValueError("无法对空数据进行去填充")
    padding_len = padded_data[-1] # 获取最后一个字节，即填充长度
    if padding_len > block_size or padding_len == 0:
        raise ValueError("无效的填充长度")
    # 检查填充字节是否正确 (可选但推荐)
    if padded_data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("无效的填充字节")
    return padded_data[:-padding_len] # 返回去除填充的数据

# --- DES 核心函数 ---

def generate_keys(key_bits):
    # 从 64 位主密钥生成 16 轮的 48 位子密钥
    if len(key_bits) != 64:
        raise ValueError("密钥必须是 64 位长")

    key_56 = permute(key_bits, PC1) # PC-1 置换得到 56 位
    c_half = key_56[:28] # 分为左右两半 C0, D0
    d_half = key_56[28:]

    subkeys = [] # 存储生成的子密钥
    for i in range(16): # 迭代 16 轮
        shift_amount = SHIFT_SCHEDULE[i] # 获取当前轮的移位数
        c_half = left_circular_shift(c_half, shift_amount) # 左半部分循环左移
        d_half = left_circular_shift(d_half, shift_amount) # 右半部分循环左移
        combined_cd = c_half + d_half # 合并移位后的两部分
        subkey_48 = permute(combined_cd, PC2) # PC-2 置换得到 48 位子密钥
        subkeys.append(subkey_48)

    return subkeys

def feistel_f(r_half, subkey):
    # DES 的 Feistel 轮函数 f(R, K)
    expanded_r = permute(r_half, E) # 1. 扩展置换 E (32 位 -> 48 位)
    xored = xor(expanded_r, subkey) # 2. 与子密钥异或

    sbox_output = [] # 存储 S 盒的输出
    chunks_6bit = split_block(xored, 6) # 3. 分成 8 个 6 位块

    for i, chunk in enumerate(chunks_6bit): # 对每个块进行 S 盒代换
        # 第 1 位和第 6 位组成行号 (0-3)
        row = (chunk[0] << 1) + chunk[5]
        # 中间 4 位组成列号 (0-15)
        col = (chunk[1] << 3) + (chunk[2] << 2) + (chunk[3] << 1) + chunk[4]
        s_val = S_BOX[i][row][col] # 查找 S 盒
        s_bits = [int(b) for b in bin(s_val)[2:].zfill(4)] # 将 S 盒输出转为 4 位
        sbox_output.extend(s_bits)

    p_output = permute(sbox_output, P) # 4. P 盒置换
    return p_output

def des_process_block(block_bits, subkeys):
    # 处理单个 64 位数据块的 DES 加密/解密
    if len(block_bits) != 64:
        raise ValueError("数据块必须是 64 位长")

    permuted_block = permute(block_bits, IP) # 1. 初始置换 IP
    l_half = permuted_block[:32] # 分为左右两半 L0, R0
    r_half = permuted_block[32:]

    # 3. 16 轮 Feistel 迭代
    for i in range(16):
        l_prev = l_half
        r_prev = r_half
        current_subkey = subkeys[i] # 获取当前轮子密钥
        f_result = feistel_f(r_prev, current_subkey) # 计算 f(R_{i-1}, K_i)
        l_half = r_prev # L_i = R_{i-1}
        r_half = xor(l_prev, f_result) # R_i = L_{i-1} XOR f(R_{i-1}, K_i)

    # 4. 最终合并 R16 和 L16 (注意：Feistel 结构最后没有交换)
    final_lr = r_half + l_half

    # 5. 末尾置换 FP (IP 的逆)
    processed_bits = permute(final_lr, FP)
    return processed_bits

# --- 主加密/解密函数 (ECB 模式) ---

def des_encrypt(text: str, key: str) -> str:
    """使用 DES ECB 模式加密文本"""
    # 准备密钥
    if len(key) < 8: # 密钥不足 8 字节用 null 补齐 (不推荐)
        key = key + '\0' * (8 - len(key))
    key_bytes = key[:8].encode('utf-8') # 取前 8 字节并编码
    key_bits = bytes_to_bits(key_bytes) # 转为位列表
    subkeys = generate_keys(key_bits) # 生成加密子密钥

    # 准备数据
    text_bytes = text.encode('utf-8') # 文本编码为字节
    padded_bytes = pad(text_bytes, 8) # PKCS#7 填充到 8 字节的倍数
    padded_bits = bytes_to_bits(padded_bytes) # 转为位列表

    # 按块加密 (ECB 模式)
    encrypted_bits = []
    for i in range(0, len(padded_bits), 64): # 按 64 位分块
        block = padded_bits[i:i+64]
        if len(block) != 64:
             # 正常填充后不应发生这种情况
             raise ValueError("填充错误")
        encrypted_block = des_process_block(block, subkeys) # 加密块
        encrypted_bits.extend(encrypted_block)

    # 结果处理
    encrypted_bytes = bits_to_bytes(encrypted_bits) # 将结果位列表转为字节
    return base64.b64encode(encrypted_bytes).decode('utf-8') # Base64 编码

def des_decrypt(encrypted_text: str, key: str) -> str:
    """解密 DES ECB 模式加密的文本 (Base64 编码)"""
    try:
        # 准备密钥
        if len(key) < 8:
            key = key + '\0' * (8 - len(key))
        key_bytes = key[:8].encode('utf-8')
        key_bits = bytes_to_bits(key_bytes)

        # 生成解密子密钥 (加密子密钥的逆序)
        encryption_subkeys = generate_keys(key_bits)
        decryption_subkeys = encryption_subkeys[::-1] # K16, K15, ..., K1

        # 准备数据
        encrypted_bytes = base64.b64decode(encrypted_text) # Base64 解码
        if len(encrypted_bytes) % 8 != 0: # 密文长度应为 8 的倍数
            raise ValueError("无效的密文长度")
        encrypted_bits = bytes_to_bits(encrypted_bytes) # 转为位列表

        # 按块解密 (ECB 模式)
        decrypted_bits = []
        for i in range(0, len(encrypted_bits), 64): # 按 64 位分块
            block = encrypted_bits[i:i+64]
            if len(block) != 64:
                 raise ValueError("密文处理错误")
            decrypted_block = des_process_block(block, decryption_subkeys) # 解密块
            decrypted_bits.extend(decrypted_block)

        # 结果处理
        decrypted_padded_bytes = bits_to_bytes(decrypted_bits) # 将结果位转为字节
        decrypted_bytes = unpad(decrypted_padded_bytes, 8) # 去除 PKCS#7 填充
        return decrypted_bytes.decode('utf-8') # 将字节解码为 UTF-8 字符串

    except (ValueError, base64.binascii.Error) as e:
        # 捕获预期的错误，如填充错误、Base64 错误、长度错误等
        raise ValueError(f"解密失败: {str(e)}")
    except Exception as e:
        # 捕获其他意外错误
        raise ValueError(f"解密过程中发生意外错误: {str(e)}")


# --- 主程序执行 / 示例 ---
if __name__ == "__main__":
    plaintext = "这是一条用于 DES 测试的消息。" # 中文测试明文
    secret_key = "mima1234" # 使用 8 字节密钥

    print(f"原始明文: {plaintext}")
    print(f"密钥: {secret_key}")

    try:
        # 加密
        encrypted_b64 = des_encrypt(plaintext, secret_key)
        print(f"加密结果 (Base64): {encrypted_b64}")

        # 解密
        decrypted_text = des_decrypt(encrypted_b64, secret_key)
        print(f"解密结果: {decrypted_text}")

        # 验证
        if plaintext == decrypted_text:
            print("\n成功: 解密文本与原始明文一致。")
        else:
            print("\n错误: 解密文本与原始明文不一致。")

        # 测试使用错误密钥解密
        try:
            print("\n尝试使用错误密钥进行解密...")
            wrong_key = "cuowumima"
            decrypted_wrong = des_decrypt(encrypted_b64, wrong_key)
            # 解密可能成功但得到乱码，或在去填充时失败
            print(f"错误密钥解密结果 (很可能是乱码): {decrypted_wrong}")
        except ValueError as e:
            # 预期会失败
            print(f"解密失败 (符合预期): {e}")

    except ValueError as e:
        print(f"\n处理过程中发生错误: {e}")
    except Exception as e:
        print(f"\n发生意外的关键错误: {e}")