from fastapi import APIRouter, HTTPException
from models.crypto import CryptoRequest
from crypto.des import des_encrypt, des_decrypt
from crypto.rsa import generate_rsa_keys, rsa_encrypt, rsa_decrypt
from crypto.sha1 import sha1_hash
from crypto.custom_des import des_encrypt as custom_des_encrypt, des_decrypt as custom_des_decrypt
from crypto.custom_rsa import make_keys as custom_generate_rsa_keys, rsa_enc as custom_rsa_encrypt, rsa_dec as custom_rsa_decrypt
from crypto.custom_sha1 import sha1_hash as custom_sha1_hash

router = APIRouter()

# 原有端点（保持不变）
@router.post("/des/encrypt")
async def des_encrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供密钥")
    try:
        return {"result": des_encrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/des/decrypt")
async def des_decrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供密钥")
    try:
        return {"result": des_decrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/rsa/generate-keys")
async def rsa_generate_keys():
    private_key, public_key = generate_rsa_keys()
    return {"private_key": private_key, "public_key": public_key}

@router.post("/rsa/encrypt")
async def rsa_encrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供公钥")
    try:
        return {"result": rsa_encrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/rsa/decrypt")
async def rsa_decrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供私钥")
    try:
        return {"result": rsa_decrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/sha1/hash")
async def sha1_hash_endpoint(request: CryptoRequest):
    return {"result": sha1_hash(request.text)}

# 自定义端点
@router.post("/custom/des/encrypt")
async def custom_des_encrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供密钥")
    try:
        return {"result": custom_des_encrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"自定义 DES 加密错误: {str(e)}")

@router.post("/custom/des/decrypt")
async def custom_des_decrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供密钥")
    try:
        return {"result": custom_des_decrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"自定义 DES 解密错误: {str(e)}")

@router.get("/custom/rsa/generate-keys")
async def custom_rsa_generate_keys():
    try:
        private_key, public_key = custom_generate_rsa_keys()
        return {"private_key": private_key, "public_key": public_key}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"自定义 RSA 密钥生成错误: {str(e)}")

@router.post("/custom/rsa/encrypt")
async def custom_rsa_encrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供公钥")
    try:
        return {"result": custom_rsa_encrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"自定义 RSA 加密错误: {str(e)}")

@router.post("/custom/rsa/decrypt")
async def custom_rsa_decrypt_endpoint(request: CryptoRequest):
    if not request.key:
        raise HTTPException(status_code=400, detail="需要提供私钥")
    try:
        return {"result": custom_rsa_decrypt(request.text, request.key)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"自定义 RSA 解密错误: {str(e)}")

@router.post("/custom/sha1/hash")
async def custom_sha1_hash_endpoint(request: CryptoRequest):
    try:
        return {"result": custom_sha1_hash(request.text)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"自定义 SHA-1 哈希错误: {str(e)}")