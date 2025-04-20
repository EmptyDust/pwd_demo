from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def sha1_hash(text: str) -> str:
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(text.encode())
    return digest.finalize().hex()