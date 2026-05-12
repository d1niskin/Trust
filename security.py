import secrets
import string
import hashlib
from cryptography.fernet import Fernet

# Для MVP ключ захардкожен (в реальности он прячется в .env)
ENCRYPTION_KEY = b'v_c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w='
cipher_suite = Fernet(ENCRYPTION_KEY)

def generate_pin(length=6):
    """Генерирует случайный PIN-код (буквы + цифры)"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

def get_password_hash(password: str) -> str:
    """Хэширует PIN с помощью встроенного SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет, совпадает ли введенный PIN с хэшем"""
    return get_password_hash(plain_password) == hashed_password

def encrypt_text(text: str) -> str:
    """Шифрует текст жалобы"""
    return cipher_suite.encrypt(text.encode('utf-8')).decode('utf-8')

def decrypt_text(encrypted_text: str) -> str:
    """Расшифровывает текст жалобы"""
    return cipher_suite.decrypt(encrypted_text.encode('utf-8')).decode('utf-8')