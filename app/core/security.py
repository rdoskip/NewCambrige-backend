import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from cryptography.fernet import Fernet
from jose import jwt, JWTError
from app.core.config import settings


import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography.fernet import Fernet
from jose import jwt, JWTError

from app.core.config import settings


# ==========================================
# JWT
# ==========================================

def crear_token(data: dict) -> str:
    ahora = datetime.now(timezone.utc)
    payload = {
        **data,
        "iat": ahora,
        "exp": ahora + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verificar_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"leeway": 5},
        )
    except JWTError:
        return None


# ==========================================
# FERNET (cifrado simétrico de datos)
# ==========================================

def _get_fernet_key() -> bytes:
    key_material = settings.SECRET_KEY.encode()[:32].ljust(32, b"0")
    return base64.urlsafe_b64encode(key_material)


_fernet = Fernet(_get_fernet_key())


def encriptar_texto(texto: str) -> str:
    if not texto:
        return texto
    return _fernet.encrypt(texto.encode()).decode()


def desencriptar_texto(texto_encriptado: str) -> str:
    if not texto_encriptado:
        return texto_encriptado
    try:
        return _fernet.decrypt(texto_encriptado.encode()).decode()
    except Exception:
        return texto_encriptado