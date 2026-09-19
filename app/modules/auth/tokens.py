from app.core.security import crear_token, verificar_token


def emitir_access_token(user_id: int, roles: list[str]) -> str:
    """Genera un JWT con el id de usuario y sus roles."""
    return crear_token({"sub": str(user_id), "roles": roles})


def decodificar_token(token: str) -> dict | None:
    """Devuelve el payload si el JWT es válido, o None."""
    return verificar_token(token)