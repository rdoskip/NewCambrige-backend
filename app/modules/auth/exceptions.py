class AuthError(Exception):
    """Base de errores de autenticación/autorización."""
    status_code: int = 401
    detail: str = "Error de autenticación"

    def __init__(self, detail: str | None = None):
        if detail is not None:
            self.detail = detail
        super().__init__(self.detail)


class InvalidCredentials(AuthError):
    detail = "Credenciales incorrectas"


class AccountLocked(AuthError):
    status_code = 429
    detail = "Demasiados intentos. Intenta nuevamente en 1 minuto."


class AccountInactive(AuthError):
    status_code = 403
    detail = "Usuario inactivo. Contacte al administrador."


class SessionExpired(AuthError):
    detail = "Sesión expirada"


class SessionNotFound(AuthError):
    detail = "Sesión no válida o cerrada"


class UserNotFound(AuthError):
    detail = "Usuario no encontrado"


class DuplicateDocument(AuthError):
    status_code = 400
    detail = "El documento ya está registrado"


class InvalidRole(AuthError):
    status_code = 400
    detail = "Rol inválido"