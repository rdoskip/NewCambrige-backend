from fastapi import Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.modules.auth import sessions as sessions_module
from app.modules.auth import tokens as tokens_module
from app.modules.auth.exceptions import SessionExpired
from app.modules.usuarios.models import Rol, RolUsuario, Usuario


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=True)


def _cargar_roles(db: Session, user_id: int) -> list[str]:
    filas = (
        db.query(Rol.nombre)
        .join(RolUsuario, Rol.id_rol == RolUsuario.id_rol)
        .filter(RolUsuario.id_usuario == user_id)
        .all()
    )
    return [f[0] for f in filas]


def get_current_user(
    response: Response,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Usuario:
    payload = tokens_module.decodificar_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sesion = sessions_module.buscar_sesion_activa(db, token)
    if not sesion:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión no válida o cerrada",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        sessions_module.validar_sesion(sesion)
    except SessionExpired as exc:
        sessions_module.cerrar_sesion(db, sesion)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    usuario = (
        db.query(Usuario)
        .filter(Usuario.id_usuario == int(payload["sub"]))
        .first()
    )
    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado",
        )

    usuario.rol_nombres = _cargar_roles(db, usuario.id_usuario)
    sessions_module.registrar_actividad(db, sesion)

    if sessions_module.debe_renovar(payload):
        nuevo_token = tokens_module.emitir_access_token(
            usuario.id_usuario, usuario.rol_nombres,
        )
        if sessions_module.rotar_token(db, sesion, token, nuevo_token):
            response.headers["X-Refreshed-Token"] = nuevo_token

    return usuario


def require_roles(roles_permitidos: list[str]):
    def role_checker(
        current_user: Usuario = Depends(get_current_user),
    ) -> Usuario:
        if not any(r in current_user.rol_nombres for r in roles_permitidos):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acceso denegado. Roles requeridos: {roles_permitidos}",
            )
        return current_user

    return role_checker