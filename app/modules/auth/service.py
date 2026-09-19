from sqlalchemy.orm import Session

from app.modules.auth import attempts as attempts_module
from app.modules.auth import passwords as passwords_module
from app.modules.auth import sessions as sessions_module
from app.modules.auth import tokens as tokens_module
from app.modules.auth.exceptions import (
    AccountInactive,
    DuplicateDocument,
    InvalidCredentials,
    InvalidRole,
)
from app.modules.usuarios.models import Rol, RolUsuario, Usuario


def autenticar_usuario(db: Session, documento: str, password: str) -> Usuario:
    usuario = db.query(Usuario).filter(Usuario.documento == documento).first()
    if not usuario:
        raise InvalidCredentials()

    attempts_module.verificar_bloqueo(db, documento)

    if not usuario.estado:
        raise AccountInactive()

    if not passwords_module.verify_password(password, usuario.contrasena):
        attempts_module.registrar_intento_fallido(db, documento)
        raise InvalidCredentials()

    attempts_module.limpiar_intentos(db, documento)
    return usuario


def asignar_roles(db: Session, user_id: int, roles: list[str]) -> None:
    for nombre in roles:
        rol = db.query(Rol).filter(Rol.nombre == nombre).first()
        if not rol:
            raise InvalidRole(f"Rol no encontrado: {nombre}")
        db.add(RolUsuario(id_usuario=user_id, id_rol=rol.id_rol))


def crear_usuario(
    db: Session,
    nombre: str,
    documento: str,
    contrasena: str,
    roles: list[str] | None = None,
) -> Usuario:
    if db.query(Usuario).filter(Usuario.documento == documento).first():
        raise DuplicateDocument()

    usuario = Usuario(
        nombre=nombre,
        documento=documento,
        contrasena=passwords_module.hash_password(contrasena),
    )
    db.add(usuario)
    db.commit()
    db.refresh(usuario)

    try:
        asignar_roles(db, usuario.id_usuario, roles or ["none"])
    except InvalidRole:
        db.delete(usuario)
        db.commit()
        raise

    db.commit()
    return usuario


def _roles_de(db: Session, user_id: int) -> list[str]:
    filas = (
        db.query(Rol.nombre)
        .join(RolUsuario, Rol.id_rol == RolUsuario.id_rol)
        .filter(RolUsuario.id_usuario == user_id)
        .all()
    )
    return [f[0] for f in filas]


def generar_token(db: Session, usuario: Usuario) -> dict:
    roles = _roles_de(db, usuario.id_usuario)
    token = tokens_module.emitir_access_token(usuario.id_usuario, roles)
    sessions_module.crear_o_renovar_sesion(db, usuario.id_usuario, token)
    return {"access_token": token, "token_type": "bearer"}