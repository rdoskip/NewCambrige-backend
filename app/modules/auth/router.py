from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.modules.auth import service
from app.modules.auth import sessions as sessions_module
from app.modules.auth.deps import get_current_user, oauth2_scheme, require_roles
from app.modules.auth.exceptions import AuthError
from app.modules.auth.schemas import TokenResponse, UsuarioCreate, UsuarioResponse
from app.modules.usuarios.models import Usuario


router = APIRouter()


@router.post("/token", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    try:
        usuario = service.autenticar_usuario(
            db, form_data.username, form_data.password,
        )
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)

    return service.generar_token(db, usuario)


@router.get("/me", response_model=UsuarioResponse)
def get_me(current_user: Usuario = Depends(get_current_user)):
    return current_user


@router.post("/register", response_model=UsuarioResponse)
def register(
    data: UsuarioCreate,
    db: Session = Depends(get_db),
    _: Usuario = Depends(require_roles(["admin"])),
):
    try:
        usuario = service.crear_usuario(
            db, data.nombre, data.documento, data.password, data.roles,
        )
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)

    return usuario


@router.post("/logout")
def logout(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    sesion = sessions_module.buscar_sesion_activa(db, token)
    if not sesion:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión no encontrada",
        )

    sessions_module.cerrar_sesion(db, sesion)
    return {"message": "Sesión cerrada correctamente"}