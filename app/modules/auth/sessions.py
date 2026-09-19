from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.modules.auth.exceptions import SessionExpired
from app.modules.auth.models import SesionUsuario


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def buscar_sesion_activa(db: Session, token: str) -> SesionUsuario | None:
    return (
        db.query(SesionUsuario)
        .filter(
            SesionUsuario.token == token,
            SesionUsuario.activa.is_(True),
        )
        .first()
    )


def crear_sesion(db: Session, user_id: int, token: str) -> SesionUsuario:
    ahora = _now()
    sesion = SesionUsuario(
        id_usuario=user_id,
        token=token,
        fecha_inicio=ahora,
        fecha_expiracion=ahora + timedelta(minutes=settings.SESSION_ABSOLUTE_MINUTES),
        ultima_actividad=ahora,
        activa=True,
    )
    db.add(sesion)
    db.commit()
    db.refresh(sesion)
    return sesion


def crear_o_renovar_sesion(db: Session, user_id: int, token: str) -> SesionUsuario:
    """
    Una sola fila por usuario. Sobrescribe la existente o crea si no hay.
    """
    ahora = _now()
    sesion = (
        db.query(SesionUsuario)
        .filter(SesionUsuario.id_usuario == user_id)
        .first()
    )

    if sesion is None:
        sesion = SesionUsuario(
            id_usuario=user_id,
            token=token,
            fecha_inicio=ahora,
            fecha_expiracion=ahora + timedelta(minutes=settings.SESSION_ABSOLUTE_MINUTES),
            ultima_actividad=ahora,
            activa=True,
        )
        db.add(sesion)
    else:
        sesion.token = token
        sesion.fecha_inicio = ahora
        sesion.fecha_expiracion = ahora + timedelta(minutes=settings.SESSION_ABSOLUTE_MINUTES)
        sesion.ultima_actividad = ahora
        sesion.activa = True

    db.commit()
    db.refresh(sesion)
    return sesion

def cerrar_sesion(db: Session, sesion: SesionUsuario) -> None:
    sesion.activa = False
    db.commit()


def validar_sesion(sesion: SesionUsuario) -> None:
    """Lanza SessionExpired si la sesión ya no es válida."""
    ahora = _now()

    if _ensure_aware(sesion.fecha_expiracion) <= ahora:
        raise SessionExpired("Sesión expirada por tiempo máximo")

    limite_inactividad = _ensure_aware(sesion.ultima_actividad) + timedelta(
        minutes=settings.SESSION_IDLE_MINUTES
    )
    if limite_inactividad <= ahora:
        raise SessionExpired("Sesión expirada por inactividad")


def registrar_actividad(db: Session, sesion: SesionUsuario) -> None:
    """Actualiza ultima_actividad con throttle para no escribir en cada request."""
    ahora = _now()
    delta = (ahora - _ensure_aware(sesion.ultima_actividad)).total_seconds()
    if delta >= settings.ACTIVITY_UPDATE_THROTTLE_SECONDS:
        sesion.ultima_actividad = ahora
        db.commit()


def debe_renovar(payload: dict) -> bool:
    """True si al token le queda menos del umbral configurado."""
    exp = payload.get("exp")
    iat = payload.get("iat")
    if not exp or not iat:
        return False

    ahora = _now().timestamp()
    vida_total = exp - iat
    if vida_total <= 0:
        return False

    return (exp - ahora) <= vida_total * settings.REFRESH_THRESHOLD_RATIO


def rotar_token(
    db: Session, sesion: SesionUsuario, token_viejo: str, token_nuevo: str,
) -> bool:
    """
    Rota el token de la sesión de forma atómica.
    Devuelve True si esta request fue la que rotó.
    Evita condiciones de carrera cuando hay varias requests concurrentes.
    """
    filas = (
        db.query(SesionUsuario)
        .filter(
            SesionUsuario.id_sesion == sesion.id_sesion,
            SesionUsuario.token == token_viejo,
        )
        .update({"token": token_nuevo}, synchronize_session=False)
    )
    db.commit()
    return filas > 0