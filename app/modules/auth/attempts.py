from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.modules.auth.exceptions import AccountLocked
from app.modules.auth.models import LoginAttempt


MAX_ATTEMPTS = 5
LOCK_MINUTES = 1


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def verificar_bloqueo(db: Session, documento: str) -> None:
    intento = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username == documento)
        .first()
    )
    if intento and intento.bloqueado_hasta:
        if _ensure_aware(intento.bloqueado_hasta) > _now():
            raise AccountLocked()


def registrar_intento_fallido(db: Session, documento: str) -> None:
    intento = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username == documento)
        .first()
    )

    if not intento:
        db.add(LoginAttempt(username=documento, intentos=1))
    else:
        intento.intentos += 1
        if intento.intentos >= MAX_ATTEMPTS:
            intento.bloqueado_hasta = _now() + timedelta(minutes=LOCK_MINUTES)
            intento.intentos = 0

    db.commit()


def limpiar_intentos(db: Session, documento: str) -> None:
    intento = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username == documento)
        .first()
    )
    if intento:
        intento.intentos = 0
        intento.bloqueado_hasta = None
        db.commit()