from sqlalchemy import (
    Column, Integer, String, Boolean, ForeignKey, TIMESTAMP, Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class SesionUsuario(Base):
    __tablename__ = "sesion_usuario"

    id_sesion = Column(Integer, primary_key=True, index=True)
    id_usuario = Column(
        Integer,
        ForeignKey("usuario.id_usuario", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    token = Column(Text, nullable=False, unique=True)
    fecha_inicio = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False,
    )
    fecha_expiracion = Column(TIMESTAMP(timezone=True), nullable=False)
    ultima_actividad = Column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False,
    )
    activa = Column(Boolean, default=True, nullable=False)

    usuario = relationship("Usuario", back_populates="sesiones")


class LoginAttempt(Base):
    __tablename__ = "login_attempt"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, unique=True)
    intentos = Column(Integer, default=0, nullable=False)
    bloqueado_hasta = Column(TIMESTAMP(timezone=True), nullable=True)
    ultimo_intento = Column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )