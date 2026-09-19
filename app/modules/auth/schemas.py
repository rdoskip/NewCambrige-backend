from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class UsuarioResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_usuario: int
    nombre: str
    documento: str


class UsuarioCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    nombre: str
    password: str
    documento: str
    roles: Optional[List[str]] = None