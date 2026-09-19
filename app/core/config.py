from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"

    # JWT settings
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Session settings
    SESSION_IDLE_MINUTES: int = 30
    SESSION_ABSOLUTE_MINUTES: int = 720          # 12 h
    REFRESH_THRESHOLD_RATIO: float = 0.5
    ACTIVITY_UPDATE_THROTTLE_SECONDS: int = 30


    ENVIRONMENT: str = "development"
    APP_URL: str = "http://localhost:8000"
    WEB_URL: str = "https://www.webcolegios.com/clararincon/"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
