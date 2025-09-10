from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "Maktaba API"
    db_endpoint: str
    db_user: str
    db_pw: str
    db_port: str
    db_name: str

    model_config = SettingsConfigDict(env_file=".env")
settings = Settings()