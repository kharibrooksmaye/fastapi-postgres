from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Maktaba API"
    db_endpoint: str
    db_user: str
    db_pw: str
    db_port: str
    db_name: str
    secret_key: str
    access_token_expire_minutes: str = "30"
    algorithm: str = "HS256"
    db_url: str

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
