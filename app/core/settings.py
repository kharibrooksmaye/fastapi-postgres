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
    test_db_url: str
    image_api_key: str
    google_cxe: str
    s3_keyid: str
    s3_secret: str
    supabase_url: str
    supabase_key: str
    supabase_service_key: str
    stripe_api_key: str
    stripe_api_live_key: str
    stripe_webhook_secret: str = ""  # Optional for local development

    # Refresh token configuration
    refresh_token_expire_days: int = 30
    refresh_token_remember_me_days: int = 90


    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
