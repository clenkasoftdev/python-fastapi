from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration loaded from environment or .env file using pydantic v2 settings.

    Required environment variables:
    - COGNITO_REGION
    - COGNITO_USERPOOL_ID
    - COGNITO_APP_CLIENT_ID
    """

    # Load the .env file and accept environment keys. pydantic-settings
    # normalizes env keys to lowercase with underscores (e.g. COGNITO_REGION -> cognito_region).
    # Use aliases that match those normalized keys so the fields populate correctly.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    region: str = Field(..., alias="cognito_region")
    user_pool_id: str = Field(..., alias="cognito_userpool_id")
    app_client_id: str = Field(..., alias="cognito_app_client_id")


# Create a settings instance if environment variables are present.
# In test runs we may not have env vars, and many tests inject a settings-like
# object instead of relying on a global; avoid raising during import so tests
# can import modules that reference `settings` without the real env configured.
try:
    settings: Optional[Settings] = Settings()
except Exception:
    settings = None
