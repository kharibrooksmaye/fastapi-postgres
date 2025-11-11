"""
Tests for RefreshToken model including CSRF token hash field.
"""

import pytest
from datetime import datetime, timedelta, timezone
from app.src.models.refresh_tokens import RefreshToken


class TestRefreshTokenModel:
    """Tests for RefreshToken SQLModel"""

    def test_refresh_token_creation_basic(self):
        """Test creating a basic refresh token without optional fields"""
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        token = RefreshToken(
            user_id=1,
            token_hash="hashed_token_value",
            expires_at=expires_at,
        )

        assert token.user_id == 1
        assert token.token_hash == "hashed_token_value"
        assert token.expires_at == expires_at
        assert token.csrf_token_hash is None  # Optional field
        assert token.device_name is None
        assert token.is_revoked is False
        assert token.revoked_at is None

    def test_refresh_token_with_csrf_hash(self):
        """Test creating refresh token with CSRF token hash"""
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        token = RefreshToken(
            user_id=1,
            token_hash="hashed_token_value",
            csrf_token_hash="hashed_csrf_value",
            expires_at=expires_at,
        )

        assert token.csrf_token_hash == "hashed_csrf_value"

    def test_refresh_token_with_all_fields(self):
        """Test creating refresh token with all fields populated"""
        created = datetime.now(timezone.utc)
        expires = created + timedelta(days=30)
        last_used = created + timedelta(hours=1)
        revoked = created + timedelta(days=1)

        token = RefreshToken(
            user_id=1,
            token_hash="hashed_token_value",
            csrf_token_hash="hashed_csrf_value",
            device_name="Chrome on MacOS",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0...",
            created_at=created,
            expires_at=expires,
            last_used_at=last_used,
            is_revoked=True,
            revoked_at=revoked,
        )

        assert token.user_id == 1
        assert token.token_hash == "hashed_token_value"
        assert token.csrf_token_hash == "hashed_csrf_value"
        assert token.device_name == "Chrome on MacOS"
        assert token.ip_address == "192.168.1.1"
        assert token.user_agent == "Mozilla/5.0..."
        assert token.created_at == created
        assert token.expires_at == expires
        assert token.last_used_at == last_used
        assert token.is_revoked is True
        assert token.revoked_at == revoked

    def test_csrf_token_hash_is_optional(self):
        """Test that csrf_token_hash can be None (backward compatibility)"""
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        # Should work without csrf_token_hash
        token = RefreshToken(
            user_id=1,
            token_hash="hashed_token_value",
            expires_at=expires_at,
        )

        assert token.csrf_token_hash is None

    def test_csrf_token_hash_can_be_updated(self):
        """Test that csrf_token_hash can be set after creation"""
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        token = RefreshToken(
            user_id=1,
            token_hash="hashed_token_value",
            expires_at=expires_at,
        )

        # Initially None
        assert token.csrf_token_hash is None

        # Can be updated
        token.csrf_token_hash = "new_csrf_hash"
        assert token.csrf_token_hash == "new_csrf_hash"
