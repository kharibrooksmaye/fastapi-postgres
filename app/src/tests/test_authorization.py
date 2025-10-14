import pytest
from fastapi import HTTPException
from app.core.authorization import require_roles, require_minimum_role
from app.src.models.users import User
from app.src.schema.users import UserTypeEnum


@pytest.fixture
def user_factory():
    """Factory function to create mock users"""
    def _create_user(user_type: UserTypeEnum, user_id: int = 1):
        return User(
            id=user_id,
            name=f"{user_type.value.capitalize()} User",
            member_id=str(user_id),
            username=user_type.value,
            email=f"{user_type.value}@example.com",
            password="hashedpassword",
            is_active=True,
            type=user_type
        )
    return _create_user


@pytest.fixture
def admin_user(user_factory):
    return user_factory(UserTypeEnum.admin, 1)


@pytest.fixture
def librarian_user(user_factory):
    return user_factory(UserTypeEnum.librarian, 2)


@pytest.fixture
def patron_user(user_factory):
    return user_factory(UserTypeEnum.patron, 3)


@pytest.mark.parametrize("role,user_fixture", [
    ("admin", "admin_user"),
    ("librarian", "librarian_user"),
    ("patron", "patron_user"),
])
async def test_require_roles_single_role_success(role, user_fixture, request):
    """Test require_roles with single role - user has required role"""
    user = request.getfixturevalue(user_fixture)
    check_roles = require_roles(role)
    result = await check_roles(user)
    assert result == user
    assert result.type.value == role


@pytest.mark.parametrize("required_role,user_fixture,user_role", [
    ("admin", "patron_user", "patron"),
    ("admin", "librarian_user", "librarian"),
    ("librarian", "patron_user", "patron"),
])
async def test_require_roles_access_denied(required_role, user_fixture, user_role, request):
    """Test require_roles - user lacks required role"""
    user = request.getfixturevalue(user_fixture)
    check_roles = require_roles(required_role)

    with pytest.raises(HTTPException) as exc_info:
        await check_roles(user)

    assert exc_info.value.status_code == 403
    assert "Access forbidden" in exc_info.value.detail
    assert required_role in exc_info.value.detail


async def test_require_roles_list_of_roles_success(librarian_user):
    """Test require_roles with list - user has one of the roles"""
    check_roles = require_roles(["admin", "librarian"])
    result = await check_roles(librarian_user)
    assert result == librarian_user


async def test_require_roles_string_conversion(admin_user):
    """Test require_roles converts string to list"""
    check_roles = require_roles("admin")
    result = await check_roles(admin_user)
    assert result.type == UserTypeEnum.admin


@pytest.mark.parametrize("minimum_role,user_fixture", [
    ("patron", "patron_user"),
    ("librarian", "librarian_user"),
    ("admin", "admin_user"),
])
async def test_require_minimum_role_exact_match(minimum_role, user_fixture, request):
    """Test require_minimum_role - user has exact minimum role"""
    user = request.getfixturevalue(user_fixture)
    check_minimum = require_minimum_role(minimum_role)
    result = await check_minimum(user)
    assert result == user


@pytest.mark.parametrize("minimum_role,user_fixture", [
    ("patron", "librarian_user"),
    ("patron", "admin_user"),
    ("librarian", "admin_user"),
])
async def test_require_minimum_role_hierarchical_access(minimum_role, user_fixture, request):
    """Test require_minimum_role - higher role can access lower role resources"""
    user = request.getfixturevalue(user_fixture)
    check_minimum = require_minimum_role(minimum_role)
    result = await check_minimum(user)
    assert result == user


@pytest.mark.parametrize("minimum_role,user_fixture,expected_message", [
    ("librarian", "patron_user", "Requires minimum role of librarian"),
    ("admin", "patron_user", "Requires minimum role of admin"),
    ("admin", "librarian_user", "Requires minimum role of admin"),
])
async def test_require_minimum_role_access_denied(minimum_role, user_fixture, expected_message, request):
    """Test require_minimum_role - lower role cannot access higher role resources"""
    user = request.getfixturevalue(user_fixture)
    check_minimum = require_minimum_role(minimum_role)

    with pytest.raises(HTTPException) as exc_info:
        await check_minimum(user)

    assert exc_info.value.status_code == 403
    assert expected_message in exc_info.value.detail


def test_require_minimum_role_invalid_role():
    """Test require_minimum_role with invalid role raises ValueError"""
    with pytest.raises(ValueError) as exc_info:
        require_minimum_role("invalid_role")

    assert "Invalid role: invalid_role" in str(exc_info.value)
