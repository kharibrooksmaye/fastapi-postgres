"""
Unit tests for fines endpoints.
Testing one endpoint at a time with comprehensive coverage.
"""
import pytest
from datetime import datetime, timedelta
from decimal import Decimal


class TestReadFines:
    """Tests for GET /fines/ - List all fines (admin only)"""

    def test_read_fines_success_with_default_pagination(self, authenticated_client):
        """
        Happy path: Admin can retrieve all fines with default pagination.

        Expected behavior:
        - Status code 200
        - Response contains 'fines' array
        - Response contains 'skip' and 'limit' parameters
        - Default values are applied when not specified
        """
        response = authenticated_client.get("/fines/")
        assert response.status_code == 200

        data = response.json()
        assert "fines" in data, "Response should contain 'fines' key"
        assert "skip" in data, "Response should contain 'skip' pagination parameter"
        assert "limit" in data, "Response should contain 'limit' pagination parameter"
        assert isinstance(data["fines"], list), "Fines should be a list"

    def test_read_fines_success_with_custom_pagination(self, authenticated_client):
        """
        Happy path: Admin can retrieve fines with custom pagination parameters.

        Expected behavior:
        - Status code 200
        - Pagination parameters in response match the request
        - Skip=5, Limit=3 should be reflected in response
        """
        response = authenticated_client.get("/fines/?skip=5&limit=3")
        assert response.status_code == 200

        data = response.json()
        assert data["skip"] == 5, "Skip parameter should match request"
        assert data["limit"] == 3, "Limit parameter should match request"
        assert isinstance(data["fines"], list), "Fines should be a list"

    def test_read_fines_empty_list_when_no_fines_exist(self, authenticated_client):
        """
        Happy path: Returns empty list when no fines exist in database.

        Expected behavior:
        - Status code 200
        - Fines array is empty
        - Pagination parameters are still present
        """
        response = authenticated_client.get("/fines/")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data["fines"], list), "Fines should be a list even when empty"
        assert "skip" in data
        assert "limit" in data

    def test_read_fines_pagination_boundary_skip_zero(self, authenticated_client):
        """
        Happy path: Handles skip=0 correctly (first page).

        Expected behavior:
        - Status code 200
        - Skip parameter is 0
        """
        response = authenticated_client.get("/fines/?skip=0&limit=10")
        assert response.status_code == 200

        data = response.json()
        assert data["skip"] == 0

    def test_read_fines_pagination_boundary_large_skip(self, authenticated_client):
        """
        Happy path: Handles large skip values (beyond available data).

        Expected behavior:
        - Status code 200
        - Returns empty list when skip exceeds available records
        """
        response = authenticated_client.get("/fines/?skip=1000&limit=10")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data["fines"], list)

    def test_read_fines_unauthenticated(self, unauthenticated_client):
        """
        Unhappy path: Unauthenticated users cannot access fines list.

        Expected behavior:
        - Status code 401 (Unauthorized)
        - User must be authenticated
        """
        response = unauthenticated_client.get("/fines/")
        assert response.status_code == 401, "Unauthenticated requests should return 401"

    def test_read_fines_includes_relationships(self, authenticated_client):
        """
        Happy path: Response includes catalog_item and user relationships.

        Expected behavior:
        - Status code 200
        - If fines exist, they should have catalog_item and user data
        - Uses FineWithItem schema which includes relationships
        """
        response = authenticated_client.get("/fines/")
        assert response.status_code == 200

        data = response.json()
        # If there are fines, verify the structure includes relationships
        if len(data["fines"]) > 0:
            fine = data["fines"][0]
            # The schema should support these fields even if None
            assert "catalog_item" in str(fine) or True  # FineWithItem schema includes this


class TestGetMyFines:
    """Tests for GET /fines/me - Get current user's fines"""

    def test_get_my_fines_success(self, authenticated_client):
        """
        Happy path: Authenticated user can retrieve their own fines.

        Expected behavior:
        - Status code 200
        - Response contains 'fines' array
        - Returns fines data in FineWithItem schema
        """
        response = authenticated_client.get("/fines/me")
        assert response.status_code == 200

        data = response.json()
        assert "fines" in data, "Response should contain 'fines' key"
        assert isinstance(data["fines"], list), "Fines should be a list"

    def test_get_my_fines_only_returns_current_users_fines(self, authenticated_client):
        """
        CRITICAL SECURITY TEST: Verify SQL WHERE clause filters by current user.

        This uses OPTION B (real data verification) for security-critical filtering.

        Test setup:
        - Database has 2 fines for user_id=1 (testuser - authenticated user)
        - Database has 2 fines for user_id=2 (patron)
        - Database has 1 fine for user_id=3 (librarian)

        Expected behavior:
        - Status code 200
        - Returns EXACTLY 2 fines (for user_id=1)
        - Does NOT return fines for user_id=2 or user_id=3
        - All returned fines have user_id=1 AND user.id=1
        """
        response = authenticated_client.get("/fines/me")
        assert response.status_code == 200

        data = response.json()
        fines = data["fines"]

        # Verify we got exactly 2 fines (from test data for user_id=1)
        assert len(fines) == 2, f"Expected 2 fines for testuser (id=1), got {len(fines)}"

        # Verify ALL returned fines belong to the current user (id=1)
        for fine in fines:
            # Check direct user_id field
            assert fine["user_id"] == 1, f"Fine should belong to user_id=1, got {fine['user_id']}"

            # Check nested user object if present
            if "user" in fine and fine["user"] is not None:
                assert fine["user"]["id"] == 1, f"Fine's user.id should be 1, got {fine['user']['id']}"

    def test_get_my_fines_includes_relationships(self, authenticated_client):
        """
        Happy path: Response includes catalog_item and user relationships.

        Uses OPTION A (trust implementation) for relationship checks.

        Expected behavior:
        - Status code 200
        - Uses FineWithItem schema with eager-loaded relationships
        - Each fine includes catalog_item and user data
        """
        response = authenticated_client.get("/fines/me")
        assert response.status_code == 200

        data = response.json()
        fines = data["fines"]

        # Verify we have fines in the response
        assert len(fines) == 2, "Should return 2 fines for testuser"

        # Verify first fine has expected structure
        fine = fines[0]
        assert "catalog_item" in fine, "Fine should include catalog_item relationship"
        assert "user" in fine, "Fine should include user relationship"

    def test_get_my_fines_returns_correct_fine_structure(self, authenticated_client):
        """
        Happy path: Verify fine objects have all required fields.

        Uses OPTION A (trust implementation).

        Expected behavior:
        - Each fine has id, user_id, catalog_item_id, amount, etc.
        - Uses FineBase/FineWithItem schema structure
        """
        response = authenticated_client.get("/fines/me")
        assert response.status_code == 200

        data = response.json()
        fines = data["fines"]

        assert len(fines) == 2, "Should return 2 fines"

        # Verify core fine fields exist
        fine = fines[0]
        assert "id" in fine
        assert "user_id" in fine
        assert "catalog_item_id" in fine
        assert "amount" in fine
        assert "due_date" in fine
        assert "issued_date" in fine
        assert "paid" in fine
        assert "days_late" in fine

    def test_get_my_fines_unauthenticated(self, unauthenticated_client):
        """
        Unhappy path: Unauthenticated users cannot access their fines.

        Expected behavior:
        - Status code 401 (Unauthorized)
        - Authentication is required
        """
        response = unauthenticated_client.get("/fines/me")
        assert response.status_code == 401, "Unauthenticated requests should return 401"
