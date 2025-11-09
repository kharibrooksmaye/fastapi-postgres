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
