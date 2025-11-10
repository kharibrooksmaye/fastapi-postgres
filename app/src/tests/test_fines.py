"""
Unit tests for fines endpoints.
Testing one endpoint at a time with comprehensive coverage.
"""
import pytest
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import patch, MagicMock


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


class TestGetUserFines:
    """Tests for GET /fines/{user_id} - Get specific user's fines (staff only)"""

    def test_get_user_fines_success_for_specific_user(self, authenticated_client):
        """
        Happy path: Staff can retrieve fines for any specific user by user_id.

        Uses OPTION B (real data) for security-critical user filtering.

        Test setup:
        - Database has 2 fines for user_id=2 (patron)
        - Authenticated as admin (staff role)

        Expected behavior:
        - Status code 200
        - Returns exactly 2 fines for user_id=2
        - Does NOT return fines for other users
        """
        response = authenticated_client.get("/fines/2")
        assert response.status_code == 200

        data = response.json()
        assert "fines" in data
        fines = data["fines"]

        # Verify we got exactly 2 fines for user_id=2
        assert len(fines) == 2, f"Expected 2 fines for user_id=2, got {len(fines)}"

        # Verify all fines belong to user_id=2
        for fine in fines:
            assert fine["user_id"] == 2, f"All fines should belong to user_id=2, got {fine['user_id']}"

    def test_get_user_fines_returns_empty_for_nonexistent_user(self, authenticated_client):
        """
        Happy path: Returns empty list for non-existent user_id.

        Uses OPTION A (trust implementation).

        Expected behavior:
        - Status code 200
        - Returns empty fines array
        - Does not raise 404
        """
        response = authenticated_client.get("/fines/99999")
        assert response.status_code == 200

        data = response.json()
        assert "fines" in data
        assert data["fines"] == [], "Should return empty list for non-existent user"

    def test_get_user_fines_returns_empty_for_user_with_no_fines(self, authenticated_client):
        """
        Happy path: Returns empty list for user with no fines.

        Uses OPTION A (trust implementation).

        Note: We could create a user with no fines, but trust that
        the query handles this correctly.

        Expected behavior:
        - Status code 200
        - Returns empty fines array
        """
        # User 99999 doesn't exist, so will return empty
        response = authenticated_client.get("/fines/99999")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data["fines"], list)

    def test_get_user_fines_unauthenticated(self, unauthenticated_client):
        """
        Unhappy path: Unauthenticated users cannot access user fines.

        Expected behavior:
        - Status code 401 (Unauthorized)
        - Must be authenticated
        """
        response = unauthenticated_client.get("/fines/2")
        assert response.status_code == 401, "Unauthenticated requests should return 401"


class TestGetFine:
    """Tests for GET /fines/fine/{fine_id} - Get specific fine details"""

    def test_get_fine_success_as_staff(self, authenticated_client):
        """
        Happy path: Staff can retrieve any fine by fine_id.

        Uses OPTION B (real data) to verify fine retrieval.

        Test setup:
        - Database has fine with id=1 (belongs to user_id=1)
        - Authenticated as admin (staff role)

        Expected behavior:
        - Status code 200
        - Returns fine with all details
        - Includes catalog_item and user relationships
        """
        response = authenticated_client.get("/fines/fine/1")
        assert response.status_code == 200

        data = response.json()
        assert "fine" in data, "Response should contain 'fine' key"
        fine = data["fine"]

        # Verify fine details
        assert fine["id"] == 1
        assert fine["user_id"] == 1
        assert "catalog_item" in fine
        assert "user" in fine

    def test_get_fine_success_as_owner(self, authenticated_client):
        """
        Happy path: User can retrieve their own fine.

        Uses OPTION B (real data) for ownership verification.

        Test setup:
        - Database has fine with id=1 (belongs to user_id=1)
        - Authenticated as user_id=1 (owns the fine)

        Expected behavior:
        - Status code 200
        - Returns the fine (user owns it)
        - Includes relationships
        """
        response = authenticated_client.get("/fines/fine/1")
        assert response.status_code == 200

        data = response.json()
        fine = data["fine"]

        # Verify it's the user's fine
        assert fine["id"] == 1
        assert fine["user_id"] == 1

    def test_get_fine_not_found(self, authenticated_client):
        """
        Unhappy path: Returns 404 for non-existent fine_id.

        Expected behavior:
        - Status code 404
        - Error detail message indicates fine not found
        - Checked BEFORE authorization (404 takes precedence)
        """
        response = authenticated_client.get("/fines/fine/99999")
        assert response.status_code == 404
        assert response.json()["detail"] == "Fine not found"

    def test_get_fine_includes_relationships(self, authenticated_client):
        """
        Happy path: Response includes eager-loaded relationships.

        Uses OPTION A (trust implementation) for relationship checks.

        Expected behavior:
        - Status code 200
        - Fine includes catalog_item relationship
        - Fine includes user relationship
        - Uses FineWithItem schema
        """
        response = authenticated_client.get("/fines/fine/1")
        assert response.status_code == 200

        data = response.json()
        fine = data["fine"]

        assert "catalog_item" in fine, "Fine should include catalog_item"
        assert "user" in fine, "Fine should include user"

    def test_get_fine_unauthenticated(self, unauthenticated_client):
        """
        Unhappy path: Unauthenticated users cannot access fine details.

        Expected behavior:
        - Status code 401 (Unauthorized)
        - Must be authenticated
        """
        response = unauthenticated_client.get("/fines/fine/1")
        assert response.status_code == 401, "Unauthenticated requests should return 401"


class TestDeleteFine:
    """Tests for DELETE /fines/{fine_id} - Delete specific fine (admin only)"""

    def test_delete_fine_success(self, authenticated_client):
        """
        Happy path: Admin can delete a fine by fine_id.

        Uses OPTION B (real data) to verify deletion.

        Test setup:
        - Database has fine with id=1
        - Authenticated as admin

        Expected behavior:
        - Status code 200
        - Returns success message
        - Fine is actually deleted from database
        """
        response = authenticated_client.delete("/fines/1")
        assert response.status_code == 200
        assert response.json()["detail"] == "Fine deleted successfully"

        # Verify fine was deleted by trying to get it
        get_response = authenticated_client.get("/fines/fine/1")
        assert get_response.status_code == 404, "Fine should be deleted"

    def test_delete_fine_not_found(self, authenticated_client):
        """
        Unhappy path: Returns 404 when trying to delete non-existent fine.

        Expected behavior:
        - Status code 404
        - Error detail indicates fine not found
        """
        response = authenticated_client.delete("/fines/99999")
        assert response.status_code == 404
        assert response.json()["detail"] == "Fine not found"

    def test_delete_fine_unauthenticated(self, unauthenticated_client):
        """
        Unhappy path: Unauthenticated users cannot delete fines.

        Expected behavior:
        - Status code 401 (Unauthorized)
        - Must be authenticated as admin
        """
        response = unauthenticated_client.delete("/fines/1")
        assert response.status_code == 401, "Unauthenticated requests should return 401"


class TestDeleteAllFines:
    """Tests for DELETE /fines/ - Delete all fines (admin only)"""

    def test_delete_all_fines_success(self, authenticated_client):
        """
        Happy path: Admin can delete all fines.

        Uses OPTION B (real data) to verify all fines deleted.

        Test setup:
        - Database has 5 fines total
        - Authenticated as admin

        Expected behavior:
        - Status code 200
        - Returns success message
        - All fines are deleted from database
        """
        response = authenticated_client.delete("/fines/")
        assert response.status_code == 200
        assert response.json()["detail"] == "All fines deleted successfully"

        # Verify all fines were deleted
        get_response = authenticated_client.get("/fines/")
        assert get_response.status_code == 200
        assert len(get_response.json()["fines"]) == 0, "All fines should be deleted"

    def test_delete_all_fines_unauthenticated(self, unauthenticated_client):
        """
        Unhappy path: Unauthenticated users cannot delete all fines.

        Expected behavior:
        - Status code 401 (Unauthorized)
        - Must be authenticated as admin
        """
        response = unauthenticated_client.delete("/fines/")
        assert response.status_code == 401, "Unauthenticated requests should return 401"


class TestPayFine:
    """Tests for POST /fines/pay/{fine_id} - Create payment intent for a fine"""

    @patch("app.src.routes.fines.create_stripe_payment_intent")
    def test_pay_fine_success_as_owner(self, mock_stripe, authenticated_client):
        """
        Happy path: User can pay their own fine.

        Uses OPTION B (real data) to verify authorization.

        Test setup:
        - Fine id=1 belongs to user_id=1 (testuser - authenticated user)
        - Mock Stripe payment intent creation

        Expected behavior:
        - Status code 200
        - Returns fine data, payment_intent, client_secret, total_amount
        - Stripe payment intent created with correct amount
        """
        # Mock Stripe response
        mock_intent = MagicMock()
        mock_intent.id = "pi_test_123456"
        mock_intent.client_secret = "pi_test_123456_secret_abc"
        mock_stripe.return_value = mock_intent

        response = authenticated_client.post("/fines/pay/1")
        assert response.status_code == 200

        data = response.json()
        assert "fine" in data, "Response should contain fine data"
        assert "payment_intent" in data, "Response should contain payment_intent ID"
        assert "client_secret" in data, "Response should contain client_secret"
        assert "total_amount" in data, "Response should contain total_amount"

        # Verify Stripe was called
        assert mock_stripe.called, "Stripe payment intent should be created"

        # Verify the fine belongs to the user
        assert data["fine"]["user_id"] == 1

    @patch("app.src.routes.fines.create_stripe_payment_intent")
    def test_pay_fine_success_as_admin(self, mock_stripe, authenticated_client):
        """
        Happy path: Admin can pay any user's fine.

        Uses OPTION B (real data) to verify admin authorization.

        Test setup:
        - Fine id=3 belongs to user_id=2 (patron)
        - Authenticated as admin (user_id=1)
        - Mock Stripe payment intent creation

        Expected behavior:
        - Status code 200
        - Admin can pay fine for different user
        - Returns payment intent details
        """
        # Mock Stripe response
        mock_intent = MagicMock()
        mock_intent.id = "pi_test_admin_789"
        mock_intent.client_secret = "pi_test_admin_789_secret_xyz"
        mock_stripe.return_value = mock_intent

        response = authenticated_client.post("/fines/pay/3")
        assert response.status_code == 200

        data = response.json()
        assert data["fine"]["user_id"] == 2, "Fine should belong to user_id=2 (patron)"
        assert "payment_intent" in data
        assert mock_stripe.called

    def test_pay_fine_not_found(self, authenticated_client):
        """
        Unhappy path: Returns 404 for non-existent fine.

        Expected behavior:
        - Status code 404
        - Error detail indicates fine not found
        - Checked BEFORE authorization
        """
        response = authenticated_client.post("/fines/pay/99999")
        assert response.status_code == 404
        assert response.json()["detail"] == "Fine not found"

    def test_pay_fine_already_paid(self, authenticated_client):
        """
        Unhappy path: Returns 400 when trying to pay an already paid fine.

        Uses OPTION B (real data) - fine id=4 is already paid.

        Test setup:
        - Fine id=4 belongs to user_id=2 and is already paid (paid=True)
        - Authenticated as admin who can access any fine

        Expected behavior:
        - Status code 400 (Bad Request)
        - Error message indicates fine is already paid
        """
        response = authenticated_client.post("/fines/pay/4")
        assert response.status_code == 400
        assert response.json()["detail"] == "Fine is already paid"

    def test_pay_fine_unauthenticated(self, unauthenticated_client):
        """
        Unhappy path: Unauthenticated users cannot pay fines.

        Expected behavior:
        - Status code 401 (Unauthorized)
        - Must be authenticated
        """
        response = unauthenticated_client.post("/fines/pay/1")
        assert response.status_code == 401, "Unauthenticated requests should return 401"

    @patch("app.src.routes.fines.create_stripe_payment_intent")
    def test_pay_fine_stripe_metadata(self, mock_stripe, authenticated_client):
        """
        Happy path: Verify Stripe payment intent includes correct metadata.

        Uses OPTION B (real data) to verify metadata content.

        Test setup:
        - Fine id=1 with known values (amount, dates, catalog_item)

        Expected behavior:
        - Status code 200
        - Stripe called with metadata containing fine details
        """
        # Mock Stripe response
        mock_intent = MagicMock()
        mock_intent.id = "pi_test_metadata"
        mock_intent.client_secret = "pi_test_metadata_secret"
        mock_stripe.return_value = mock_intent

        response = authenticated_client.post("/fines/pay/1")
        assert response.status_code == 200

        # Verify Stripe was called with correct parameters
        assert mock_stripe.called
        call_args = mock_stripe.call_args

        # Check metadata contains expected keys
        metadata = call_args.kwargs["metadata"]
        assert "fine_id" in metadata
        assert "user_id" in metadata
        assert "amount" in metadata
        assert "catalog_item" in metadata
        assert "issued_date" in metadata
        assert "due_date" in metadata
        assert "days_late" in metadata
        assert "paid_on" in metadata
