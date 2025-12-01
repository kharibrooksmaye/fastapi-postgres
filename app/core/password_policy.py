from typing import List, Tuple
import re
from datetime import datetime, timezone

from app.core.settings import settings


class PasswordPolicy:
    """
    Comprehensive password policy validation and enforcement.
    
    Features:
    - Length requirements
    - Character complexity requirements
    - Common password detection
    - Personal information prevention
    - Password history checking
    - Password aging and expiry
    """
    
    # Common passwords list (subset - in production, use a comprehensive list)
    COMMON_PASSWORDS = {
        'password', 'password123', '123456', '123456789', 'qwerty', 
        'abc123', 'password1', 'admin', 'letmein', 'welcome',
        'monkey', '1234567890', 'dragon', 'princess', 'login',
        'admin123', 'root', 'pass', '12345678', 'master',
        'hello', 'charlie', 'aa123456', 'donald', 'password12'
    }
    
    @classmethod
    def validate_password(
        cls, 
        password: str, 
        user_info: dict = None, 
        password_history: List[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Validate password against all policy requirements.
        
        Args:
            password: The password to validate
            user_info: User information to check against (username, email, name)
            password_history: List of hashed previous passwords
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Length validation
        length_errors = cls._validate_length(password)
        errors.extend(length_errors)
        
        # Character complexity validation
        complexity_errors = cls._validate_complexity(password)
        errors.extend(complexity_errors)
        
        # Common password validation
        if settings.password_prevent_common_passwords:
            common_errors = cls._validate_common_passwords(password)
            errors.extend(common_errors)
        
        # Personal information validation
        if settings.password_prevent_personal_info and user_info:
            personal_errors = cls._validate_personal_info(password, user_info)
            errors.extend(personal_errors)
        
        # Password history validation
        if password_history:
            history_errors = cls._validate_password_history(password, password_history)
            errors.extend(history_errors)
        
        return len(errors) == 0, errors
    
    @classmethod
    def _validate_length(cls, password: str) -> List[str]:
        """Validate password length requirements."""
        errors = []
        
        if len(password) < settings.password_min_length:
            errors.append(f"Password must be at least {settings.password_min_length} characters long")
        
        if len(password) > settings.password_max_length:
            errors.append(f"Password must not exceed {settings.password_max_length} characters")
        
        return errors
    
    @classmethod
    def _validate_complexity(cls, password: str) -> List[str]:
        """Validate password character complexity requirements."""
        errors = []
        
        if settings.password_require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if settings.password_require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if settings.password_require_numbers and not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one number")
        
        if settings.password_require_special_chars:
            special_chars = re.escape(settings.password_special_chars)
            if not re.search(f'[{special_chars}]', password):
                errors.append(f"Password must contain at least one special character: {settings.password_special_chars}")
        
        return errors
    
    @classmethod
    def _validate_common_passwords(cls, password: str) -> List[str]:
        """Check against common password list."""
        errors = []
        
        # Normalize password for comparison (lowercase, remove common substitutions)
        normalized = cls._normalize_password(password)
        
        if normalized in cls.COMMON_PASSWORDS:
            errors.append("Password is too common. Please choose a more unique password")
        
        # Check for keyboard patterns
        if cls._is_keyboard_pattern(password):
            errors.append("Password contains keyboard patterns. Please avoid sequences like 'qwerty' or '123456'")
        
        return errors
    
    @classmethod
    def _validate_personal_info(cls, password: str, user_info: dict) -> List[str]:
        """Check if password contains personal information."""
        errors = []
        
        password_lower = password.lower()
        
        # Check against username, email, name
        for field in ['username', 'email', 'name']:
            if field in user_info and user_info[field]:
                value = str(user_info[field]).lower()
                
                # Check if password contains the field value
                if value in password_lower or password_lower in value:
                    errors.append(f"Password must not contain your {field}")
                
                # Check parts of email (before @)
                if field == 'email' and '@' in value:
                    email_user = value.split('@')[0]
                    if len(email_user) > 2 and email_user in password_lower:
                        errors.append("Password must not contain parts of your email address")
                
                # Check name parts
                if field == 'name' and ' ' in value:
                    name_parts = value.split()
                    for part in name_parts:
                        if len(part) > 2 and part in password_lower:
                            errors.append("Password must not contain parts of your name")
        
        return errors
    
    @classmethod
    def _validate_password_history(cls, password: str, password_history: List[str]) -> List[str]:
        """Check against password history."""
        from app.core.authentication import pwd_context
        
        errors = []
        
        # Check if new password matches any of the previous passwords
        for old_password_hash in password_history[-settings.password_history_count:]:
            if pwd_context.verify(password, old_password_hash):
                errors.append(f"Password has been used recently. Please choose a different password (last {settings.password_history_count} passwords cannot be reused)")
                break
        
        return errors
    
    @classmethod
    def _normalize_password(cls, password: str) -> str:
        """Normalize password for common pattern detection."""
        # Convert to lowercase
        normalized = password.lower()
        
        # Common character substitutions
        substitutions = {
            '@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's',
            '$': 's', '7': 't', '4': 'a', '8': 'b', '6': 'g'
        }
        
        for char, replacement in substitutions.items():
            normalized = normalized.replace(char, replacement)
        
        # Remove numbers and special characters for pattern matching
        normalized = re.sub(r'[^a-z]', '', normalized)
        
        return normalized
    
    @classmethod
    def _is_keyboard_pattern(cls, password: str) -> bool:
        """Detect keyboard patterns and sequences."""
        password_lower = password.lower()
        
        # Common keyboard patterns
        patterns = [
            'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
            '1234567890', 'abcdefgh', 'password', '12345', '123456', '1234567'
        ]
        
        # Check for patterns in password
        for pattern in patterns:
            if pattern in password_lower:
                return True
        
        # Check for sequential characters (3 or more)
        for i in range(len(password) - 2):
            char_codes = [ord(c) for c in password[i:i+3]]
            if (char_codes[1] == char_codes[0] + 1 and char_codes[2] == char_codes[1] + 1) or \
               (char_codes[1] == char_codes[0] - 1 and char_codes[2] == char_codes[1] - 1):
                return True
        
        return False
    
    @classmethod
    def check_password_expiry(cls, password_changed_at: datetime) -> Tuple[bool, int, bool]:
        """
        Check if password is expired or expiring soon.
        
        Args:
            password_changed_at: When password was last changed
            
        Returns:
            Tuple of (is_expired, days_until_expiry, should_warn)
        """
        if not password_changed_at or settings.password_max_age_days <= 0:
            return False, -1, False
        
        now = datetime.now(timezone.utc)
        if password_changed_at.tzinfo is None:
            password_changed_at = password_changed_at.replace(tzinfo=timezone.utc)
        
        days_since_change = (now - password_changed_at).days
        days_until_expiry = settings.password_max_age_days - days_since_change
        
        is_expired = days_until_expiry <= 0
        should_warn = days_until_expiry <= settings.password_warn_expiry_days and days_until_expiry > 0
        
        return is_expired, days_until_expiry, should_warn
    
    @classmethod
    def get_password_strength_score(cls, password: str) -> Tuple[int, str]:
        """
        Calculate password strength score (0-100).
        
        Returns:
            Tuple of (score, strength_label)
        """
        score = 0
        
        # Length scoring (up to 25 points)
        length_score = min(25, (len(password) / settings.password_min_length) * 15)
        if len(password) >= 12:
            length_score += 5
        if len(password) >= 16:
            length_score += 5
        score += length_score
        
        # Character variety (up to 40 points)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(f'[{re.escape(settings.password_special_chars)}]', password))
        
        char_variety = sum([has_lower, has_upper, has_digit, has_special])
        score += char_variety * 10
        
        # Uniqueness (up to 20 points)
        if not cls._is_keyboard_pattern(password):
            score += 10
        
        normalized = cls._normalize_password(password)
        if normalized not in cls.COMMON_PASSWORDS:
            score += 10
        
        # Complexity patterns (up to 15 points)
        if len(set(password)) / len(password) > 0.6:  # Character diversity
            score += 5
        
        if not re.search(r'(.)\1{2,}', password):  # No repeated characters
            score += 5
        
        if len(password) > 0 and len(set(password.lower())) / len(password) > 0.7:
            score += 5
        
        # Determine strength label
        if score >= 80:
            strength = "Very Strong"
        elif score >= 65:
            strength = "Strong"
        elif score >= 50:
            strength = "Moderate"
        elif score >= 35:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return min(100, score), strength


def validate_password_policy(
    password: str, 
    user_info: dict = None, 
    password_history: List[str] = None
) -> Tuple[bool, List[str], int, str]:
    """
    Convenience function for complete password validation.
    
    Returns:
        Tuple of (is_valid, errors, strength_score, strength_label)
    """
    is_valid, errors = PasswordPolicy.validate_password(password, user_info, password_history)
    score, strength = PasswordPolicy.get_password_strength_score(password)
    
    return is_valid, errors, score, strength