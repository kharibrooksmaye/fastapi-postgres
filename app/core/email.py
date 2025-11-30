from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from app.core.settings import settings


async def send_activation_email(
    email: str,
    username: str,
    activation_token: str
):
    """
    Send activation email with token link

    Args:
        email (str): User's email address
        username (str): User's username
        activation_token (str): Activation token (plaintext)
    """
    
    frontend_url = getattr(settings, "frontend_url", "http://localhost:5173")
    
    activation_link = f"{frontend_url}/activate?token={activation_token}"
    
    subject = "Activate Your Maktaba Account"
    
    html_body = f"""
    <html>
        <body>
            <h2>Welcome to Maktaba, {username}!</h2>
            <p>Thank you for registering. Please click the link below to activate your account:</p>
            <a href="{activation_link}">Activate Account</a>
            <p>Or copy and paste this link into your browser:</p>
        <p>{activation_link}</p>
        <p><strong>This link expires in 48 hours.</strong></p>
        <p>If you didn't create this account, please ignore this email.</p>
      </body>
    </html>
    """
    
    text_body = f"""
    Welcome to Maktaba, {username}!
    Thank you for registering. Please use the link below to activate your account:
    {activation_link}
    This link expires in 48 hours.
    If you didn't create this account, please ignore this email.
    """
    
    # Create message
    
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = email
    
    # Attach parts
    message.attach(MIMEText(text_body, "plain"))
    message.attach(MIMEText(html_body, "html"))
    
    # Send email
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
        print(f"Activation email sent to {email}")
    except Exception as e:
        print(f"Failed to send email to {email}: {e}")


async def send_password_reset_email(
    email: str,
    username: str,
    reset_token: str
):
    """
    Send password reset email with token link

    Args:
        email (str): User's email address
        username (str): User's username
        reset_token (str): Password reset token (plaintext)
    """
    
    frontend_url = getattr(settings, "frontend_url", "http://localhost:5173")
    
    reset_link = f"{frontend_url}/reset-password?token={reset_token}"
    
    subject = "Reset Your Maktaba Password"
    
    html_body = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello {username},</p>
            <p>We received a request to reset your password for your Maktaba account.</p>
            <p>Click the link below to reset your password:</p>
            <a href="{reset_link}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
            <p>Or copy and paste this link into your browser:</p>
            <p>{reset_link}</p>
            <p><strong>This link expires in 1 hour for security reasons.</strong></p>
            <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
            <p>For security, this request came from IP: [IP will be logged by server]</p>
        </body>
    </html>
    """
    
    text_body = f"""
    Password Reset Request
    
    Hello {username},
    
    We received a request to reset your password for your Maktaba account.
    
    Please use the link below to reset your password:
    {reset_link}
    
    This link expires in 1 hour for security reasons.
    
    If you didn't request this password reset, please ignore this email. Your password will remain unchanged.
    """
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = email
    
    # Attach parts
    message.attach(MIMEText(text_body, "plain"))
    message.attach(MIMEText(html_body, "html"))
    
    # Send email
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
        print(f"Password reset email sent to {email}")
    except Exception as e:
        print(f"Failed to send password reset email to {email}: {e}")


async def send_password_changed_notification(
    email: str,
    username: str,
    ip_address: str = "Unknown"
):
    """
    Send notification email when password is successfully changed

    Args:
        email (str): User's email address
        username (str): User's username
        ip_address (str): IP address where the change originated
    """
    
    subject = "Your Maktaba Password Has Been Changed"
    
    html_body = f"""
    <html>
        <body>
            <h2>Password Successfully Changed</h2>
            <p>Hello {username},</p>
            <p>This is a confirmation that your password for your Maktaba account has been successfully changed.</p>
            <p><strong>Change Details:</strong></p>
            <ul>
                <li>Date: Just now</li>
                <li>IP Address: {ip_address}</li>
            </ul>
            <p>If you made this change, no further action is required.</p>
            <p><strong>If you did NOT make this change:</strong></p>
            <ol>
                <li>Someone may have unauthorized access to your account</li>
                <li>Please contact support immediately</li>
                <li>Consider reviewing your account security</li>
            </ol>
            <p>For your security, we recommend using strong, unique passwords and enabling two-factor authentication when available.</p>
        </body>
    </html>
    """
    
    text_body = f"""
    Password Successfully Changed
    
    Hello {username},
    
    This is a confirmation that your password for your Maktaba account has been successfully changed.
    
    Change Details:
    - Date: Just now
    - IP Address: {ip_address}
    
    If you made this change, no further action is required.
    
    If you did NOT make this change:
    1. Someone may have unauthorized access to your account
    2. Please contact support immediately
    3. Consider reviewing your account security
    
    For your security, we recommend using strong, unique passwords and enabling two-factor authentication when available.
    """
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = email
    
    # Attach parts
    message.attach(MIMEText(text_body, "plain"))
    message.attach(MIMEText(html_body, "html"))
    
    # Send email
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
        print(f"Password change notification sent to {email}")
    except Exception as e:
        print(f"Failed to send password change notification to {email}: {e}")


async def send_account_locked_notification(
    email: str,
    username: str,
    lockout_duration_minutes: int = 15,
    failed_attempts: int = 5
):
    """
    Send notification email when account is locked due to failed login attempts

    Args:
        email (str): User's email address
        username (str): User's username
        lockout_duration_minutes (int): How long the account will be locked
        failed_attempts (int): Number of failed attempts that triggered the lockout
    """
    
    subject = "Your Maktaba Account Has Been Temporarily Locked"
    
    html_body = f"""
    <html>
        <body>
            <h2>Account Temporarily Locked</h2>
            <p>Hello {username},</p>
            <p>Your Maktaba account has been temporarily locked due to {failed_attempts} consecutive failed login attempts.</p>
            <p><strong>Security Details:</strong></p>
            <ul>
                <li>Account locked: Just now</li>
                <li>Lockout duration: {lockout_duration_minutes} minutes</li>
                <li>Failed attempts: {failed_attempts}</li>
            </ul>
            <p><strong>What happens next:</strong></p>
            <ul>
                <li>Your account will automatically unlock in {lockout_duration_minutes} minutes</li>
                <li>You can then try logging in again</li>
                <li>The failed attempt counter will reset</li>
            </ul>
            <p><strong>If this wasn't you:</strong></p>
            <ol>
                <li>Someone may be trying to access your account</li>
                <li>Consider changing your password immediately after the lockout expires</li>
                <li>Review your account security settings</li>
                <li>Contact support if you need assistance</li>
            </ol>
            <p>This is an automated security measure to protect your account.</p>
        </body>
    </html>
    """
    
    text_body = f"""
    Account Temporarily Locked
    
    Hello {username},
    
    Your Maktaba account has been temporarily locked due to {failed_attempts} consecutive failed login attempts.
    
    Security Details:
    - Account locked: Just now
    - Lockout duration: {lockout_duration_minutes} minutes
    - Failed attempts: {failed_attempts}
    
    What happens next:
    - Your account will automatically unlock in {lockout_duration_minutes} minutes
    - You can then try logging in again
    - The failed attempt counter will reset
    
    If this wasn't you:
    1. Someone may be trying to access your account
    2. Consider changing your password immediately after the lockout expires
    3. Review your account security settings
    4. Contact support if you need assistance
    
    This is an automated security measure to protect your account.
    """
    
    # Create message
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = email
    
    # Attach parts
    message.attach(MIMEText(text_body, "plain"))
    message.attach(MIMEText(html_body, "html"))
    
    # Send email
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
        print(f"Account locked notification sent to {email}")
    except Exception as e:
        print(f"Failed to send account locked notification to {email}: {e}")