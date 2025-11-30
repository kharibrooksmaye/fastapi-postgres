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