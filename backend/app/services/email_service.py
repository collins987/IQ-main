# app/services/email_service.py
"""
Email delivery service supporting SMTP.
Designed to work with MailHog (dev) and production SMTP servers.

Configuration via app/config.py:
- SMTP_HOST
- SMTP_PORT
- SMTP_USERNAME
- SMTP_PASSWORD
- SMTP_TLS

Can be easily extended for SendGrid, AWS SES, etc.
"""

import smtplib
from email.message import EmailMessage
from app.config import (
    EMAIL_FROM,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USERNAME,
    SMTP_PASSWORD,
    SMTP_TLS,
)


def send_email(to: str, subject: str, html_content: str) -> bool:
    """
    Send an email via SMTP.
    
    Args:
        to: Recipient email address
        subject: Email subject
        html_content: HTML email body
    
    Returns:
        True if sent successfully, False on error
    
    Note:
        For development: Use MailHog on localhost:1025
        docker compose up mailhog
        Web UI: http://localhost:8025
    """
    try:
        msg = EmailMessage()
        msg["From"] = EMAIL_FROM
        msg["To"] = to
        msg["Subject"] = subject
        
        # Fallback for non-HTML clients
        msg.set_content("This email requires an HTML-capable client.")
        
        # Add HTML alternative
        msg.add_alternative(html_content, subtype="html")
        
        # Send via SMTP
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_TLS:
                server.starttls()
            
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            
            server.send_message(msg)
        
        print(f"✅ Email sent to {to}")
        return True
    
    except Exception as e:
        print(f"❌ Failed to send email to {to}: {str(e)}")
        return False

