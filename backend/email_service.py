import os
import smtplib
from email.message import EmailMessage


def send_otp_email(to_email: str, otp: str, expire_minutes: int = 5) -> None:
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")

    if not smtp_user or not smtp_pass:
        raise RuntimeError("SMTP_USER or SMTP_PASS is not configured")

    message = EmailMessage()
    message["Subject"] = "Your SecureShare OTP Code"
    message["From"] = smtp_user
    message["To"] = to_email
    message.set_content(
        "\n".join(
            [
                "Hello,",
                "",
                "Your SecureShare OTP code is:",
                "",
                otp,
                "",
                f"This code will expire in {expire_minutes} minutes.",
                "",
                "If you did not request this login, please ignore this email.",
                "",
                "SecureShare Team",
            ]
        )
    )

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(message)
