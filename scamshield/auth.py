"""Supabase Managed Authentication for ScamShield India."""

import os
from supabase import create_client, Client

def get_supabase_client() -> Client | None:
    """Initializes the Supabase client from environment variables."""
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    if not url or not key:
        return None
    try:
        return create_client(url, key)
    except Exception:
        return None

def sign_up_user(email: str, password: str) -> tuple[bool, str]:
    """Signs up a new user and checks if email confirmation is required."""
    client = get_supabase_client()
    if not client:
        return False, "Supabase credentials missing in .env."

    try:
        response = client.auth.sign_up({
            "email": email.strip().lower(),
            "password": password
        })

        if response.user:
            # If Supabase is requiring email confirmation (Confirm Email is ON)
            if response.session is None and not response.user.confirmed_at:
                return True, "📧 Confirmation email sent! Please check your inbox and verify your email before signing in."
            
            # If Confirm Email is OFF, user is verified immediately
            return True, "✅ Account created and verified! You can now sign in."

        return False, "Sign-up failed. Please check email format."

    except Exception as e:
        err_msg = str(e)
        if "User already registered" in err_msg:
            return False, "This email is already registered. Please go to 'Sign In'."
        if "Password should be at least" in err_msg:
            return False, "Password must be at least 6 characters long."
        return False, f"Auth Error: {err_msg}"

def sign_in_user(email: str, password: str) -> tuple[bool, str, str | None]:
    """Signs in user. Rejects unconfirmed accounts if Confirm Email is ON."""
    client = get_supabase_client()
    if not client:
        return False, "Supabase credentials missing in .env.", None

    try:
        response = client.auth.sign_in_with_password({
            "email": email.strip().lower(),
            "password": password
        })
        if response.user and response.session:
            return True, "Signed in successfully!", response.user.email
        return False, "Invalid credentials.", None

    except Exception as e:
        err_msg = str(e)
        if "Email not confirmed" in err_msg:
            return False, "⚠️ Your email is not verified yet. Please check your email inbox and click the confirmation link first.", None
        if "Invalid login credentials" in err_msg:
            return False, "Incorrect email or password.", None
        return False, f"Sign-in error: {err_msg}", None

def send_magic_link_otp(email: str) -> tuple[bool, str]:
    """Sends a passwordless login link/OTP directly via Supabase free emailer."""
    client = get_supabase_client()
    if not client:
        return False, "Supabase credentials missing in .env."

    try:
        client.auth.sign_in_with_otp({"email": email.strip().lower()})
        return True, "Verification link sent! Check your email inbox."
    except Exception as e:
        return False, f"Failed to send link: {str(e)}"