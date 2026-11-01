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
    """Signs up a new user via Supabase."""
    client = get_supabase_client()
    if not client:
        return False, "Supabase credentials missing in .env (SUPABASE_URL, SUPABASE_KEY)."

    try:
        response = client.auth.sign_up({
            "email": email.strip().lower(),
            "password": password
        })
        if response.user:
            return True, "Account created successfully! You can now sign in."
        return False, "Sign-up failed. Please verify your email format."
    except Exception as e:
        err_msg = str(e)
        if "User already registered" in err_msg:
            return False, "This email is already registered. Please click 'Sign In'."
        if "Password should be at least" in err_msg:
            return False, "Password must be at least 6 characters long."
        return False, f"Auth Error: {err_msg}"

def sign_in_user(email: str, password: str) -> tuple[bool, str, str | None]:
    """Signs in an existing user with email and password."""
    client = get_supabase_client()
    if not client:
        return False, "Supabase credentials missing in .env (SUPABASE_URL, SUPABASE_KEY).", None

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