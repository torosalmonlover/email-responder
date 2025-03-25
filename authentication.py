import os
import json
import time
import requests
from google.oauth2.credentials import Credentials
from flask import redirect, url_for, request, make_response
from googleapiclient.discovery import build
from dotenv import load_dotenv

load_dotenv()

def init_Oauth(oauth):
    google = oauth.register(
        name="google",
        client_id=os.getenv("CLIENT_ID"),
        client_secret=os.getenv("CLIENT_SECRET"),
        authorize_url="https://accounts.google.com/o/oauth2/auth",
        authorize_params=None,
        access_token_url="https://oauth2.googleapis.com/token",
        access_token_params=None,
        refresh_token_url="https://oauth2.googleapis.com/token",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly"},
    )

    return google

from flask import session

def init_Gmail():
    # If the service is already in the session, return it
    if 'gmail_service' in session:
        return session['gmail_service']

    access_token = request.cookies.get("access_token")
    expires_at = request.cookies.get("expires_at")
    refresh_token = request.cookies.get("refresh_token")

    # If no token, force login
    if not access_token or not expires_at:
        return None

    # Convert expiration time to float for comparison
    expires_at = float(expires_at)

    # If token is expired, refresh it
    if time.time() > expires_at:
        if not refresh_token:
            return None  # No refresh token, user must log in again

        # Request a new access token using the refresh token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": os.getenv("CLIENT_ID"),
            "client_secret": os.getenv("CLIENT_SECRET"),
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        response = requests.post(token_url, data=data).json()

        if "access_token" not in response:
            return None  # Failed to refresh token, force re-login

        # Update tokens
        new_access_token = response["access_token"]
        new_expires_at = time.time() + response["expires_in"]

        # Save updated token to cookies
        response = make_response(redirect(url_for("routes.get_emails")))
        response.set_cookie("access_token", new_access_token, httponly=True, secure=True)
        response.set_cookie("expires_at", str(new_expires_at), httponly=True, secure=True)

        access_token = new_access_token

    # Initialize Gmail API client with valid token
    credentials = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=credentials)

    # Store the Gmail service in session
    session['gmail_service'] = service

    return service
