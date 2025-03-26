import os
import json
import time
import requests
from google.oauth2.credentials import Credentials
from flask import redirect, url_for, request, make_response, g
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

def init_Gmail(access_token):
    if not access_token:
        return f"access token is nowhere to be seen when initializing Gmail api" # No access token, force login

    # Initialize Gmail API client with the access token
    credentials = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=credentials)

    return service

def token_and_Gmail_validation():
    access_token = request.cookies.get("access_token")
    expires_at = request.cookies.get("expires_at")
    refresh_token = request.cookies.get("refresh_token")

    if not access_token or not expires_at:
        print("error: access token or expiration is not properly assigned")
        return redirect(url_for("routes.index"))
    
    expires_at = float(expires_at)
    if time.time() > expires_at:
        if not refresh_token:
            print("error: refresh token is not properly assigned")
            return redirect(url_for("routes.index"))
        refresh_Gmail_token(refresh_token)

    service = init_Gmail(access_token)

    return service

def refresh_Gmail_token(refresh_token):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": os.getenv("CLIENT_ID"),
        "client_secret": os.getenv("CLIENT_SECRET"),
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    response = requests.post(token_url, data=data).json()

    if "access_token" not in response:
        return None  # Return None to indicate failure

    # Get new tokens
    new_access_token = response["access_token"]
    new_expires_at = time.time() + response["expires_in"]

    # Update the cookies with the new tokens
    response = make_response()
    response.set_cookie("access_token", new_access_token, httponly=True, samesite="Strict", secure=True)
    response.set_cookie("expires_at", str(new_expires_at), httponly=True, samesite="Strict", secure=True)

    return response
