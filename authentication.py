import os
import json
import time
import requests
from google.oauth2.credentials import Credentials
from flask import redirect, url_for, request, make_response, g
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
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
        client_kwargs={"scope": "openid email profile https://mail.google.com/"},
    )

    return google

def init_Gmail(access_token):
    if not access_token:
        return f"access token is nowhere to be seen when initializing Gmail api"

    # Initialize Gmail API client with the access token
    credentials = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=credentials)

    return service

def token_and_Gmail_validation():
    access_token = request.cookies.get("access_token")
    expires_at = request.cookies.get("expires_at")
    refresh_token = request.cookies.get("refresh_token")
    refresh_token_expires_in = request.cookies.get("refresh_token_expires_in")

    if not access_token or not expires_at:
        print("error: access token or expiration is not properly assigned")
        return redirect(url_for("routes.login"))
    
    expires_at = float(expires_at)
    refresh_token_expires_in = float(refresh_token_expires_in)
    if time.time() > expires_at:
        if not refresh_token or time.time() > refresh_token_expires_in:
            return redirect(url_for("routes.login"))
        refresh_Gmail_token(access_token, refresh_token)

    service = init_Gmail(access_token)

    return service

def refresh_Gmail_token(access_token, refresh_token):
    creds = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        client_id=os.getenv("CLIENT_ID"),
        client_secret=os.getenv("CLIENT_SECRET"),
        token_uri="https://oauth2.googleapis.com/token",
    )
    creds.refresh(Request())

    new_access_token = creds.token
    new_expires_at = creds.expiry

    print(f"New Access Token: {new_access_token}")
    print(f"New Expires At: {new_expires_at}")

    response = make_response()
    response.set_cookie("access_token", new_access_token, httponly=True, secure=True)
    response.set_cookie("expires_at", str(new_expires_at), httponly=True, secure=True)

    return response
