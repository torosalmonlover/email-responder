import os
import json
from flask import Blueprint, redirect, url_for, request, make_response, current_app
from authentication import init_Gmail
from flask_caching import Cache
from app import cache

routes = Blueprint("routes", __name__)

COOKIE_NAME = "oauth_token"

@routes.route("/")
def index():
    try:
        if request.cookies.get(COOKIE_NAME):
            return redirect(url_for("routes.profile")) 
    except Exception as e:
        print(f"Error checking cookie: {e}")

    return "Welcome to OAuth Email App! <a href='/login'>Login with Google</a>"

@routes.route("/login")
def login():
    google = current_app.config["GOOGLE_OAUTH"]
    return google.authorize_redirect(url_for("routes.callback", _external=True))

@routes.route("/auth/callback")
def callback():
    google = current_app.config["GOOGLE_OAUTH"]
    token = google.authorize_access_token()

    # Extract only necessary token data
    access_token = token.get("access_token")
    expires_at = token.get("expires_at", 0)
    refresh_token = token.get("refresh_token")

    # Store tokens in cookies
    response = make_response(redirect(url_for("routes.profile")))
    response.set_cookie("access_token", access_token, httponly=True, secure=True)
    response.set_cookie("expires_at", str(expires_at), httponly=True, secure=True)

    # Store refresh token only if it's new (some OAuth providers don't return it every time)
    if refresh_token:
        response.set_cookie("refresh_token", refresh_token, httponly=True, secure=True)

    return response

@routes.route("/profile")
def profile():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return redirect(url_for("routes.login"))
    
    user = json.loads(token)
    return f"Logged in as {user['userinfo']['email']}, printing user info here {user}. <a href='/logout'>Logout</a>"

@routes.route("/logout")
def logout():
    response = make_response(redirect("https://accounts.google.com/logout"))
    response.delete_cookie("access_token")
    response.delete_cookie("expires_at")
    response.delete_cookie("refresh_token")
    return response

@routes.route("/emails")
@cache.cached(timeout=600)
def get_emails():
    service = init_Gmail(COOKIE_NAME)
    if not service:
        return redirect(url_for("routes.login"))
    
    results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
    messages = results.get("messages", [])

    email_numbers = (
    "You have no unread emails!" if not messages 
    else f"You have {len(messages)} unread emails!" if len(messages) < 100 
    else f"You have {len(messages)} or more unread emails!"
    )

    email_list = "<h2>Unread Emails</h2><ul>"
    for msg in messages:
        email_list += f'<li><a href="/emails/{msg["id"]}">View Email {msg["id"]}</a></li>'
    email_list += "</ul>"

    return email_list

@routes.route("/emails/<email_id>")
def view_email(email_id):
    service = init_Gmail(COOKIE_NAME)
    if not service:
        return redirect(url_for("routes.login"))

    try:
        email = service.users().messages().get(userId="me", id=email_id, format="full").execute()
        payload = email.get("payload", {})
        headers = payload.get("headers", [])

        # Get email subject
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")

        # Get email body (handling text/plain and text/html)
        body = "No Content Available"
        if "parts" in payload:
            for part in payload["parts"]:
                if part["mimeType"] == "text/plain":
                    body = part["body"].get("data", "").replace("\n", "<br>")
                    break
                elif part["mimeType"] == "text/html":
                    body = part["body"].get("data", "")
                    break

        return f"<h2>{subject}</h2><p>{body}</p><a href='/emails'>Back to Emails</a>"
    
    except Exception as e:
        return f"Error fetching email: {str(e)}"