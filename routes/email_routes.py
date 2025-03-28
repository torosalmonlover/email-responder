import os
import json
import base64
from flask import Blueprint, redirect, url_for, request, make_response, current_app, g, render_template
from authentication import token_and_Gmail_validation
from app import cache

routes = Blueprint("routes", __name__)

@routes.route("/")
def index():
    # access_token = request.cookies.get("access_token")

    # if access_token:
    #     return redirect(url_for("routes.profile"))
    
    return "Welcome to OAuth Email App! <a href='/login'>Login with Google</a>"

@routes.route("/login")
def login():
    google = current_app.config["GOOGLE_OAUTH"]
    redirect_uri = url_for("routes.callback", _external=True)
    return google.authorize_redirect(redirect_uri, access_type="offline", prompt='consent')

@routes.route("/auth/callback")
def callback():
    google = current_app.config["GOOGLE_OAUTH"]
    token = google.authorize_access_token()

    print(f"tokens: {token}")

    # Extract only necessary token data
    access_token = token.get("access_token")
    expires_at = token.get("expires_at", 0)
    refresh_token = token.get("refresh_token")

    print(f"access_token: {access_token}")
    print(f"expires_at: {expires_at}")
    print(f"refresh_token: {refresh_token}")

    # Store tokens in cookies
    response = make_response(redirect(url_for("routes.profile")))
    response.set_cookie("access_token", access_token, httponly=True, secure=True) # reduced samesite="Strict"
    response.set_cookie("expires_at", str(expires_at), httponly=True, secure=True)


    # Store refresh token only if it's new (some OAuth providers don't return it every time)
    if refresh_token:
        response.set_cookie("refresh_token", refresh_token, httponly=True, secure=True)

    return response

@routes.route("/profile")
def profile():
    service = token_and_Gmail_validation()
    
    user_info = service.users().getProfile(userId="me").execute()
    return f"Logged in as {user_info['emailAddress']}. <a href='/logout'>Logout</a>"

@routes.route("/logout")
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("access_token")
    response.delete_cookie("expires_at")
    response.delete_cookie("refresh_token")
    return response

@routes.route("/emails")
@cache.cached(timeout=360000)
def list_emails():
    service = token_and_Gmail_validation()

    quota_used = 0
    
    try:
        results = service.users().messages().list(userId="me", labelIds=["INBOX"], q="is:unread").execute()
        quota_used += 5  # List request quota
        email_ids = results.get("messages", [])

        if not email_ids:
            return "No emails found."

        email_list = []

        for message in email_ids:
            message_details = service.users().messages().get(userId="me", id=message['id'], format="metadata", metadataHeaders=["Subject", "From"]).execute()
            quota_used += 5 

            headers = message_details['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
            sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown Sender")

            email_list.append({
                "subject": subject,
                "sender": sender,
                "id": message['id']
            })

        print(f"Total Quota Used: {quota_used} units")

        return render_template("email_list.html", emails=email_list)

    except Exception as e:
        return f"Error fetching emails: {str(e)}"

@routes.route("/emails/<email_id>")
@cache.cached()
def view_email(email_id):
    service = token_and_Gmail_validation()

    try:
        # Fetch the email details from Gmail API
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
                    body_data = part["body"].get("data", "")
                    body = base64.urlsafe_b64decode(body_data).decode("utf-8") if body_data else "No Content Available"
                    break
                elif part["mimeType"] == "text/html":
                    body_data = part["body"].get("data", "")
                    body = base64.urlsafe_b64decode(body_data).decode("utf-8") if body_data else "No Content Available"
                    break

        # Render the email details in the HTML template, sending the body as HTML
        return render_template("view_email.html", subject=subject, body=body)
    
    except Exception as e:
        return f"Error fetching email: {str(e)}"