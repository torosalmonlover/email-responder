from email.mime.text import MIMEText
import os
import json
import base64
import time
from flask import Blueprint, jsonify, redirect, url_for, request, make_response, current_app, g, render_template
from authentication import token_and_Gmail_validation
from app import cache

routes = Blueprint("routes", __name__)

@routes.route("/")
def index():
    try:
        service = token_and_Gmail_validation()
        if not service:
            raise Exception("Token validation failed")
        return redirect(url_for("routes.profile"))
    except Exception as e:
        print(f"Token validation error: {e}")
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

    # Extract only necessary token data
    access_token = token.get("access_token")
    expires_at = token.get("expires_at")
    refresh_token = token.get("refresh_token")
    refresh_token_expires_in = token.get("refresh_token_expires_in")
    refresh_token_expires_in += time.time()

    # Store tokens in cookies
    response = make_response(redirect(url_for("routes.profile")))
    response.set_cookie("access_token", access_token, httponly=True, secure=True) # reduced samesite="Strict"
    response.set_cookie("expires_at", str(expires_at), httponly=True, secure=True)

    # Store refresh token only if it's new (some OAuth providers don't return it every time)
    if refresh_token:
        response.set_cookie("refresh_token", refresh_token, httponly=True, secure=True)
        response.set_cookie("refresh_token_expires_in", str(refresh_token_expires_in), httponly=True, secure=True)

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
@cache.cached(timeout=360000) # reducing token usage for testing
def list_emails():
    service = token_and_Gmail_validation()

    quota_used = 0

    query = {
    "userId": "me",
    "labelIds": ["INBOX"],
    "q": "is:unread",
    "maxResults":"50"
    }
    
    results = service.users().messages().list(**query).execute()
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
    
@routes.route("/create")
def show_website():
    return render_template("create_email.html")
    
@routes.route("/create_email", methods=["POST"])
def create_message():
    data = request.get_json()
    to = data.get("to")
    sender = data.get("from")
    subject = data.get("subject")
    message_text = data.get("message_text")
    # add function here for ai editing and advice
    finalize_message(to, sender, subject, message_text)
    return jsonify({"message": "Email created successfully!"})

def finalize_message(to, sender, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_string().encode("utf-8"))
    message = {'raw': raw_message.decode("utf-8")}
    
    service = token_and_Gmail_validation()

    try:
        message = service.users().messages().send(userId="me", body=message).execute()
        print('Message Id: %s' % message['id'])
    except Exception as e:
        print('An error occurred: %s' % e)
        return None