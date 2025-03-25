import os
from flask import Flask
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from authentication import init_Oauth
from flask_caching import Cache

load_dotenv()

app = Flask(__name__)

# Configure Flask secret key for security
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
app.config["SESSION_TYPE"] = "cookies"
app.config["SESSION_PERMANENT"] = False
app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = 600

# Initialize OAuth
cache = Cache(app)
oauth = OAuth(app)
google = init_Oauth(oauth)

# Store Google OAuth client in app config
app.config["GOOGLE_OAUTH"] = google

# Register routes
from routes.email_routes import routes
app.register_blueprint(routes)

if __name__ == "__main__":
    app.run(debug=True)
