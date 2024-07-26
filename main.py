from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session

from helpers import login_required, usd

# Import the blueprints
from app import add_password, change_password, delete_password, edit_password, login, logout, passwords_vault, register


# Configure application
app = Flask(__name__)

# Register the blueprint
app.register_blueprint(add_password.add_password_bp)
app.register_blueprint(change_password.change_password_bp)
app.register_blueprint(delete_password.delete_password_bp)
app.register_blueprint(edit_password.edit_password_bp)
app.register_blueprint(login.login_bp)
app.register_blueprint(logout.logout_bp)
app.register_blueprint(passwords_vault.passwords_vault_bp)
app.register_blueprint(register.register_bp)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

# Number of iterations for encryption
iterations = 100000


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Homepage"""

    # Get user's id
    user_id = session["user_id"]

    return render_template("index.html")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)