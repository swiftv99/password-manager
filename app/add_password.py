import os
import hashlib
import base64
from cs50 import SQL
from flask import Blueprint, flash, redirect, render_template, request, session
from cryptography.fernet import Fernet
from helpers import apology, login_required

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

# Number of iterations for encryption
iterations = 100000

add_password_bp = Blueprint('add_password_bp', __name__)

@add_password_bp.route("/add-password", methods=["GET", "POST"])
@login_required
def add_password():
    """Add password to the database"""

    if request.method == "POST":

        user_id = session["user_id"]
        website = request.form.get("website")
        username = request.form.get("username")
        password = request.form.get("password")
        salt = os.urandom(16)  # Generate a random salt value

        # check if website, username and password are submitted
        if not website:
            return apology("Must provide website", 400)
        elif not username:
            return apology("Must provide username", 400)
        elif not password:
            return apology("Must provide password", 400)

        # Get the password hash from the database
        password_hash_dict = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        password_hash = password_hash_dict[0]['hash']

        # Derive the encryption key from the hashed master password and salt
        key = hashlib.pbkdf2_hmac('sha256', password_hash.encode('utf-8'), salt, iterations)
        fernet = Fernet(base64.urlsafe_b64encode(key))

        # Encrypt the password using the Fernet object
        password_bytes = password.encode('utf-8')
        encrypted_password = fernet.encrypt(password_bytes)

        # Add data the user provided to the database
        db.execute("INSERT INTO passwords (website, username, password, salt, user_id) VALUES (?, ?, ?, ?, ?)",
                   website, username, encrypted_password, salt, user_id)

        # redirect to the home page
        flash("Password Added!")
        return redirect("/")

    # if request method is GET, show the add-password page
    else:
        return render_template("add-password.html")
