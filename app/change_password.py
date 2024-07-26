import os
import hashlib
import base64
import re

from cs50 import SQL
from flask import Blueprint, flash, redirect, render_template, request, session
# from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet

from helpers import apology, login_required

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

# Number of iterations for encryption
iterations = 100000

change_password_bp = Blueprint('change_password_bp', __name__)

@change_password_bp.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password of user"""

    if request.method == "POST":

        # Ensure all fields were submitted
        if not request.form.get("old-password") or not request.form.get("new-password") or not request.form.get("confirmation"):
            return apology("Please fill all fields.", 403)

        # Query database for user
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("old-password")):
            return apology("Incorrect password.", 403)

        # Ensure new password matches confirmation
        if request.form.get("new-password") != request.form.get("confirmation"):
            return apology("Passwords must match.", 403)

        # Ensure password meets minimum requirements
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E])[\x21-\x7E]{8,}$'
        if not re.match(pattern, request.form.get("new-password")):
            return apology("Password must be at least 8 characters long, one uppercase letter, one lowercase letter, one digit, and one symbol", 400)

        # Get user's data from database
        user_id = session["user_id"]
        passwords = db.execute("SELECT id, website, username, password, salt FROM passwords WHERE user_id = ?", user_id)

        # Decrypt the passwords using the old master password and re-encrypt them with the new master password
        old_masterpassword1 = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        old_masterpassword = old_masterpassword1[0]['hash']

        new_masterpassword_hash = generate_password_hash(request.form.get("new-password"))
        new_masterpassword = new_masterpassword_hash

        for password in passwords:
            encrypted_password = password["password"]
            salt = password["salt"]
            old_key = hashlib.pbkdf2_hmac('sha256', old_masterpassword.encode('utf-8'), salt, iterations)
            fernet = Fernet(base64.urlsafe_b64encode(old_key))
            password_bytes = fernet.decrypt(encrypted_password)
            password_str = password_bytes.decode('utf-8')
            password["password"] = password_str
            newsalt = os.urandom(16) # Generate a random salt value
            new_key = hashlib.pbkdf2_hmac('sha256', new_masterpassword.encode('utf-8'), newsalt, iterations)
            newfernet = Fernet(base64.urlsafe_b64encode(new_key))
            password_bytes2 = password["password"].encode('utf-8')
            encrypted_password2 = newfernet.encrypt(password_bytes2)
             # Update the encrypted password and salt in the database
            db.execute("UPDATE passwords SET password = ?, salt = ? WHERE id = ?", encrypted_password2, newsalt, password["id"])



        # Update password hash in database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_masterpassword_hash, user_id)

        # Redirect to home page
        flash("Password changed!")
        return redirect("/")

    else:
        return render_template("password.html")