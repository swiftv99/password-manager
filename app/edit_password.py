import os
import hashlib
import base64

from cs50 import SQL
from flask import Blueprint, flash, redirect, request, session
from cryptography.fernet import Fernet

from helpers import login_required

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

# Number of iterations for encryption
iterations = 100000

edit_password_bp = Blueprint('edit_password_bp', __name__)

@edit_password_bp.route("/edit-password/<int:password_id>", methods=["POST"])
@login_required
def edit_password(password_id):
    """Edit password from the database"""

    # Get user's id
    user_id = session["user_id"]

    # Delete the password with the given id and user_id from the database
    newwebsite = request.form.get("new_website")
    newusername = request.form.get("new_username")
    newpassword = request.form.get("new_password")

    # Get the password hash from the database
    password_hash_dict = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
    password_hash = password_hash_dict[0]['hash']

    salt = os.urandom(16) # Generate a random salt value

    # Derive the encryption key from the hashed master password and salt
    key = hashlib.pbkdf2_hmac('sha256', password_hash.encode('utf-8'), salt, iterations)
    fernet = Fernet(base64.urlsafe_b64encode(key))

    # Encrypt the password using the Fernet object
    password_bytes = newpassword.encode('utf-8')
    encrypted_password = fernet.encrypt(password_bytes)

    db.execute("UPDATE passwords SET website = ?, username = ?, password = ?, salt = ? WHERE id = ? AND user_id = ?", newwebsite, newusername, encrypted_password, salt, password_id, user_id)

    flash("Password updated!")
    return redirect("/passwords-vault")