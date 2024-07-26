import hashlib
import base64

from cs50 import SQL
from flask import Blueprint, render_template, session
from cryptography.fernet import Fernet

from helpers import login_required

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

# Number of iterations for encryption
iterations = 100000

passwords_vault_bp = Blueprint('passwords_vault_bp', __name__)

@passwords_vault_bp.route("/passwords-vault")
@login_required
def passwords_vault():
    """Vault with the passwords"""

    # Get the user's id
    user_id = session["user_id"]

    # Get user's new master password hash from database
    new_masterpassword_hash = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
    new_masterpassword = new_masterpassword_hash[0]['hash']

    # Get user's data from database
    passwords = db.execute("SELECT id, website, username, password, salt FROM passwords WHERE user_id = ?", user_id)

    # Decrypt the passwords using the new master password
    for password in passwords:
        encrypted_password = password["password"]
        salt = password["salt"]
        key = hashlib.pbkdf2_hmac('sha256', new_masterpassword.encode('utf-8'), salt, iterations)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        password_bytes = fernet.decrypt(encrypted_password)
        password_str = password_bytes.decode('utf-8')
        password["password"] = password_str

    return render_template("passwords-vault.html", passwords=passwords)