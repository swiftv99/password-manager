from cs50 import SQL
from flask import Blueprint, flash, redirect, session

from helpers import login_required

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

delete_password_bp = Blueprint('delete_password_bp', __name__)

@delete_password_bp.route("/delete-password/<int:password_id>", methods=["POST"])
@login_required
def delete_password(password_id):
    """Delete a password from the database"""

    # Get user's id
    user_id = session["user_id"]

    # Delete the password with the given id and user_id from the database
    db.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", password_id, user_id)

    flash("Password deleted!")
    return redirect("/passwords-vault")