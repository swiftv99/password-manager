import re

from cs50 import SQL
from flask import Blueprint, redirect, render_template, request, session
from werkzeug.security import generate_password_hash

from helpers import apology

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

register_bp = Blueprint('register_bp', __name__)

@register_bp.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 400)

        # Ensure password meets minimum requirements
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\x21-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E])[\x21-\x7E]{8,}$'
        if not re.match(pattern, request.form.get("password")):
            return apology("Password must be at least 8 characters long, one uppercase letter, one lowercase letter, one digit, and one symbol", 400)

        # Save username and password hash in variables
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)

        # Ensure username doesn't already exists
        if len(rows) != 0:
            return apology("username is already taken", 400)

        # Insert data into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        # Redirect user to login page
        return redirect("/login")
    else:
        return render_template("register.html")