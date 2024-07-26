from flask import Blueprint, redirect, session

logout_bp = Blueprint('logout_bp', __name__)

@logout_bp.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")