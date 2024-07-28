from cs50 import SQL

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///passwords.db")

try:
    db.execute("DELETE FROM users WHERE id>0")
    db.execute("DELETE FROM passwords WHERE id>0")
    users = db.execute("SELECT * FROM users")
    passwords = db.execute("SELECT * FROM passwords")
    print(f"Users: {users}", f"Passwords: {passwords}")
    print("Users and Passwords are deleted successfully")
except:
    print("Couldn't clear database information")