from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_session import Session
from datetime import datetime

from support import login_required

app = Flask(__name__)

db = SQL("sqlite:///tasks.db")

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route("/")
def index():
    try:
        userID = session["user_id"]
        TASKS = db.execute("SELECT * FROM tasks WHERE user_id = ? ORDER BY deadline;", userID)
        return render_template("index.html", tasks=TASKS)
    except KeyError:
        return redirect("/login")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("error.html", message="Missing username and/or password")

        accounts = db.execute("SELECT * FROM users WHERE username = ?", username)
        if not accounts:
            return render_template("error.html", message="Invalid username")
        if not check_password_hash(accounts[0]["password"], password):
            return render_template("error.html", message="Invalid username and/or password")

        # Log user in
        session["user_id"] = accounts[0]["userID"]

        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()

    return redirect("/login")


@app.route("/register", methods=["POST", "GET"])
def register():

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check if the username is already used
        accounts = db.execute("SELECT * FROM users WHERE username = ?;", username)
        if accounts:
            return render_template("error.html", message="Username already taken")

        # Check if no data is missing
        if not username or not password or not confirmation:
            return render_template("error.html", message="Missing username and/or password")

        if password != confirmation:
            return render_template("error.html", message="Passwords do not match")

        db.execute("INSERT INTO users (username, password) VALUES(?, ?);", username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/addTask", methods=["POST", "GET"])
@login_required
def addTask():
    if request.method == "POST":
        description = request.form.get("description")
        deadline = request.form.get("date")

        # Check if all necessary forms have been filled

        if not description or not deadline:
            return render_template("error.html", message="data missing")

        # Check if date is correct

        if datetime.strptime(deadline, '%Y-%m-%d') < datetime.today():
            return render_template("error.html", message="Incorrect date")

        # Add task to database

        userID = session["user_id"]
        db.execute("INSERT INTO tasks (description, deadline, user_id) VALUES(?, ?, ?);", description, deadline, userID)

        return redirect("/")
    else:
        return render_template("addTask.html")


@app.route("/deleteTask", methods=["POST"])
@login_required
def deleteTask():
    id = request.form.get("id")
    if id:
        db.execute("DELETE FROM tasks WHERE taksID = ?;", id)
    return redirect("/")


if __name__ == '__main__':
    app.run(host='localhost', port=5000)
