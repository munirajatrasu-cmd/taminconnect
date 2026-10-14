
import os
import hmac
from functools import wraps
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/", methods=["GET", "POST"])
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_username = os.environ.get("DIALER_USERNAME", "")
        valid_password = os.environ.get("DIALER_PASSWORD", "")

        if (
            valid_username
            and valid_password
            and hmac.compare_digest(username, valid_username)
            and hmac.compare_digest(password, valid_password)
        ):
            session.clear()
            session["logged_in"] = True
            session.permanent = True
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
