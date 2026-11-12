import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("DATABASE", "access.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)


def database():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_database(error=None):
    db = g.pop("db", None)
    if db:
        db.close()


def initialize_database():
    db = database()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
            suspended INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY, username TEXT NOT NULL, user_id INTEGER,
            success INTEGER NOT NULL, happened_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
            target TEXT NOT NULL, happened_at TEXT NOT NULL
        );
    """)
    db.commit()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def audit(action, target):
    actor = g.user["username"] if getattr(g, "user", None) else "system"
    database().execute(
        "INSERT INTO audit_logs (actor, action, target, happened_at) VALUES (?, ?, ?, ?)",
        (actor, action, target, now()),
    )
    database().commit()


@app.before_request
def load_user_and_check_csrf():
    initialize_database()
    g.user = None
    if session.get("user_id"):
        g.user = database().execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not g.user or g.user["suspended"]:
            session.clear()
            g.user = None
            flash("Your account is unavailable. Please contact an administrator.", "error")
            if request.method == "POST":
                return redirect(url_for("login"))
    if request.method == "POST":
        token = session.get("csrf_token")
        if not token or not secrets.compare_digest(token, request.form.get("csrf_token", "")):
            abort(400, "Invalid form token. Please refresh and try again.")


@app.context_processor
def template_values():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["csrf_token"]}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 40:
            flash("Choose a username between 3 and 40 characters.", "error")
        elif len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
        else:
            try:
                db = database()
                db.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), now()),
                )
                db.commit()
                audit("register", username)
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        user = database().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        valid = user and check_password_hash(user["password_hash"], request.form.get("password", ""))
        database().execute(
            "INSERT INTO login_history (username, user_id, success, happened_at) VALUES (?, ?, ?, ?)",
            (username, user["id"] if user else None, int(bool(valid)), now()),
        )
        database().commit()
        if valid and not user["suspended"]:
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_hex(32)
            g.user = user
            audit("login", username)
            return redirect(url_for("dashboard"))
        if valid and user["suspended"]:
            audit("blocked_login_suspended", username)
        flash("Sign in failed. Check your details or contact an administrator.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", g.user["username"])
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    history = database().execute(
        "SELECT success, happened_at FROM login_history WHERE user_id = ? ORDER BY id DESC LIMIT 8",
        (g.user["id"],),
    ).fetchall()
    return render_template("dashboard.html", history=history)


@app.route("/admin")
@admin_required
def admin():
    db = database()
    users = db.execute("SELECT id, username, role, suspended, created_at FROM users ORDER BY id").fetchall()
    logins = db.execute("SELECT username, success, happened_at FROM login_history ORDER BY id DESC LIMIT 30").fetchall()
    logs = db.execute("SELECT actor, action, target, happened_at FROM audit_logs ORDER BY id DESC LIMIT 40").fetchall()
    return render_template("admin.html", users=users, logins=logins, logs=logs)


@app.route("/admin/user/<int:user_id>", methods=["POST"])
@admin_required
def update_user(user_id):
    db = database()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        abort(404)
    action = request.form.get("action")
    if action == "role" and request.form.get("role") in ("admin", "user"):
        if target["id"] == g.user["id"] and request.form["role"] != "admin":
            flash("You cannot remove your own admin role.", "error")
        else:
            db.execute("UPDATE users SET role = ? WHERE id = ?", (request.form["role"], user_id))
            db.commit()
            audit("role_changed_to_" + request.form["role"], target["username"])
    elif action == "suspension":
        suspended = 0 if target["suspended"] else 1
        if target["id"] == g.user["id"] and suspended:
            flash("You cannot suspend your own account.", "error")
        else:
            db.execute("UPDATE users SET suspended = ? WHERE id = ?", (suspended, user_id))
            db.commit()
            audit("account_suspended" if suspended else "account_reactivated", target["username"])
    return redirect(url_for("admin"))


@app.cli.command("init-db")
def init_db_command():
    initialize_database()
    print("Database initialized.")


@app.cli.command("create-admin")
def create_admin_command():
    """Create the first admin without hard-coded credentials."""
    import getpass
    initialize_database()
    username = input("Admin username: ").strip().lower()
    password = getpass.getpass("Admin password (10+ characters): ")
    if len(username) < 3 or len(password) < 10:
        raise SystemExit("Username must be 3+ characters and password 10+ characters.")
    try:
        db = database()
        db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
            (username, generate_password_hash(password), now()),
        )
        db.commit()
        print("Admin account created.")
    except sqlite3.IntegrityError:
        raise SystemExit("That username already exists.")


if __name__ == "__main__":
    initialize_database()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
