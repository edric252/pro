# AccessHub

AccessHub is a small role-based access management app built with Flask and SQLite. It has user registration and login, admin and regular-user roles, account suspension, login history, and an audit trail.

## Run on Windows

You need Python 3.10 or newer.

1. Double-click `run.bat` to start the app. Keep the server window open.
2. Open <http://127.0.0.1:5000> in your browser.
3. Register an account, or create an administrator from a second terminal as shown below.

To install the app manually:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
.venv\Scripts\python.exe -m flask --app app create-admin
.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 5000
```

The admin command prompts for a username and password. New public registrations always receive the regular-user role; administrators can change roles in the admin console.

## Features

- Werkzeug password hashing
- Server-side role checks for administrator pages and actions
- CSRF tokens on form submissions
- Login history for successful and failed attempts
- Audit entries for account and role changes
- Account suspension and reactivation
- SQLite parameterized queries

## Security notes

Passwords are stored as hashes. Sessions use HTTP-only and SameSite cookies. Set a strong `SECRET_KEY` and `COOKIE_SECURE=1` when serving over HTTPS. The Flask development server is for local development only; use a production WSGI server behind HTTPS for deployment.

The local SQLite database is `access.db`. It contains user and audit data and is excluded from Git. Create a new administrator with `flask --app app create-admin` after cloning; do not publish passwords or the local database.
