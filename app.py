from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from datetime import datetime, timedelta, timezone
import hashlib
import os
import secrets

from flask import Flask, jsonify, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

IS_PRODUCTION = os.getenv("FLASK_ENV", "").lower() == "production"
SECRET_KEY = os.getenv("SECRET_KEY")
if IS_PRODUCTION and not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set when FLASK_ENV=production.")

app.config.update(
    SECRET_KEY=SECRET_KEY or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///bank.db").replace(
        "postgres://", "postgresql://", 1
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=1800,
)

db = SQLAlchemy(app)

# "Remember this device" cookie for staff. Only a random token is ever
# stored client-side; the server only ever persists its hash.
STAFF_REMEMBER_COOKIE = "bbk_staff_remember"
STAFF_REMEMBER_DAYS = 30


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    phone_number = db.Column(db.String(30), nullable=False)
    account_number = db.Column(db.Integer, unique=True, nullable=False, index=True)
    pin_hash = db.Column(db.String(255), nullable=False)
    balance_cents = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    transactions = db.relationship(
        "Transaction", backref="account", cascade="all, delete-orphan", lazy=True
    )


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey("account.id"), nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False)
    amount_cents = db.Column(db.Integer, nullable=False)
    balance_after_cents = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class SystemMeta(db.Model):
    """Single-row table recording when this database was first created.

    Created once, the first time the database is initialized, and never
    overwritten afterwards -- so app restarts do not reset it.
    """

    id = db.Column(db.Integer, primary_key=True)
    database_started_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )


class StaffDeviceToken(db.Model):
    """A hashed, single-use-per-device "remember me" token for staff.

    Only the SHA-256 hash of the random token is stored here; the raw
    token itself lives only in an HttpOnly cookie on the staff member's
    browser and is never written to the database, logs, or any API
    response.
    """

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)


def money_to_cents(value):
    try:
        if value is None or str(value).strip() == "":
            raise ValueError
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if not amount.is_finite() or amount < 0:
            raise ValueError
        cents = int(amount * 100)
        if cents > 100_000_000_00:  # $100 million demo safety limit
            raise ValueError
        return cents
    except (ValueError, InvalidOperation, TypeError):
        raise ValueError("Invalid amount")


def account_dict(account):
    return {
        "name": account.name,
        "phone_number": account.phone_number,
        "acno": account.account_number,
        "amount": account.balance_cents / 100,
        "createdAt": account.created_at.isoformat(),
    }


def tx_dict(tx):
    return {
        "date": tx.created_at.isoformat(),
        "desc": tx.description,
        "delta": tx.amount_cents / 100,
        "balanceAfter": tx.balance_after_cents / 100,
    }


def find_account(acno):
    try:
        number = int(str(acno).strip())
    except (TypeError, ValueError):
        return None
    return db.session.execute(
        db.select(Account).filter_by(account_number=number)
    ).scalar_one_or_none()


def generate_account_number():
    for _ in range(100):
        number = secrets.randbelow(900_000) + 100_000
        if not db.session.execute(
            db.select(Account).filter_by(account_number=number)
        ).scalar_one_or_none():
            return number
    raise RuntimeError("Could not generate a unique account number.")


def get_current_account():
    acno = session.get("account_number")
    return find_account(acno) if acno else None


def to_iso_utc(dt):
    """Return an ISO-8601 timestamp, assuming naive datetimes are UTC.

    SQLite drops timezone info on round-trip, so datetimes read back from
    the database are naive even though they were written as UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def get_system_meta():
    """Fetch (or, on first run only, create) the single SystemMeta row."""
    meta = db.session.execute(db.select(SystemMeta)).scalars().first()
    if not meta:
        meta = SystemMeta(database_started_at=datetime.now(timezone.utc))
        db.session.add(meta)
        db.session.commit()
    return meta


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_staff_remember_cookie(response):
    """Create a new staff device token and attach it to the response."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=STAFF_REMEMBER_DAYS)
    db.session.add(StaffDeviceToken(token_hash=hash_token(token), expires_at=expires_at))
    db.session.commit()
    response.set_cookie(
        STAFF_REMEMBER_COOKIE,
        token,
        max_age=STAFF_REMEMBER_DAYS * 86400,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite="Lax",
        path="/",
    )


def find_valid_staff_token(token):
    """Look up a staff device token by its hash, pruning it if expired."""
    if not token:
        return None
    row = db.session.execute(
        db.select(StaffDeviceToken).filter_by(token_hash=hash_token(token))
    ).scalar_one_or_none()
    if not row:
        return None
    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        db.session.delete(row)
        db.session.commit()
        return None
    return row


def revoke_staff_token(token):
    if not token:
        return
    row = db.session.execute(
        db.select(StaffDeviceToken).filter_by(token_hash=hash_token(token))
    ).scalar_one_or_none()
    if row:
        db.session.delete(row)
        db.session.commit()


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/accounts")
def create_account():
    auth_error = staff_required()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()
    phone = str(data.get("phone", "")).strip()

    if not 2 <= len(name) <= 120:
        return jsonify(success=False, message="Enter a valid customer name."), 400
    if not phone or len(phone) > 30:
        return jsonify(success=False, message="Enter a valid phone number."), 400

    try:
        cents = money_to_cents(data.get("amount", 0))
    except ValueError:
        return jsonify(success=False, message="Enter a valid opening deposit."), 400

    pin = secrets.randbelow(9000) + 1000
    account_number = generate_account_number()

    account = Account(
        name=name,
        phone_number=phone,
        account_number=account_number,
        pin_hash=generate_password_hash(str(pin)),
        balance_cents=cents,
    )

    try:
        db.session.add(account)
        db.session.flush()
        db.session.add(
            Transaction(
                account_id=account.id,
                description="Opening deposit",
                amount_cents=cents,
                balance_after_cents=cents,
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return jsonify(success=True, account_number=account_number, pin=pin)


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    account = find_account(data.get("acno"))
    pin = str(data.get("pin", "")).strip()

    if not account or not check_password_hash(account.pin_hash, pin):
        return jsonify(success=False, message="Invalid account number or PIN."), 401

    session.clear()
    session.permanent = True
    session["account_number"] = account.account_number
    return jsonify(success=True, account=account_dict(account))


@app.post("/api/staff/login")
def staff_login():
    data = request.get_json(silent=True) or {}
    supplied = str(data.get("pin", "")).strip()
    remember = bool(data.get("remember"))
    expected = os.getenv("STAFF_PIN")

    if not expected:
        return jsonify(success=False, message="Staff access is not configured."), 503
    if not secrets.compare_digest(supplied, expected):
        return jsonify(success=False, message="Invalid staff PIN."), 401

    session.clear()
    session.permanent = True
    session["staff_authenticated"] = True

    response = jsonify(success=True)
    if remember:
        issue_staff_remember_cookie(response)
    return response


@app.get("/api/staff/remember-status")
def staff_remember_status():
    """Check (without logging in) whether this browser has a remembered
    staff device, so the login screen can show a 'Remembered on this
    device' state before any credentials are exchanged."""
    token = request.cookies.get(STAFF_REMEMBER_COOKIE)
    row = find_valid_staff_token(token)
    response = jsonify(success=True, remembered=bool(row))
    if token and not row:
        response.delete_cookie(STAFF_REMEMBER_COOKIE, path="/")
    return response


@app.post("/api/staff/session/resume")
def staff_session_resume():
    """Establish a staff session from a valid remembered-device cookie."""
    token = request.cookies.get(STAFF_REMEMBER_COOKIE)
    row = find_valid_staff_token(token)
    if not row:
        response = jsonify(success=False, message="This device isn't remembered. Please sign in.")
        response.delete_cookie(STAFF_REMEMBER_COOKIE, path="/")
        return response, 401

    session.clear()
    session.permanent = True
    session["staff_authenticated"] = True
    return jsonify(success=True)


@app.post("/api/staff/forget-device")
def staff_forget_device():
    """Invalidate this browser's remembered staff device, if any."""
    token = request.cookies.get(STAFF_REMEMBER_COOKIE)
    revoke_staff_token(token)
    response = jsonify(success=True)
    response.delete_cookie(STAFF_REMEMBER_COOKIE, path="/")
    return response


def staff_required():
    if not session.get("staff_authenticated"):
        return jsonify(success=False, message="Staff authentication required."), 401
    return None


@app.post("/api/staff/lookup")
def staff_lookup():
    auth_error = staff_required()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    account = find_account(data.get("acno"))
    pin = str(data.get("pin", "")).strip()

    if not account or not check_password_hash(account.pin_hash, pin):
        return jsonify(success=False, message="Account not found or PIN incorrect."), 404

    return jsonify(success=True, account=account_dict(account))


@app.post("/api/staff/close")
def close_account():
    auth_error = staff_required()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    account = find_account(data.get("acno"))
    pin = str(data.get("pin", "")).strip()

    if not account or not check_password_hash(account.pin_hash, pin):
        return jsonify(success=False, message="Account not found or PIN incorrect."), 404

    db.session.delete(account)
    db.session.commit()
    return jsonify(success=True)


@app.get("/api/dashboard")
def dashboard():
    account = get_current_account()
    if not account:
        return jsonify(success=False, message="Not signed in."), 401

    transactions = db.session.execute(
        db.select(Transaction)
        .filter_by(account_id=account.id)
        .order_by(Transaction.created_at.asc(), Transaction.id.asc())
    ).scalars().all()

    return jsonify(
        success=True,
        account=account_dict(account),
        transactions=[tx_dict(tx) for tx in transactions],
    )


@app.post("/api/transaction")
def make_transaction():
    account = get_current_account()
    if not account:
        return jsonify(success=False, message="Not signed in."), 401

    data = request.get_json(silent=True) or {}
    kind = data.get("type")
    note = str(data.get("note", "")).strip()[:255]

    try:
        cents = money_to_cents(data.get("amount"))
    except ValueError:
        return jsonify(success=False, message="Enter a valid amount."), 400

    if cents <= 0:
        return jsonify(success=False, message="Amount must be greater than zero."), 400

    if kind == "deposit":
        delta = cents
        description = note or "Deposit"
    elif kind == "withdraw":
        if cents > account.balance_cents:
            return jsonify(success=False, message="Insufficient balance."), 400
        delta = -cents
        description = note or "Withdrawal"
    else:
        return jsonify(success=False, message="Invalid transaction type."), 400

    account.balance_cents += delta
    db.session.add(
        Transaction(
            account_id=account.id,
            description=description,
            amount_cents=delta,
            balance_after_cents=account.balance_cents,
        )
    )
    db.session.commit()

    return jsonify(success=True, balance=account.balance_cents / 100)


@app.get("/api/stats")
def stats():
    """Public, aggregate-only bank statistics for the landing page hero.

    Deliberately excludes any per-customer detail (names, phone numbers,
    individual balances or transaction amounts) -- only counts, sums and
    timestamps are returned.
    """
    meta = get_system_meta()

    rows = db.session.execute(
        db.select(Account.created_at, Account.balance_cents).order_by(Account.created_at.asc())
    ).all()

    total_accounts = len(rows)
    total_balance_cents = sum(row.balance_cents for row in rows)

    growth_map = {}
    for row in rows:
        day = row.created_at.date().isoformat()
        growth_map[day] = growth_map.get(day, 0) + 1
    account_growth = [{"date": day, "count": count} for day, count in sorted(growth_map.items())]

    total_transactions = db.session.execute(
        db.select(db.func.count(Transaction.id))
    ).scalar_one()

    today = datetime.now(timezone.utc).date().isoformat()

    latest_account_at = db.session.execute(
        db.select(Account.created_at).order_by(Account.created_at.desc()).limit(1)
    ).scalar_one_or_none()

    latest_transaction_at = db.session.execute(
        db.select(Transaction.created_at).order_by(Transaction.created_at.desc()).limit(1)
    ).scalar_one_or_none()

    return jsonify(
        success=True,
        total_accounts=total_accounts,
        total_balance=total_balance_cents / 100,
        total_transactions=total_transactions,
        database_started_at=to_iso_utc(meta.database_started_at),
        account_growth=account_growth,
        accounts_today=growth_map.get(today, 0),
        latest_account_at=to_iso_utc(latest_account_at),
        latest_transaction_at=to_iso_utc(latest_transaction_at),
        last_updated=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(success=True)


def seed_demo():
    if db.session.execute(
        db.select(Account).filter_by(account_number=100234)
    ).scalar_one_or_none():
        return

    account = Account(
        name="Priya Nair",
        phone_number="9876543210",
        account_number=100234,
        pin_hash=generate_password_hash("4471"),
        balance_cents=524000,
    )
    db.session.add(account)
    db.session.flush()

    balance = 0
    steps = [
        ("Opening deposit", 400000),
        ("Salary credit", 120000),
        ("Grocery", -14500),
        ("Utility bill", -26000),
        ("Salary credit", 120000),
        ("Rent payment", -120000),
        ("Cash deposit", 60000),
        ("Card refund", 24500),
    ]

    for description, delta in steps:
        balance += delta
        db.session.add(
            Transaction(
                account_id=account.id,
                description=description,
                amount_cents=delta,
                balance_after_cents=balance,
            )
        )

    account.balance_cents = balance
    db.session.commit()


with app.app_context():
    db.create_all()
    get_system_meta()  # created once; never overwritten on later restarts
    if os.getenv("SEED_DEMO", "true").lower() == "true":
        seed_demo()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )
