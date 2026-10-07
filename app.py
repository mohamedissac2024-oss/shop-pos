import os
import secrets
import hashlib

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from psycopg2 import errors as pg_errors

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_connection


# =========================================
# FLASK APP + SECURITY SETTINGS
# =========================================

# Render sets the RENDER environment variable automatically
IS_PRODUCTION = os.getenv("RENDER") is not None

app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "SECRET_KEY is not set. Add a long random value "
        "in your environment variables."
    )

app.secret_key = secret_key

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    WTF_CSRF_TIME_LIMIT=None
)

# Render sits behind a proxy: use the real client IP and https
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)

# CSRF protection for every POST form
csrf = CSRFProtect(app)

# Rate limiting (only applied where we add @limiter.limit)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://"
)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):

    return (
        "Your form expired or is invalid. "
        "Go back, refresh the page and try again.",
        400
    )


# =========================================
# HELPERS
# =========================================

def close_db(cursor, connection):

    cursor.close()
    connection.close()


def parse_int(value, minimum=None):

    try:
        number = int(value)
    except (TypeError, ValueError):
        return None

    if minimum is not None and number < minimum:
        return None

    return number


def parse_money(value):

    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return None

    if not amount.is_finite() or amount < 0:
        return None

    return amount


# =========================================
# LOGIN REQUIRED
# =========================================

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


# =========================================
# ADMIN REQUIRED
# (platform owner only)
# =========================================

def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            return "Access denied. Admins only.", 403

        return f(*args, **kwargs)

    return decorated_function


# =========================================
# CHECK USER + SHOP STATUS ON EVERY REQUEST
# =========================================

PUBLIC_ENDPOINTS = {
    "home",
    "login",
    "logout",
    "setup_account",
    "static"
}


@app.before_request
def check_shop_status():

    if request.endpoint is None:
        return

    if request.endpoint in PUBLIC_ENDPOINTS:
        return

    if "user_id" not in session:
        return

    # Platform admin is never locked out
    if session.get("role") == "admin":
        return

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            shops.status,
            shops.trial_ends_at
        FROM users
        JOIN shops
        ON shops.id = users.shop_id
        WHERE users.id = %s
        AND users.shop_id = %s
        """,
        (
            session["user_id"],
            session.get("shop_id")
        )
    )

    row = cursor.fetchone()

    close_db(cursor, connection)

    # User or shop no longer exists
    if not row:

        session.clear()

        return redirect(url_for("login"))

    status = row[0]
    trial_ends_at = row[1]

    trial_expired = (
        status == "trial"
        and trial_ends_at is not None
        and trial_ends_at < datetime.utcnow()
    )

    if status == "suspended" or trial_expired:

        session.clear()

        return (
            "Your shop account is suspended or its trial has ended. "
            "Please contact support.",
            403
        )


# =========================================
# HOME
# =========================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# =========================================
# LOGIN
# =========================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 50 per hour", methods=["POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                username,
                password_hash,
                shop_id,
                role
            FROM users
            WHERE lower(username) = %s
            """,
            (username,)
        )

        user = cursor.fetchone()

        close_db(cursor, connection)

        if user and check_password_hash(
            user[2],
            password
        ):

            # Start a fresh session (prevents session fixation)
            session.clear()

            session.permanent = True

            session["user_id"] = user[0]
            session["username"] = user[1]
            session["shop_id"] = user[3]
            session["role"] = user[4]

            return redirect(url_for("dashboard"))

        return "Invalid username or password.", 401

    return render_template("login.html")


# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================
# DASHBOARD
# =========================================

@app.route("/dashboard")
@login_required
def dashboard():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    # Total products
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM products
        WHERE shop_id = %s
        AND is_active = TRUE
        """,
        (shop_id,)
    )

    total_products = cursor.fetchone()[0]

    # Products in stock
    cursor.execute(
        """
        SELECT COALESCE(SUM(quantity), 0)
        FROM products
        WHERE shop_id = %s
        AND is_active = TRUE
        """,
        (shop_id,)
    )

    products_in_stock = cursor.fetchone()[0]

    # Total sales
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM sales
        WHERE shop_id = %s
        """,
        (shop_id,)
    )

    total_sales = cursor.fetchone()[0]

    # Total revenue
    cursor.execute(
        """
        SELECT COALESCE(SUM(total), 0)
        FROM sales
        WHERE shop_id = %s
        """,
        (shop_id,)
    )

    total_revenue = cursor.fetchone()[0]

    # Total profit
    cursor.execute(
        """
        SELECT COALESCE(
            SUM(
                (selling_price - buying_price) * quantity
            ),
            0
        )
        FROM sales
        WHERE shop_id = %s
        AND buying_price IS NOT NULL
        """,
        (shop_id,)
    )

    total_profit = cursor.fetchone()[0]

    # Low stock
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM products
        WHERE shop_id = %s
        AND is_active = TRUE
        AND quantity <= 5
        """,
        (shop_id,)
    )

    low_stock_count = cursor.fetchone()[0]

    close_db(cursor, connection)

    return render_template(
        "dashboard.html",
        total_products=total_products,
        products_in_stock=products_in_stock,
        total_sales=total_sales,
        total_revenue=total_revenue,
        total_profit=total_profit,
        low_stock_count=low_stock_count
    )


# =========================================
# PRODUCTS
# =========================================

@app.route("/products")
@login_required
def products():

    shop_id = session["shop_id"]

    search = request.args.get("search", "")

    connection = get_connection()
    cursor = connection.cursor()

    if search:

        cursor.execute(
            """
            SELECT
                id,
                name,
                quantity,
                buying_price,
                selling_price
            FROM products
            WHERE shop_id = %s
            AND is_active = TRUE
            AND (
                name ILIKE %s
            )
            ORDER BY id DESC
            """,
            (
                shop_id,
                f"%{search}%"
            )
        )

    else:

        cursor.execute(
            """
            SELECT
                id,
                name,
                quantity,
                buying_price,
                selling_price
            FROM products
            WHERE shop_id = %s
            AND is_active = TRUE
            ORDER BY id DESC
            """,
            (shop_id,)
        )

    products = cursor.fetchall()

    close_db(cursor, connection)

    return render_template(
        "products.html",
        products=products,
        search=search
    )


# =========================================
# ADD PRODUCT
# =========================================

@app.route("/add-product", methods=["GET", "POST"])
@login_required
def add_product():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        quantity = parse_int(request.form.get("quantity"), 0)
        buying_price = parse_money(request.form.get("buying_price"))
        selling_price = parse_money(request.form.get("selling_price"))

        if not name:
            return "Product name is required.", 400

        if quantity is None:
            return "Quantity must be a whole number (0 or more).", 400

        if buying_price is None or selling_price is None:
            return "Prices must be valid numbers (0 or more).", 400

        shop_id = session["shop_id"]

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO products
            (
                name,
                quantity,
                buying_price,
                selling_price,
                shop_id
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                name,
                quantity,
                buying_price,
                selling_price,
                shop_id
            )
        )

        connection.commit()

        close_db(cursor, connection)

        return redirect(url_for("products"))

    return render_template("add_product.html")


# =========================================
# EDIT PRODUCT
# =========================================

@app.route("/edit-product/<int:product_id>", methods=["GET", "POST"])
@login_required
def edit_product(product_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        quantity = parse_int(request.form.get("quantity"), 0)
        buying_price = parse_money(request.form.get("buying_price"))
        selling_price = parse_money(request.form.get("selling_price"))

        if not name:
            close_db(cursor, connection)
            return "Product name is required.", 400

        if quantity is None:
            close_db(cursor, connection)
            return "Quantity must be a whole number (0 or more).", 400

        if buying_price is None or selling_price is None:
            close_db(cursor, connection)
            return "Prices must be valid numbers (0 or more).", 400

        cursor.execute(
            """
            UPDATE products
            SET
                name = %s,
                quantity = %s,
                buying_price = %s,
                selling_price = %s
            WHERE id = %s
            AND shop_id = %s
            AND is_active = TRUE
            """,
            (
                name,
                quantity,
                buying_price,
                selling_price,
                product_id,
                shop_id
            )
        )

        connection.commit()

        close_db(cursor, connection)

        return redirect(url_for("products"))

    cursor.execute(
        """
        SELECT
            id,
            name,
            quantity,
            buying_price,
            selling_price
        FROM products
        WHERE id = %s
        AND shop_id = %s
        AND is_active = TRUE
        """,
        (
            product_id,
            shop_id
        )
    )

    product = cursor.fetchone()

    close_db(cursor, connection)

    if not product:
        return "Product not found.", 404

    return render_template(
        "edit_product.html",
        product=product
    )


# =========================================
# DELETE PRODUCT
# (hides the product but keeps sales history)
# =========================================

@app.route("/delete-product/<int:product_id>", methods=["POST"])
@login_required
def delete_product(product_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE products
        SET is_active = FALSE
        WHERE id = %s
        AND shop_id = %s
        """,
        (
            product_id,
            shop_id
        )
    )

    connection.commit()

    close_db(cursor, connection)

    return redirect(url_for("products"))


# =========================================
# CUSTOMERS
# =========================================

@app.route("/customers")
@login_required
def customers():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            name,
            phone,
            email,
            created_at
        FROM customers
        WHERE shop_id = %s
        ORDER BY id DESC
        """,
        (shop_id,)
    )

    customers = cursor.fetchall()

    close_db(cursor, connection)

    return render_template(
        "customers.html",
        customers=customers
    )


# =========================================
# ADD CUSTOMER
# =========================================

@app.route("/add-customer", methods=["GET", "POST"])
@login_required
def add_customer():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()

        if not name:
            return "Customer name is required.", 400

        shop_id = session["shop_id"]

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO customers
            (
                name,
                phone,
                email,
                shop_id
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                name,
                phone,
                email,
                shop_id
            )
        )

        connection.commit()

        close_db(cursor, connection)

        return redirect(url_for("customers"))

    return render_template("add_customer.html")


# =========================================
# EDIT CUSTOMER
# =========================================

@app.route("/edit-customer/<int:customer_id>", methods=["GET", "POST"])
@login_required
def edit_customer(customer_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()

        if not name:
            close_db(cursor, connection)
            return "Customer name is required.", 400

        cursor.execute(
            """
            UPDATE customers
            SET
                name = %s,
                phone = %s,
                email = %s
            WHERE id = %s
            AND shop_id = %s
            """,
            (
                name,
                phone,
                email,
                customer_id,
                shop_id
            )
        )

        connection.commit()

        close_db(cursor, connection)

        return redirect(url_for("customers"))

    cursor.execute(
        """
        SELECT
            id,
            name,
            phone,
            email
        FROM customers
        WHERE id = %s
        AND shop_id = %s
        """,
        (
            customer_id,
            shop_id
        )
    )

    customer = cursor.fetchone()

    close_db(cursor, connection)

    if not customer:
        return "Customer not found.", 404

    return render_template(
        "edit_customer.html",
        customer=customer
    )


# =========================================
# DELETE CUSTOMER
# =========================================

@app.route("/delete-customer/<int:customer_id>", methods=["POST"])
@login_required
def delete_customer(customer_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            DELETE FROM customers
            WHERE id = %s
            AND shop_id = %s
            """,
            (
                customer_id,
                shop_id
            )
        )

        connection.commit()

    except pg_errors.ForeignKeyViolation:

        connection.rollback()

        close_db(cursor, connection)

        return (
            "This customer has purchase records "
            "and cannot be deleted."
        ), 400

    close_db(cursor, connection)

    return redirect(url_for("customers"))


# =========================================
# MAKE SALE
# =========================================

@app.route("/sale", methods=["GET", "POST"])
@login_required
def sale():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        product_id = parse_int(request.form.get("product_id"), 1)
        quantity = parse_int(request.form.get("quantity"), 1)

        if product_id is None:
            close_db(cursor, connection)
            return "Please choose a product.", 400

        if quantity is None:
            close_db(cursor, connection)
            return "Quantity must be a whole number greater than zero.", 400

        # Optional customer
        customer_id = None

        raw_customer_id = request.form.get("customer_id", "").strip()

        if raw_customer_id:

            customer_id = parse_int(raw_customer_id, 1)

            if customer_id is None:
                close_db(cursor, connection)
                return "Invalid customer.", 400

            # The customer must belong to THIS shop
            cursor.execute(
                """
                SELECT id
                FROM customers
                WHERE id = %s
                AND shop_id = %s
                """,
                (
                    customer_id,
                    shop_id
                )
            )

            if not cursor.fetchone():
                close_db(cursor, connection)
                return "Customer not found.", 404

        # Get product (must belong to this shop and be active)
        cursor.execute(
            """
            SELECT
                id,
                name,
                quantity,
                buying_price,
                selling_price
            FROM products
            WHERE id = %s
            AND shop_id = %s
            AND is_active = TRUE
            """,
            (
                product_id,
                shop_id
            )
        )

        product = cursor.fetchone()

        if not product:
            close_db(cursor, connection)
            return "Product not found.", 404

        buying_price = product[3]
        selling_price = product[4]

        # Reduce stock safely.
        # The WHERE quantity >= %s check makes it impossible
        # for two sales at the same time to oversell.
        cursor.execute(
            """
            UPDATE products
            SET quantity = quantity - %s
            WHERE id = %s
            AND shop_id = %s
            AND is_active = TRUE
            AND quantity >= %s
            """,
            (
                quantity,
                product_id,
                shop_id,
                quantity
            )
        )

        if cursor.rowcount != 1:

            connection.rollback()

            close_db(cursor, connection)

            return "Not enough stock.", 400

        total = selling_price * quantity

        # Create sale
        cursor.execute(
            """
            INSERT INTO sales
            (
                product_id,
                quantity,
                selling_price,
                total,
                customer_id,
                buying_price,
                shop_id
            )
            VALUES
            (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                product_id,
                quantity,
                selling_price,
                total,
                customer_id,
                buying_price,
                shop_id
            )
        )

        sale_id = cursor.fetchone()[0]

        # Stock update and sale are saved together
        connection.commit()

        close_db(cursor, connection)

        return redirect(
            url_for(
                "receipt",
                sale_id=sale_id
            )
        )

    # Products
    cursor.execute(
        """
        SELECT
            id,
            name,
            quantity,
            selling_price
        FROM products
        WHERE shop_id = %s
        AND is_active = TRUE
        AND quantity > 0
        ORDER BY name
        """,
        (shop_id,)
    )

    products = cursor.fetchall()

    # Customers
    cursor.execute(
        """
        SELECT
            id,
            name,
            phone
        FROM customers
        WHERE shop_id = %s
        ORDER BY name
        """,
        (shop_id,)
    )

    customers = cursor.fetchall()

    close_db(cursor, connection)

    return render_template(
        "sale.html",
        products=products,
        customers=customers
    )


# =========================================
# SALES
# =========================================

@app.route("/sales")
@login_required
def sales():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            sales.id,
            products.name,
            customers.name,
            sales.quantity,
            sales.selling_price,
            sales.total,
            sales.sale_date
        FROM sales

        JOIN products
        ON sales.product_id = products.id
        AND products.shop_id = sales.shop_id

        LEFT JOIN customers
        ON sales.customer_id = customers.id
        AND customers.shop_id = sales.shop_id

        WHERE sales.shop_id = %s

        ORDER BY sales.id DESC
        """,
        (shop_id,)
    )

    sales = cursor.fetchall()

    close_db(cursor, connection)

    return render_template(
        "sales.html",
        sales=sales
    )


# =========================================
# RECEIPT
# =========================================

@app.route("/receipt/<int:sale_id>")
@login_required
def receipt(sale_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            sales.id,
            products.name,
            customers.name,
            customers.phone,
            sales.quantity,
            sales.selling_price,
            sales.total,
            sales.sale_date
        FROM sales

        JOIN products
        ON sales.product_id = products.id
        AND products.shop_id = sales.shop_id

        LEFT JOIN customers
        ON sales.customer_id = customers.id
        AND customers.shop_id = sales.shop_id

        WHERE sales.id = %s
        AND sales.shop_id = %s
        """,
        (
            sale_id,
            shop_id
        )
    )

    sale = cursor.fetchone()

    close_db(cursor, connection)

    if not sale:
        return "Sale not found.", 404

    return render_template(
        "receipt.html",
        sale=sale
    )


# =========================================
# CUSTOMER PURCHASES
# =========================================

@app.route("/customer/<int:customer_id>/purchases")
@login_required
def customer_purchases(customer_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            sales.id,
            products.name,
            sales.quantity,
            sales.selling_price,
            sales.total,
            sales.sale_date
        FROM sales

        JOIN products
        ON sales.product_id = products.id
        AND products.shop_id = sales.shop_id

        WHERE sales.customer_id = %s
        AND sales.shop_id = %s

        ORDER BY sales.id DESC
        """,
        (
            customer_id,
            shop_id
        )
    )

    purchases = cursor.fetchall()

    close_db(cursor, connection)

    return render_template(
        "customer_purchases.html",
        purchases=purchases
    )


# =========================================
# LOW STOCK
# =========================================

@app.route("/low-stock")
@login_required
def low_stock():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            name,
            quantity,
            buying_price,
            selling_price
        FROM products
        WHERE shop_id = %s
        AND is_active = TRUE
        AND quantity <= 5
        ORDER BY quantity ASC
        """,
        (shop_id,)
    )

    products = cursor.fetchall()

    close_db(cursor, connection)

    return render_template(
        "low_stock.html",
        products=products
    )


# =========================================
# CREATE SHOP
# ADMIN ONLY
# =========================================

@app.route("/create-shop", methods=["GET", "POST"])
@admin_required
def create_shop():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()

        if not name:
            return "Shop name is required.", 400

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO shops
            (
                name,
                phone,
                email
            )
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (
                name,
                phone,
                email
            )
        )

        shop_id = cursor.fetchone()[0]

        connection.commit()

        close_db(cursor, connection)

        return render_template(
            "create_shop.html",
            success=True,
            shop_id=shop_id,
            shop_name=name
        )

    return render_template(
        "create_shop.html"
    )


# =========================================
# CREATE INVITATION
# ADMIN ONLY
# =========================================

@app.route("/create-invite", methods=["GET", "POST"])
@admin_required
def create_invite():

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        shop_id = parse_int(request.form.get("shop_id"), 1)

        if shop_id is None:
            close_db(cursor, connection)
            return "Please choose a shop.", 400

        # Make sure the shop exists
        cursor.execute(
            """
            SELECT id
            FROM shops
            WHERE id = %s
            """,
            (shop_id,)
        )

        if not cursor.fetchone():
            close_db(cursor, connection)
            return "Shop not found.", 404

        # Generate secure random token
        token = secrets.token_urlsafe(32)

        # Hash token before saving
        token_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

        # Invitation expires after 24 hours
        expires_at = datetime.utcnow() + timedelta(hours=24)

        cursor.execute(
            """
            INSERT INTO account_invites
            (
                token_hash,
                expires_at,
                used,
                shop_id
            )
            VALUES
            (%s, %s, FALSE, %s)
            """,
            (
                token_hash,
                expires_at,
                shop_id
            )
        )

        connection.commit()

        close_db(cursor, connection)

        invitation_link = url_for(
            "setup_account",
            token=token,
            _external=True
        )

        return render_template(
            "create_invite.html",
            invitation_link=invitation_link
        )

    cursor.execute(
        """
        SELECT
            id,
            name
        FROM shops
        ORDER BY name
        """
    )

    shops = cursor.fetchall()

    close_db(cursor, connection)

    return render_template(
        "create_invite.html",
        shops=shops
    )


# =========================================
# SETUP ACCOUNT FROM INVITATION
# =========================================

@app.route(
    "/setup-account/<token>",
    methods=["GET", "POST"]
)
@limiter.limit("20 per hour", methods=["POST"])
def setup_account(token):

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            shop_id,
            expires_at,
            used
        FROM account_invites
        WHERE token_hash = %s
        """,
        (token_hash,)
    )

    invite = cursor.fetchone()

    if not invite:

        close_db(cursor, connection)

        return "Invalid invitation.", 404

    invite_id = invite[0]
    shop_id = invite[1]
    expires_at = invite[2]
    used = invite[3]

    # Check if already used
    if used:

        close_db(cursor, connection)

        return "This invitation has already been used.", 400

    # Check expiration
    if datetime.utcnow() > expires_at:

        close_db(cursor, connection)

        return "This invitation has expired.", 400

    if request.method == "POST":

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if len(username) < 3:

            close_db(cursor, connection)

            return "Username must be at least 3 characters.", 400

        if len(password) < 8:

            close_db(cursor, connection)

            return "Password must be at least 8 characters.", 400

        # Claim the invitation first.
        # If two people open the link at the same time,
        # only one of them can succeed.
        cursor.execute(
            """
            UPDATE account_invites
            SET used = TRUE
            WHERE id = %s
            AND used = FALSE
            """,
            (invite_id,)
        )

        if cursor.rowcount != 1:

            connection.rollback()

            close_db(cursor, connection)

            return "This invitation has already been used.", 400

        password_hash = generate_password_hash(
            password
        )

        try:

            # Create shop user
            cursor.execute(
                """
                INSERT INTO users
                (
                    username,
                    password_hash,
                    shop_id,
                    role
                )
                VALUES
                (%s, %s, %s, 'shop_user')
                """,
                (
                    username,
                    password_hash,
                    shop_id
                )
            )

            connection.commit()

        except pg_errors.UniqueViolation:

            # Rolls back the invitation claim too,
            # so the link still works with another username
            connection.rollback()

            close_db(cursor, connection)

            return "Username already exists.", 400

        close_db(cursor, connection)

        return redirect(url_for("login"))

    close_db(cursor, connection)

    return render_template(
        "setup_account.html"
    )


# =========================================
# TEST DATABASE
# ADMIN ONLY
# =========================================

@app.route("/test-db")
@admin_required
def test_db():

    try:

        connection = get_connection()

        cursor = connection.cursor()

        cursor.execute("SELECT 1")

        cursor.fetchone()

        close_db(cursor, connection)

        return "Database connected successfully."

    except Exception:

        return "Database connection failed.", 500


# =========================================
# RUN APP
# =========================================

if __name__ == "__main__":

    app.run(
        debug=not IS_PRODUCTION
    )