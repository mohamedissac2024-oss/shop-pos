import os
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from werkzeug.security import generate_password_hash, check_password_hash

from db import get_connection


app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


# =========================================================
# ADMIN REQUIRED
# =========================================================

def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            return "Access denied. Admins only."

        return f(*args, **kwargs)

    return decorated_function


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id, username, password_hash, shop_id, role
            FROM users
            WHERE username = %s
            """,
            (username,)
        )

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user and check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["username"] = user[1]
            session["shop_id"] = user[3]
            session["role"] = user[4]

            return redirect(url_for("dashboard"))

        return "Invalid username or password."

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# DASHBOARD
# =========================================================

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
        AND quantity <= 5
        """,
        (shop_id,)
    )

    low_stock_count = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return render_template(
        "dashboard.html",
        total_products=total_products,
        products_in_stock=products_in_stock,
        total_sales=total_sales,
        total_revenue=total_revenue,
        total_profit=total_profit,
        low_stock_count=low_stock_count
    )


# =========================================================
# PRODUCTS
# =========================================================

@app.route("/products")
@login_required
def products():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, quantity, buying_price, selling_price
        FROM products
        WHERE shop_id = %s
        ORDER BY id DESC
        """,
        (shop_id,)
    )

    products = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "products.html",
        products=products
    )


# =========================================================
# ADD PRODUCT
# =========================================================

@app.route("/add-product", methods=["GET", "POST"])
@login_required
def add_product():

    if request.method == "POST":

        name = request.form["name"]
        quantity = request.form["quantity"]
        buying_price = request.form["buying_price"]
        selling_price = request.form["selling_price"]

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

        cursor.close()
        connection.close()

        return redirect(url_for("products"))

    return render_template("add_product.html")


# =========================================================
# EDIT PRODUCT
# =========================================================

@app.route("/edit-product/<int:product_id>", methods=["GET", "POST"])
@login_required
def edit_product(product_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        name = request.form["name"]
        quantity = request.form["quantity"]
        buying_price = request.form["buying_price"]
        selling_price = request.form["selling_price"]

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

        cursor.close()
        connection.close()

        return redirect(url_for("products"))

    cursor.execute(
        """
        SELECT id, name, quantity, buying_price, selling_price
        FROM products
        WHERE id = %s
        AND shop_id = %s
        """,
        (
            product_id,
            shop_id
        )
    )

    product = cursor.fetchone()

    cursor.close()
    connection.close()

    if not product:
        return "Product not found."

    return render_template(
        "edit_product.html",
        product=product
    )


# =========================================================
# DELETE PRODUCT
# =========================================================

@app.route("/delete-product/<int:product_id>")
@login_required
def delete_product(product_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM products
        WHERE id = %s
        AND shop_id = %s
        """,
        (
            product_id,
            shop_id
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("products"))


# =========================================================
# CUSTOMERS
# =========================================================

@app.route("/customers")
@login_required
def customers():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, phone, email
        FROM customers
        WHERE shop_id = %s
        ORDER BY id DESC
        """,
        (shop_id,)
    )

    customers = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "customers.html",
        customers=customers
    )


# =========================================================
# ADD CUSTOMER
# =========================================================

@app.route("/add-customer", methods=["GET", "POST"])
@login_required
def add_customer():

    if request.method == "POST":

        name = request.form["name"]
        phone = request.form["phone"]
        email = request.form["email"]

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

        cursor.close()
        connection.close()

        return redirect(url_for("customers"))

    return render_template("add_customer.html")


# =========================================================
# EDIT CUSTOMER
# =========================================================

@app.route("/edit-customer/<int:customer_id>", methods=["GET", "POST"])
@login_required
def edit_customer(customer_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        name = request.form["name"]
        phone = request.form["phone"]
        email = request.form["email"]

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

        cursor.close()
        connection.close()

        return redirect(url_for("customers"))

    cursor.execute(
        """
        SELECT id, name, phone, email
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

    cursor.close()
    connection.close()

    if not customer:
        return "Customer not found."

    return render_template(
        "edit_customer.html",
        customer=customer
    )


# =========================================================
# DELETE CUSTOMER
# =========================================================

@app.route("/delete-customer/<int:customer_id>")
@login_required
def delete_customer(customer_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

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

    cursor.close()
    connection.close()

    return redirect(url_for("customers"))


# =========================================================
# SALE
# =========================================================

@app.route("/sale", methods=["GET", "POST"])
@login_required
def sale():

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        product_id = request.form["product_id"]
        quantity = int(request.form["quantity"])

        customer_id = request.form.get("customer_id")

        if customer_id == "":
            customer_id = None
        else:
            customer_id = int(customer_id)

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
            """,
            (
                product_id,
                shop_id
            )
        )

        product = cursor.fetchone()

        if not product:

            cursor.close()
            connection.close()

            return "Product not found."

        current_quantity = product[2]
        buying_price = product[3]
        selling_price = product[4]

        if quantity <= 0:

            cursor.close()
            connection.close()

            return "Quantity must be greater than zero."

        if quantity > current_quantity:

            cursor.close()
            connection.close()

            return "Not enough stock."

        total = selling_price * quantity

        # Reduce product stock

        cursor.execute(
            """
            UPDATE products
            SET quantity = quantity - %s
            WHERE id = %s
            AND shop_id = %s
            """,
            (
                quantity,
                product_id,
                shop_id
            )
        )

        # Save sale

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
            VALUES (%s, %s, %s, %s, %s, %s, %s)
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

        connection.commit()

        cursor.close()
        connection.close()

        return redirect(
            url_for(
                "receipt",
                sale_id=sale_id
            )
        )

    # Products belonging to current shop

    cursor.execute(
        """
        SELECT id, name, quantity, selling_price
        FROM products
        WHERE shop_id = %s
        AND quantity > 0
        ORDER BY name
        """,
        (shop_id,)
    )

    products = cursor.fetchall()

    # Customers belonging to current shop

    cursor.execute(
        """
        SELECT id, name
        FROM customers
        WHERE shop_id = %s
        ORDER BY name
        """,
        (shop_id,)
    )

    customers = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "sale.html",
        products=products,
        customers=customers
    )


# =========================================================
# SALES
# =========================================================

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
            sales.quantity,
            sales.selling_price,
            sales.total,
            sales.sale_date,
            customers.name
        FROM sales

        JOIN products
            ON sales.product_id = products.id

        LEFT JOIN customers
            ON sales.customer_id = customers.id

        WHERE sales.shop_id = %s

        ORDER BY sales.id DESC
        """,
        (shop_id,)
    )

    sales = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "sales.html",
        sales=sales
    )


# =========================================================
# RECEIPT
# =========================================================

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
            sales.quantity,
            sales.selling_price,
            sales.total,
            sales.sale_date,
            customers.name,
            customers.phone
        FROM sales

        JOIN products
            ON sales.product_id = products.id

        LEFT JOIN customers
            ON sales.customer_id = customers.id

        WHERE sales.id = %s
        AND sales.shop_id = %s
        """,
        (
            sale_id,
            shop_id
        )
    )

    sale = cursor.fetchone()

    cursor.close()
    connection.close()

    if not sale:
        return "Sale not found."

    return render_template(
        "receipt.html",
        sale=sale
    )


# =========================================================
# CUSTOMER PURCHASES
# =========================================================

@app.route("/customer-purchases/<int:customer_id>")
@login_required
def customer_purchases(customer_id):

    shop_id = session["shop_id"]

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, phone, email
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

    if not customer:

        cursor.close()
        connection.close()

        return "Customer not found."

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

    cursor.close()
    connection.close()

    return render_template(
        "customer_purchases.html",
        customer=customer,
        purchases=purchases
    )


# =========================================================
# LOW STOCK
# =========================================================

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
        AND quantity <= 5
        ORDER BY quantity ASC
        """,
        (shop_id,)
    )

    products = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "low_stock.html",
        products=products
    )


# =========================================================
# CREATE SHOP - ADMIN ONLY
# =========================================================

@app.route("/create-shop", methods=["GET", "POST"])
@admin_required
def create_shop():

    if request.method == "POST":

        name = request.form["name"]
        phone = request.form["phone"]
        email = request.form["email"]

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

        cursor.close()
        connection.close()

        return render_template(
            "create_shop.html",
            success=True,
            shop_id=shop_id,
            shop_name=name
        )

    return render_template(
        "create_shop.html"
    )


# =========================================================
# CREATE INVITATION - ADMIN ONLY
# =========================================================

@app.route("/create-invite", methods=["GET", "POST"])
@admin_required
def create_invite():

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        shop_id = request.form["shop_id"]

        # Create secure random token

        token = secrets.token_urlsafe(32)

        # Store only the hash of the token

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
                shop_id
            )
            VALUES (%s, %s, %s)
            """,
            (
                token_hash,
                expires_at,
                shop_id
            )
        )

        connection.commit()

        cursor.close()
        connection.close()

        invitation_link = url_for(
            "setup_account",
            token=token,
            _external=True
        )

        return f"""
        <h2>Invitation Created Successfully</h2>

        <p>Send this link to the customer:</p>

        <p>
            <a href="{invitation_link}">
                {invitation_link}
            </a>
        </p>

        <p>
            This invitation expires in 24 hours.
        </p>
        """

    # Get all shops

    cursor.execute(
        """
        SELECT id, name
        FROM shops
        ORDER BY name
        """
    )

    shops = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "create_invite.html",
        shops=shops
    )


# =========================================================
# SETUP ACCOUNT USING INVITATION
# =========================================================

@app.route("/setup-account/<token>", methods=["GET", "POST"])
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

        cursor.close()
        connection.close()

        return "Invalid invitation."

    invite_id = invite[0]
    shop_id = invite[1]
    expires_at = invite[2]
    used = invite[3]

    if used:

        cursor.close()
        connection.close()

        return "This invitation has already been used."

    if datetime.utcnow() > expires_at:

        cursor.close()
        connection.close()

        return "This invitation has expired."

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        password_hash = generate_password_hash(
            password
        )

        try:

            cursor.execute(
                """
                INSERT INTO users
                (
                    username,
                    password_hash,
                    shop_id,
                    role
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    username,
                    password_hash,
                    shop_id,
                    "shop_user"
                )
            )

            cursor.execute(
                """
                UPDATE account_invites
                SET used = TRUE
                WHERE id = %s
                """,
                (invite_id,)
            )

            connection.commit()

        except Exception as e:

            connection.rollback()

            cursor.close()
            connection.close()

            return f"Could not create account: {e}"

        cursor.close()
        connection.close()

        return redirect(
            url_for("login")
        )

    cursor.close()
    connection.close()

    return render_template(
        "setup_account.html"
    )


# =========================================================
# TEST DATABASE CONNECTION
# =========================================================

@app.route("/test-db")
def test_db():

    try:

        connection = get_connection()

        cursor = connection.cursor()

        cursor.execute("SELECT 1")

        result = cursor.fetchone()

        cursor.close()
        connection.close()

        return (
            f"Database connection successful! "
            f"Result: {result}"
        )

    except Exception as e:

        return f"Database connection failed: {e}"


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )