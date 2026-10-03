from functools import wraps
import os

from flask import Flask, render_template, request, redirect, session
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

from db import get_connection


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================

def login_required(route_function):

    @wraps(route_function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            return redirect("/login")

        return route_function(*args, **kwargs)

    return decorated_function


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect("/dashboard")

    return redirect("/login")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                username,
                password_hash
            FROM users
            WHERE username = %s
        """, (username,))

        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user and check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect("/dashboard")

        return "Invalid username or password."

    return render_template("login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    connection = get_connection()
    cursor = connection.cursor()

    # Total products
    cursor.execute("""
        SELECT COUNT(*)
        FROM products
    """)

    total_products = cursor.fetchone()[0]

    # Products in stock
    cursor.execute("""
        SELECT COALESCE(SUM(quantity), 0)
        FROM products
    """)

    products_in_stock = cursor.fetchone()[0]

    # Total sales
    cursor.execute("""
        SELECT COUNT(*)
        FROM sales
    """)

    total_sales = cursor.fetchone()[0]

    # Total revenue
    cursor.execute("""
        SELECT COALESCE(SUM(total), 0)
        FROM sales
    """)

    total_revenue = cursor.fetchone()[0]

    # Total profit
    cursor.execute("""
        SELECT COALESCE(
            SUM(
                (selling_price - buying_price)
                * quantity
            ),
            0
        )
        FROM sales
    """)

    total_profit = cursor.fetchone()[0]

    # Low stock
    cursor.execute("""
        SELECT COUNT(*)
        FROM products
        WHERE quantity <= 5
    """)

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


# ============================================================
# TEST DATABASE
# ============================================================

@app.route("/test-db")
@login_required
def test_db():

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT 1")

        result = cursor.fetchone()

        cursor.close()
        connection.close()

        return f"Database is working: {result[0]}"

    except Exception as e:

        return f"Database connection failed: {e}"


# ============================================================
# PRODUCTS
# ============================================================

@app.route("/products")
@login_required
def products():

    search = request.args.get("search", "")

    connection = get_connection()
    cursor = connection.cursor()

    if search:

        cursor.execute("""
            SELECT
                id,
                name,
                quantity,
                buying_price,
                selling_price
            FROM products
            WHERE name ILIKE %s
            ORDER BY id DESC
        """, (f"%{search}%",))

    else:

        cursor.execute("""
            SELECT
                id,
                name,
                quantity,
                buying_price,
                selling_price
            FROM products
            ORDER BY id DESC
        """)

    products = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "products.html",
        products=products,
        search=search
    )


# ============================================================
# ADD PRODUCT
# ============================================================

@app.route("/add-product", methods=["GET", "POST"])
@login_required
def add_product():

    if request.method == "POST":

        name = request.form["name"]
        quantity = int(request.form["quantity"])
        buying_price = request.form["buying_price"]
        selling_price = request.form["selling_price"]

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO products
            (
                name,
                quantity,
                buying_price,
                selling_price
            )
            VALUES (%s, %s, %s, %s)
        """, (
            name,
            quantity,
            buying_price,
            selling_price
        ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect("/products")

    return render_template("add_product.html")


# ============================================================
# EDIT PRODUCT
# ============================================================

@app.route("/edit-product/<int:id>", methods=["GET", "POST"])
@login_required
def edit_product(id):

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        name = request.form["name"]
        quantity = int(request.form["quantity"])
        buying_price = request.form["buying_price"]
        selling_price = request.form["selling_price"]

        cursor.execute("""
            UPDATE products
            SET
                name = %s,
                quantity = %s,
                buying_price = %s,
                selling_price = %s
            WHERE id = %s
        """, (
            name,
            quantity,
            buying_price,
            selling_price,
            id
        ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect("/products")

    cursor.execute("""
        SELECT
            id,
            name,
            quantity,
            buying_price,
            selling_price
        FROM products
        WHERE id = %s
    """, (id,))

    product = cursor.fetchone()

    cursor.close()
    connection.close()

    if not product:
        return "Product not found."

    return render_template(
        "edit_product.html",
        product=product
    )


# ============================================================
# DELETE PRODUCT
# ============================================================

@app.route("/delete-product/<int:id>", methods=["POST"])
@login_required
def delete_product(id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            name
        FROM products
        WHERE id = %s
    """, (id,))

    product = cursor.fetchone()

    if not product:

        cursor.close()
        connection.close()

        return "Product not found."

    # Check if product has sales
    cursor.execute("""
        SELECT COUNT(*)
        FROM sales
        WHERE product_id = %s
    """, (id,))

    sale_count = cursor.fetchone()[0]

    if sale_count > 0:

        cursor.close()
        connection.close()

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cannot Delete Product</title>
        </head>

        <body>

            <h2>Cannot Delete Product</h2>

            <p>
                This product has already been used in sales.
            </p>

            <p>
                You cannot delete a product that has sales.
            </p>

            <a href="/products">
                Back to Products
            </a>

        </body>
        </html>
        """

    cursor.execute("""
        DELETE FROM products
        WHERE id = %s
    """, (id,))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect("/products")


# ============================================================
# LOW STOCK
# ============================================================

@app.route("/low-stock")
@login_required
def low_stock():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            quantity,
            buying_price,
            selling_price
        FROM products
        WHERE quantity <= 5
        ORDER BY quantity ASC
    """)

    products = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "low_stock.html",
        products=products
    )


# ============================================================
# MAKE SALE
# ============================================================

@app.route("/sale", methods=["GET", "POST"])
@login_required
def make_sale():

    connection = get_connection()
    cursor = connection.cursor()

    # GET
    if request.method == "GET":

        cursor.execute("""
            SELECT
                id,
                name,
                quantity,
                buying_price,
                selling_price
            FROM products
            WHERE quantity > 0
            ORDER BY name
        """)

        products = cursor.fetchall()

        cursor.execute("""
            SELECT
                id,
                name,
                phone
            FROM customers
            ORDER BY name
        """)

        customers = cursor.fetchall()

        cursor.close()
        connection.close()

        return render_template(
            "sale.html",
            products=products,
            customers=customers
        )

    # POST
    product_id = request.form["product_id"]
    quantity = int(request.form["quantity"])

    customer_id = request.form.get("customer_id")

    if customer_id == "":
        customer_id = None

    # Get product
    cursor.execute("""
        SELECT
            id,
            name,
            quantity,
            buying_price,
            selling_price
        FROM products
        WHERE id = %s
    """, (product_id,))

    product = cursor.fetchone()

    if not product:

        cursor.close()
        connection.close()

        return "Product not found."

    product_id = product[0]
    product_name = product[1]
    stock = product[2]
    buying_price = product[3]
    selling_price = product[4]

    # Validate quantity
    if quantity <= 0:

        cursor.close()
        connection.close()

        return "Quantity must be greater than 0."

    # Check stock
    if quantity > stock:

        cursor.close()
        connection.close()

        return f"Not enough stock. Only {stock} items available."

    # Calculate total
    total = selling_price * quantity

    # Calculate profit
    profit = (selling_price - buying_price) * quantity

    # Default customer
    customer_name = "Walk-in Customer"
    customer_phone = ""

    # Get customer
    if customer_id:

        cursor.execute("""
            SELECT
                name,
                phone
            FROM customers
            WHERE id = %s
        """, (customer_id,))

        customer = cursor.fetchone()

        if customer:

            customer_name = customer[0]
            customer_phone = customer[1] or ""

    # Insert sale
    cursor.execute("""
        INSERT INTO sales
        (
            product_id,
            customer_id,
            buying_price,
            selling_price,
            quantity,
            total
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id, sale_date
    """, (
        product_id,
        customer_id,
        buying_price,
        selling_price,
        quantity,
        total
    ))

    sale = cursor.fetchone()

    sale_id = sale[0]
    sale_date = sale[1]

    # Reduce stock
    cursor.execute("""
        UPDATE products
        SET quantity = quantity - %s
        WHERE id = %s
    """, (
        quantity,
        product_id
    ))

    connection.commit()

    cursor.close()
    connection.close()

    return render_template(
        "receipt.html",
        sale_id=sale_id,
        sale_date=sale_date,
        product_name=product_name,
        quantity=quantity,
        selling_price=selling_price,
        total=total,
        profit=profit,
        customer_name=customer_name,
        customer_phone=customer_phone
    )


# ============================================================
# SALES HISTORY
# ============================================================

@app.route("/sales")
@login_required
def sales():

    filter_type = request.args.get("filter", "all")

    connection = get_connection()
    cursor = connection.cursor()

    # Date filter
    if filter_type == "today":

        date_condition = """
            WHERE sales.sale_date::date = CURRENT_DATE
        """

    elif filter_type == "week":

        date_condition = """
            WHERE sales.sale_date >= CURRENT_DATE - INTERVAL '7 days'
        """

    elif filter_type == "month":

        date_condition = """
            WHERE sales.sale_date >= DATE_TRUNC(
                'month',
                CURRENT_DATE
            )
        """

    else:

        date_condition = ""

    # Sales
    query = f"""
        SELECT
            sales.id,
            products.name,
            customers.name,
            customers.phone,
            sales.quantity,
            sales.selling_price,
            sales.total,
            (
                sales.selling_price - sales.buying_price
            ) * sales.quantity AS profit,
            sales.sale_date
        FROM sales

        JOIN products
        ON sales.product_id = products.id

        LEFT JOIN customers
        ON sales.customer_id = customers.id

        {date_condition}

        ORDER BY sales.id DESC
    """

    cursor.execute(query)

    sales = cursor.fetchall()

    # Revenue
    cursor.execute(f"""
        SELECT COALESCE(
            SUM(total),
            0
        )
        FROM sales
        {date_condition}
    """)

    total_revenue = cursor.fetchone()[0]

    # Profit
    cursor.execute(f"""
        SELECT COALESCE(
            SUM(
                (selling_price - buying_price)
                * quantity
            ),
            0
        )
        FROM sales
        {date_condition}
    """)

    total_profit = cursor.fetchone()[0]

    # Number of sales
    cursor.execute(f"""
        SELECT COUNT(*)
        FROM sales
        {date_condition}
    """)

    total_sales = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return render_template(
        "sales.html",
        sales=sales,
        filter_type=filter_type,
        total_sales=total_sales,
        total_revenue=total_revenue,
        total_profit=total_profit
    )


# ============================================================
# CUSTOMERS
# ============================================================

@app.route("/customers")
@login_required
def customers():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            phone,
            email,
            created_at
        FROM customers
        ORDER BY id DESC
    """)

    customers = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "customers.html",
        customers=customers
    )


# ============================================================
# ADD CUSTOMER
# ============================================================

@app.route("/add-customer", methods=["GET", "POST"])
@login_required
def add_customer():

    if request.method == "POST":

        name = request.form["name"]
        phone = request.form["phone"]
        email = request.form["email"]

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO customers
            (
                name,
                phone,
                email
            )
            VALUES (%s, %s, %s)
        """, (
            name,
            phone,
            email
        ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect("/customers")

    return render_template("add_customer.html")


# ============================================================
# EDIT CUSTOMER
# ============================================================

@app.route("/edit-customer/<int:id>", methods=["GET", "POST"])
@login_required
def edit_customer(id):

    connection = get_connection()
    cursor = connection.cursor()

    if request.method == "POST":

        name = request.form["name"]
        phone = request.form["phone"]
        email = request.form["email"]

        cursor.execute("""
            UPDATE customers
            SET
                name = %s,
                phone = %s,
                email = %s
            WHERE id = %s
        """, (
            name,
            phone,
            email,
            id
        ))

        connection.commit()

        cursor.close()
        connection.close()

        return redirect("/customers")

    cursor.execute("""
        SELECT
            id,
            name,
            phone,
            email
        FROM customers
        WHERE id = %s
    """, (id,))

    customer = cursor.fetchone()

    cursor.close()
    connection.close()

    if not customer:
        return "Customer not found."

    return render_template(
        "edit_customer.html",
        customer=customer
    )


# ============================================================
# DELETE CUSTOMER
# ============================================================

@app.route("/delete-customer/<int:id>", methods=["POST"])
@login_required
def delete_customer(id):

    connection = get_connection()
    cursor = connection.cursor()

    # Remove customer from previous sales
    cursor.execute("""
        UPDATE sales
        SET customer_id = NULL
        WHERE customer_id = %s
    """, (id,))

    # Delete customer
    cursor.execute("""
        DELETE FROM customers
        WHERE id = %s
    """, (id,))

    connection.commit()

    cursor.close()
    connection.close()

    return redirect("/customers")


# ============================================================
# CUSTOMER PURCHASE HISTORY
# ============================================================

@app.route("/customer/<int:id>/purchases")
@login_required
def customer_purchases(id):

    connection = get_connection()
    cursor = connection.cursor()

    # Customer
    cursor.execute("""
        SELECT
            id,
            name,
            phone,
            email
        FROM customers
        WHERE id = %s
    """, (id,))

    customer = cursor.fetchone()

    if not customer:

        cursor.close()
        connection.close()

        return "Customer not found."

    # Purchases
    cursor.execute("""
        SELECT
            products.name,
            sales.quantity,
            sales.selling_price,
            sales.total,
            sales.sale_date
        FROM sales

        JOIN products
        ON sales.product_id = products.id

        WHERE sales.customer_id = %s

        ORDER BY sales.sale_date DESC
    """, (id,))

    purchases = cursor.fetchall()

    # Total spent
    cursor.execute("""
        SELECT COALESCE(
            SUM(total),
            0
        )
        FROM sales
        WHERE customer_id = %s
    """, (id,))

    total_spent = cursor.fetchone()[0]

    cursor.close()
    connection.close()

    return render_template(
        "customer_purchases.html",
        customer=customer,
        purchases=purchases,
        total_spent=total_spent
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)