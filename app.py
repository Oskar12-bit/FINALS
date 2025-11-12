import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import mysql.connector
from werkzeug.utils import secure_filename
from decimal import Decimal
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import g

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

config = {
    'host': os.environ.get('DB_HOST', 'mysql-1910805-dodongoskar-d316.b.aivencloud.com'),
    'user': os.environ.get('DB_USER', 'avnadmin'),
    'password': os.environ.get('DB_PASS', 'AVNS_ylo12PkuojgWJUOeqHs'),
    'database': os.environ.get('DB_NAME', 'defaultdb'),
    'port': int(os.environ.get('DB_PORT',27990))
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'abu-dhabi'  
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db():
    return mysql.connector.connect(**config)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def query_products():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
        rows = cursor.fetchall()
    finally:
        cursor.close()
        db.close()
    return rows

def get_product(product_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM products WHERE id=%s", (product_id,))
        row = cursor.fetchone()
    finally:
        cursor.close()
        db.close()
    return row


def last_block():
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM blockchain ORDER BY idx DESC LIMIT 1")
        b = cursor.fetchone()
    finally:
        cursor.close()
        db.close()
    return b

def compute_hash(prev_hash, data, timestamp):
    s = f"{prev_hash}|{data}|{timestamp}"
    return hashlib.sha256(s.encode()).hexdigest()

def append_block(data):
    prev = last_block()
    prev_hash = prev['hash'] if prev else '0'*64
    timestamp = datetime.utcnow().isoformat()
    new_hash = compute_hash(prev_hash, data, timestamp)
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO blockchain (data, prev_hash, hash) VALUES (%s, %s, %s)", (data, prev_hash, new_hash))
        db.commit()
    finally:
        cursor.close()
        db.close()
    return new_hash


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('username')
        email = request.form.get('email')
        raw_pw = request.form.get('password')

        if not (name and email and raw_pw):
            flash("Please fill all fields.", "danger")
            return redirect(url_for('register'))

        pw_hash = raw_pw

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                           (name, email, pw_hash, 'user'))
            db.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))
        finally:
            cursor.close()
            db.close()

    return render_template('register.html')

@app.before_request
def before_request():
    """Make cart item count available to all templates (DB-backed)."""
    g.cart_count = 0
    user_id = session.get('user_id')
    if user_id:
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("SELECT SUM(quantity) FROM cart WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            g.cart_count = int(row[0]) if row and row[0] else 0
        finally:
            cur.close()
            db.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
        user = cursor.fetchone()
        db.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role'] 

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index')) 

        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        session.pop(f"cart_{user_id}", None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('role', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
def index():
    products = query_products()
    return render_template('index.html', products=products)
@app.route('/adminindex')
def adminindex():
    products = query_products()
    return render_template('adminindex.html', products=products)

@app.route('/product/<int:pid>')
def product(pid):
    p = get_product(pid)
    if not p:
        flash("Product not found", "danger")
        return redirect(url_for('index'))
    return render_template('product.html', product=p)


def current_cart_key():
    if 'user_id' not in session:
        return None
    return f"cart_{session['user_id']}"

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash("Please log in to view your cart.", "warning")
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT c.id AS cart_id, p.id AS product_id, p.name, p.price, p.image, c.quantity,c.quantity as stock
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = %s
        """, (session['user_id'],))
        items = cursor.fetchall()
    finally:
        cursor.close()
        db.close()

    total = Decimal('0.00')
    for it in items:
        total += Decimal(str(it['price'])) * int(it['quantity'])

    return render_template('cart.html', items=items, total=total)

@app.route('/remove_from_cart/<int:cart_id>', methods=['POST'])
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        flash('You must log in first.', 'danger')
        return redirect(url_for('login'))

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM cart WHERE id = %s AND user_id = %s", (cart_id, session['user_id']))
        db.commit()
    finally:
        cur.close()
        db.close()

    flash('Item removed from cart.', 'success')
    return redirect(url_for('cart'))


@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        flash("You must log in to add items to your cart.", "warning")
        return redirect(url_for('login'))

    pid = request.form.get('product_id')
    try:
        qty = int(request.form.get('qty', 1))
    except:
        qty = 1

    if not pid:
        flash("Invalid product ID.", "danger")
        return redirect(request.referrer or url_for('index'))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE id = %s", (pid,))
    product = cursor.fetchone()

    if not product:
        db.close()
        flash("Product not found.", "danger")
        return redirect(request.referrer or url_for('index'))


    if product['stock'] <= 0:
        db.close()
        flash(f"'{product['name']}' is Sold Out!", "danger")
        return redirect(request.referrer or url_for('index'))

    cursor.execute("SELECT * FROM cart WHERE user_id = %s AND product_id = %s", (session['user_id'], pid))
    item = cursor.fetchone()

    if item:
        new_qty = item['quantity'] + qty
        if new_qty > product['stock']:
            new_qty = product['stock']
            flash(f"Only {product['stock']} '{product['name']}' available. Quantity updated in cart.", "info")
        cursor.execute("UPDATE cart SET quantity = %s WHERE id = %s", (new_qty, item['id']))
    else:
        cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)",
                       (session['user_id'], pid, min(qty, product['stock'])))

    db.commit()
    db.close()

    flash(f"'{product['name']}' added to your cart!", "success")
    return redirect(request.referrer or url_for('index'))


@app.route('/update_cart', methods=['POST'])
def update_cart():
    if 'user_id' not in session:
        flash('You must log in first.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        for key, value in request.form.items():
            if key.startswith('qty_'):
                cart_id = key.split('_', 1)[1]
                try:
                    qty = int(value)
                except:
                    qty = 0

                cur.execute("""
                    SELECT c.*, p.stock 
                    FROM cart c
                    JOIN products p ON c.product_id = p.id
                    WHERE c.id=%s AND c.user_id=%s
                """, (cart_id, user_id))
                item = cur.fetchone()
                if not item:
                    continue

                if qty <= 0:
                    cur.execute("DELETE FROM cart WHERE id=%s AND user_id=%s", (cart_id, user_id))
                elif qty > item['stock']:
                    qty = item['stock']  
                    cur.execute("UPDATE cart SET quantity=%s WHERE id=%s AND user_id=%s", (qty, cart_id, user_id))
                    flash(f"Quantity for '{item['product_id']}' adjusted to available stock ({item['stock']})", "info")
                else:
                    cur.execute("UPDATE cart SET quantity=%s WHERE id=%s AND user_id=%s", (qty, cart_id, user_id))

        db.commit()
    finally:
        cur.close()
        db.close()

    flash('Cart updated successfully.', 'success')
    return redirect(url_for('cart'))

@app.route('/clear_cart', methods=['POST'])
def clear_cart():
    if 'user_id' not in session:
        flash("You must log in first.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
    db.commit()
    db.close()

    cart_key = f"cart_{user_id}"
    session.pop(cart_key, None)

    flash("All items removed from your cart.", "info")
    return redirect(url_for('cart'))


@app.route('/delete_from_cart/<int:product_id>', methods=['POST'])
def delete_from_cart(product_id):
    if 'user_id' not in session:
        flash("Please log in.", "warning")
        return redirect(url_for('login'))

    cart_key = current_cart_key()
    cart = session.get(cart_key, {}) or {}
    pid_str = str(product_id)
    if pid_str in cart:
        cart.pop(pid_str, None)
        session[cart_key] = cart
        flash('Item removed from cart.', 'info')
    else:
        flash('Item not found in cart.', 'warning')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        flash("You must be logged in to checkout!", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']

    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT c.id AS cart_id, c.product_id, c.quantity, p.price
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = %s
            FOR UPDATE
        """, (user_id,))
        cart_rows = cursor.fetchall()

        if not cart_rows:
            flash("Cart empty!", "danger")
            return redirect(url_for('cart'))

        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('cart'))

        customer_name = user.get('username') or user.get('name') or request.form.get('name') or 'Unnamed'
        customer_email = user.get('email') or request.form.get('email') or ''

        total = Decimal('0.00')
        order_items = []
        for r in cart_rows:
            pid = r['product_id']
            qty = int(r['quantity'])
            cursor.execute("SELECT stock, price FROM products WHERE id=%s", (pid,))
            prod = cursor.fetchone()
            if not prod:
                db.rollback()
                flash(f"Product (id={pid}) not found.", "danger")
                return redirect(url_for('cart'))
            stock = int(prod['stock'])
            price = Decimal(str(prod['price']))
            if stock < qty:
                db.rollback()
                flash(f"Not enough stock for product id {pid}", "danger")
                return redirect(url_for('cart'))
            total += price * qty
            order_items.append((pid, qty, price))


        cursor.execute("INSERT INTO orders (customer_name, customer_email, total) VALUES (%s, %s, %s)",
                       (customer_name, customer_email, str(total)))
        order_id = cursor.lastrowid

        for pid, qty, price in order_items:
            cursor.execute("INSERT INTO order_items (order_id, product_id, qty, price) VALUES (%s,%s,%s,%s)",
                           (order_id, pid, qty, str(price)))
            cursor.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (qty, pid))

        cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))

        db.commit()
    except Exception as e:
        db.rollback()
        flash("Error processing order: " + str(e), "danger")
        return redirect(url_for('cart'))
    finally:
        cursor.close()
        db.close()

    data = f"order:{order_id}|customer:{customer_name}|total:{total}"
    new_hash = append_block(data)

    flash("Checkout successful! Order ID: {}".format(order_id), "success")
    return render_template('checkout_success.html', order_id=order_id, chain_hash=new_hash)


def admin_logged_in():
    return session.get('admin_logged_in', False)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session['admin_name'] = ADMIN_USERNAME
            flash("Welcome, admin", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid credentials", "danger")
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_name', None)
    flash("Admin logged out.", "info")
    return redirect(url_for('admin_login'))

@app.route('/admin')
def admin_dashboard():
    if not admin_logged_in():
        return redirect(url_for('admin_login'))
    products = query_products()
    return render_template('admin_dashboard.html', products=products)

@app.route('/admin/products')
def admin_products():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/product/new', methods=['GET', 'POST'])
def admin_product_new():
    if not admin_logged_in():
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        subcategory = request.form.get('subcategory')  
        price = request.form.get('price') or '0.00'
        stock = request.form.get('stock') or 0
        image_filename = None

        file = request.files.get('image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_filename = filename

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute("""
                INSERT INTO products (name, description, category, subcategory, price, stock, image)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (name, description, category, subcategory, price, stock, image_filename))
            db.commit()
            flash("Product added successfully!", "success")
            return redirect(url_for('admin_dashboard'))
        finally:
            cursor.close()
            db.close()

    return render_template('admin_product_form.html', action='Create', product={})


@app.route('/admin/product/<int:pid>/edit', methods=['GET', 'POST'])
def admin_product_edit(pid):
    if not admin_logged_in():
        return redirect(url_for('admin_login'))

    p = get_product(pid)
    if not p:
        flash("Product not found", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        subcategory = request.form.get('subcategory')
        price = request.form.get('price') or '0.00'
        stock = request.form.get('stock') or 0
        image_filename = p['image']

        file = request.files.get('image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_filename = filename

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute("""
                UPDATE products
                SET name=%s, description=%s, category=%s,subcategory=%s, price=%s, stock=%s, image=%s
                WHERE id=%s
            """, (name, description, category,subcategory, price, stock, image_filename, pid))
            db.commit()
            flash("Product updated successfully!", "success")
            return redirect(url_for('admin_dashboard'))
        finally:
            cursor.close()
            db.close()

    return render_template('admin_product_form.html', action='Edit', product=p)


@app.route('/admin/product/<int:pid>/delete', methods=['POST'])
def admin_product_delete(pid):
    if not admin_logged_in():
        return redirect(url_for('admin_login'))
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM products WHERE id=%s", (pid,))
        db.commit()
        flash("Product deleted", "info")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/orders')
def admin_orders():
    if not admin_logged_in():
        return redirect(url_for('admin_login'))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM orders ORDER BY created_at DESC")
        orders = cursor.fetchall()

        for order in orders:
            c2 = db.cursor(dictionary=True)
            try:
                c2.execute("""
                    SELECT oi.*, p.name AS product_name
                    FROM order_items oi
                    LEFT JOIN products p ON p.id = oi.product_id
                    WHERE oi.order_id = %s
                """, (order['id'],))
                order['items'] = c2.fetchall()
            finally:
                c2.close()

            c3 = db.cursor(dictionary=True)
            try:
                c3.execute("SELECT * FROM blockchain WHERE data LIKE %s ORDER BY timestamp DESC LIMIT 1", (f"%order:{order['id']}%",))
                order['block'] = c3.fetchone()
            finally:
                c3.close()
    finally:
        cursor.close()
        db.close()

    return render_template('admin_orders.html', orders=orders)

@app.route('/my_orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please log in to view your orders.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM orders WHERE customer_email=(SELECT email FROM users WHERE id=%s) ORDER BY created_at DESC", (user_id,))
        orders = cursor.fetchall()

        for order in orders:
            c2 = db.cursor(dictionary=True)
            try:
                c2.execute("""
                    SELECT oi.*, p.name AS product_name, p.image AS product_image
                    FROM order_items oi
                    LEFT JOIN products p ON p.id = oi.product_id
                    WHERE oi.order_id = %s
                """, (order['id'],))
                order['items'] = c2.fetchall()
            finally:
                c2.close()

            c3 = db.cursor(dictionary=True)
            try:
                c3.execute("SELECT * FROM blockchain WHERE data LIKE %s ORDER BY timestamp DESC LIMIT 1", (f"%order:{order['id']}%",))
                order['block'] = c3.fetchone()
            finally:
                c3.close()
    finally:
        cursor.close()
        db.close()

    return render_template('my_orders.html', orders=orders)


@app.route('/category/<category>')
def view_category(category):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE category=%s", (category,))
    products = cursor.fetchall()
    cursor.close()
    db.close()

    sub_map = {
        "Electronics": ["Laptop", "Cellphone", "Tablet", "Headphones", "Camera"],
        "Clothing": ["T-Shirts", "Pants", "Dresses", "Shoes", "Jackets"],
        "Accessories": ["Bags", "Watches", "Belts", "Hats"]
    }

    subcategories = sub_map.get(category, [])

    return render_template(
        "index.html",
        products=products,
        category=category,
        subcategories=subcategories
    )


@app.route('/category/<category>/<subcategory>')
def view_subcategory(category, subcategory):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM products WHERE category=%s AND subcategory=%s",
        (category, subcategory)
    )
    products = cursor.fetchall()
    cursor.close()
    db.close()

    sub_map = {
        "Electronics": ["Laptop", "Cellphone", "Tablet", "Headphones", "Camera"],
        "Clothing": ["T-Shirts", "Pants", "Dresses", "Shoes", "Jackets"],
        "Accessories": ["Bags", "Watches", "Belts", "Hats"]
    }

    subcategories = sub_map.get(category, [])

    return render_template(
        "index.html",
        products=products,
        category=category,
        subcategories=subcategories,
        selected_subcategory=subcategory
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
