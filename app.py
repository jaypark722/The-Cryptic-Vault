import os
import json
import csv
from flask import Flask, render_template, redirect, url_for, session, request, abort, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from sqlalchemy.exc import OperationalError
from collections import Counter
from datetime import datetime
import gnupg
import random
import time

app = Flask(__name__)

app.secret_key = 'your_super_secret_key_change_me'

basedir = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(basedir, 'database', 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gpg = gnupg.GPG()

ADMIN_ID = 1
HOT_LISTING_ID = 'DATA-SIM-ORANGE-CUST-B0T'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.String(50), default='₿0.00000')
    cart_json = db.Column(db.String(5000), default='[]')
    pgp_public_key = db.Column(db.Text, nullable=True)
    transaction_history_json = db.Column(db.Text, default='[]')

    messages_received = db.relationship('Message', backref='recipient', lazy='dynamic', foreign_keys='Message.recipient_id')
    orders = db.relationship('Order', backref='customer', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_username = db.Column(db.String(80), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Message {self.subject} to {self.recipient_id}>'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='PROCESSING')
    total_amount = db.Column(db.String(50), nullable=False)
    items_json = db.Column(db.Text, nullable=False)
    order_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    encrypted_delivery = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Order {self.id} - User {self.user_id}>'

def get_user_message_count(user_id):
    with app.app_context():
        try:
            user = User.query.get(user_id)
            if not user:
                return 0

            return Message.query.filter(
                Message.recipient_id == user_id,
                Message.is_read == False,
                Message.sender_username != user.username
            ).count()
        except OperationalError:
            return 0

def create_welcome_message(user_id, username, has_pgp):
    subject = "Welcome to THE CRYPTIC VAULT"
    pgp_reminder = ""
    if not has_pgp:
        pgp_reminder = ("\n\n🚨 **SECURITY WARNING:** We noticed you did not submit a PGP Public Key. "
                        "For your own safety and to guarantee privacy for all transaction details, "
                        "please set up PGP on your profile immediately. Unencrypted orders are placed at your own risk. ")
    else:
        pgp_reminder = ("\n\n✅ **PGP Verified:** Thank you for prioritizing security. Your account is PGP VERIFIED. "
                        "Please ensure you protect your private key at all times.")
    body = (f"Welcome, {username}.\n\n"
              "You have successfully registered a new Handler account on The Cryptic Vault. "
              "Your starting balance is now available for trade. "
              "Familiarize yourself with the Terms of Service and utilize the search and cart functions to begin procurement. "
              f"{pgp_reminder}\n\n"
              "The Cryptic Vault Administration")
    new_message = Message(
        recipient_id=user_id,
        sender_username='ADMIN',
        subject=subject,
        body=body
    )
    db.session.add(new_message)


def get_current_cart():
    if session.get('logged_in'):
        user = User.query.get(session['user_id'])
        if user:
            return json.loads(user.cart_json)
    return session.get('cart', [])

def update_current_cart(new_cart_list):
    if session.get('logged_in'):
        user = User.query.get(session['user_id'])
        if user:
            user.cart_json = json.dumps(new_cart_list)
            db.session.commit()
    else:
        session['cart'] = new_cart_list
        session.modified = True

def get_product_by_id(product_id):
    try:
        with app.open_resource('static/data/products.json', 'r') as f:
            data = json.load(f)
            for product in data:
                if product.get('Product ID') == product_id:
                    price_str = product.get('Price (BTC)', '₿0.00000').replace('₿', '')
                    try:
                        product['price_float'] = float(price_str)
                    except ValueError:
                        product['price_float'] = 0.0

                    random.seed(product_id)
                    random_score = round(random.uniform(4.3, 4.9), 1)
                    random_sales = random.randint(1000, 9999)
                    random.seed(None)

                    product['Vendor score'] = f"{random_score:.1f} / 5.0"
                    product['Sales'] = f"{random_sales:,}"
                    product['Vendor'] = product.get('Vendor Name', 'N/A')

                    return product
    except FileNotFoundError:
        print("ERROR: static/data/products.json not found.")
    except json.JSONDecodeError:
        print("ERROR: static/data/products.json is invalid JSON.")

    return None

def btc_to_float(btc_str):
    return float(btc_str.replace('₿', ''))

@app.route('/')
def index():
    hot_listing_product = get_product_by_id(HOT_LISTING_ID)
    return render_template('index.html', hot_listing=hot_listing_product)

@app.route('/listings')
def listings():
    return render_template('listings.html')

@app.route('/product/<string:product_id>')
def product_detail(product_id):
    product = get_product_by_id(product_id)

    if product is None:
        abort(404)

    return render_template('product_detail.html', product=product)

@app.route('/add_to_cart/<string:listing_id>', methods=['POST'])
def add_to_cart(listing_id):
    current_cart = get_current_cart()
    current_cart.append(listing_id)
    update_current_cart(current_cart)

    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart_items = get_current_cart()

    session['cart_count'] = len(cart_items)
    session.modified = True

    if not cart_items:
        return render_template('cart.html', cart_details=[], total_price='₿0.00000')

    item_counts = Counter(cart_items)
    cart_details = []
    total_btc = 0.0

    for item_id, qty in item_counts.items():
        if item_id == 'COUPON-REDTEAM':
            continue

        listing = get_product_by_id(item_id)
        if listing:
            item_price = listing.get('price_float', 0.0)
            item_name = listing.get('Product Name (Description)', 'Unknown Item')

            subtotal = item_price * qty
            total_btc += subtotal

            cart_details.append({
                'id': item_id,
                'name': item_name,
                'price': f'₿{item_price:.5f}',
                'qty': qty,
                'subtotal': f'₿{subtotal:.5f}'
            })

    if 'COUPON-REDTEAM' in item_counts:
        cart_details.append({
            'id': 'COUPON-REDTEAM',
            'name': 'REDTEAMBECODE Coupon Credit',
            'price': '₿0.00000',
            'qty': item_counts['COUPON-REDTEAM'],
            'subtotal': '₿0.00000'
        })


    total_price_formatted = f'₿{total_btc:.5f}'
    error_message = request.args.get('error')

    return render_template('cart.html',
                            cart_details=cart_details,
                            total_price=total_price_formatted,
                            error=error_message)

@app.route('/remove_from_cart/<string:listing_id>', methods=['POST'])
def remove_from_cart(listing_id):
    current_cart = get_current_cart()

    if listing_id in current_cart:
        try:
            current_cart.remove(listing_id)
            update_current_cart(current_cart)
        except ValueError:
            pass

    return redirect(url_for('cart'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        time.sleep(2.5)

        username = request.form['username']
        password = request.form['password']
        coupon = request.form.get('coupon', '')
        pgp_key = request.form.get('pgp_key', '').strip()

        if pgp_key:
            import_result = gpg.import_keys(pgp_key)

            if not import_result.results:
                return render_template('register.html', error='Invalid PGP Public Key format. Please submit a valid ASCII-armored key block.')

            try:
                for fingerprint in [r['fingerprint'] for r in import_result.results]:
                    gpg.delete_keys(fingerprint)
            except Exception as e:
                print(f"Warning: Failed to delete imported key: {e}")


        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already taken.')

        initial_balance = '₿0.000850' if coupon == 'REDTEAMBECODE' else '₿0.00000'
        transaction_history = []

        if coupon == 'REDTEAMBECODE':
            transaction_history.append({
                'type': 'DEPOSIT',
                'amount': initial_balance,
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': f'Coupon Code: {coupon}'
            })

        new_user = User(
            username=username,
            password=password,
            balance=initial_balance,
            pgp_public_key=pgp_key or None,
            transaction_history_json=json.dumps(transaction_history)
        )

        try:
            db.session.add(new_user)
            db.session.flush()

            create_welcome_message(new_user.id, new_user.username, bool(pgp_key))

            if coupon == 'REDTEAMBECODE':
                first_order = Order(
                    user_id=new_user.id,
                    total_amount='₿0.00000',
                    items_json=json.dumps(['COUPON-REDTEAM']),
                    status='DEPOSIT'
                )
                db.session.add(first_order)

            db.session.commit()

            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = new_user.id
            session['balance'] = initial_balance
            session['pgp_verified'] = bool(pgp_key)

            if session.get('cart'):
                db_cart = json.loads(new_user.cart_json)
                anonymous_cart = session.pop('cart')
                new_user.cart_json = json.dumps(db_cart + anonymous_cart)
                db.session.commit()

            session['cart_count'] = len(json.loads(new_user.cart_json))
            session['message_count'] = get_user_message_count(new_user.id)
            session['has_orders'] = Order.query.filter_by(user_id=new_user.id).count() > 0
            session.modified = True

            return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            return render_template('register.html', error=f'Database error: {e}')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            session['logged_in'] = True
            session['username'] = user.username
            session['user_id'] = user.id
            session['balance'] = user.balance
            session['pgp_verified'] = bool(user.pgp_public_key)

            if session.get('cart'):
                db_cart = json.loads(user.cart_json)
                anonymous_cart = session.pop('cart')
                user.cart_json = json.dumps(db_cart + anonymous_cart)
                db.session.commit()

            session['cart_count'] = len(json.loads(user.cart_json))
            session['message_count'] = get_user_message_count(user.id)
            session['has_orders'] = user.orders.count() > 0
            session.modified = True

            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error='Invalid credentials.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/change_password', methods=['POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)

    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if not user:
        return redirect(url_for('logout'))

    if user.password != current_password:
        return redirect(url_for('profile', error='Error: Incorrect current password.'))

    if new_password != confirm_password:
        return redirect(url_for('profile', error='Error: New passwords do not match.'))

    if len(new_password) < 8:
        return redirect(url_for('profile', error='Error: Password must be at least 8 characters long.'))

    try:
        user.password = new_password
        db.session.commit()
        return redirect(url_for('login', success_message='Password updated successfully. Please log in with your new password.'))
    except Exception as e:
        db.session.rollback()
        return redirect(url_for('profile', error=f'Database error: {e}'))

@app.route('/checkout', methods=['POST'])
def checkout():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if not user.pgp_public_key:
        return redirect(url_for('cart', error='ERROR: You must set a PGP Public Key in your profile to complete secure transactions.'))

    time.sleep(2.5)

    cart_items = get_current_cart()
    total_btc = 0.0

    purchased_items = [item_id for item_id in cart_items if item_id != 'COUPON-REDTEAM']

    for item_id in purchased_items:
        listing = get_product_by_id(item_id)
        if listing:
            total_btc += listing.get('price_float', 0.0)
        else:
            return redirect(url_for('cart', error=f'ERROR: Product {item_id} not found in listings.'))


    current_balance = btc_to_float(user.balance)

    if current_balance < total_btc:
        return redirect(url_for('cart', error='ERROR: Insufficient funds in your wallet to cover the transaction.'))

    new_balance_float = current_balance - total_btc
    user.balance = f'₿{new_balance_float:.5f}'


    new_order = Order(
        user_id=user.id,
        total_amount=f'₿{total_btc:.5f}',
        items_json=json.dumps(cart_items),
        status='PROCESSING',
        encrypted_delivery="Processing delivery... Please wait on the orders page."
    )
    db.session.add(new_order)


    transaction_history = json.loads(user.transaction_history_json)

    if total_btc > 0.0:
        transaction_history.append({
            'type': 'PURCHASE',
            'amount': f'-₿{total_btc:.5f}',
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'description': f'Purchase of {len(purchased_items)} item(s) (Order #{new_order.id})'
        })

    user.transaction_history_json = json.dumps(transaction_history)

    user.cart_json = '[]'
    db.session.commit()
    session['balance'] = user.balance
    session['cart_count'] = 0
    session['has_orders'] = True
    session.modified = True


    final_encrypted_content = None
    final_status = 'SHIPPED'

    if HOT_LISTING_ID in cart_items:
        try:
            file_name = 'orange.csv'
            file_path = os.path.join(app.root_path, 'static', 'data', file_name)

            product_records = []
            with open(file_path, 'r', encoding='latin-1') as f:
                csv_reader = csv.DictReader(f)
                for row in csv_reader:
                    product_records.append(row)

            product_content = json.dumps(product_records, indent=4)

            encrypted_result = gpg.encrypt(product_content, user.pgp_public_key)

            if encrypted_result.ok:
                final_encrypted_content = str(encrypted_result)
            else:
                final_encrypted_content = f"ERROR: PGP encryption of delivery failed. Check your public key. ({encrypted_result.status})"
                final_status = 'ERROR'

        except FileNotFoundError:
            final_encrypted_content = f"ERROR: Product file {file_name} not found on vendor system."
            final_status = 'ERROR'
        except Exception as e:
            final_encrypted_content = f"ERROR: System failed to process delivery (CSV/JSON error: {e})."
            final_status = 'ERROR'
    else:
        delivery_message = "Your order has been placed. Delivery details for items other than the Orange SIM are pending vendor fulfillment."
        encrypted_result = gpg.encrypt(delivery_message, user.pgp_public_key)

        if encrypted_result.ok:
            final_encrypted_content = str(encrypted_result)
        else:
            final_encrypted_content = "Generic Delivery Error"
            final_status = 'ERROR'


    with app.app_context():
        order_to_update = Order.query.get(new_order.id)
        if order_to_update:
            order_to_update.encrypted_delivery = final_encrypted_content
            order_to_update.status = final_status
            db.session.commit()


    return redirect(url_for('orders', success=f'Transaction successful! Order #{new_order.id} placed and processing initiated.'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    error_message = request.args.get('error')
    success_message = request.args.get('success')

    if not user:
        return redirect(url_for('logout'))

    if request.method == 'POST':
        pgp_key = request.form.get('pgp_key_submission', '').strip()

        if not pgp_key:
            error_message = 'Please paste a valid PGP Public Key to verify your account.'
        else:
            import_result = gpg.import_keys(pgp_key)

            if not import_result.results:
                error_message = 'Invalid PGP Public Key format. Please submit a valid ASCII-armored key block.'
            else:
                try:
                    for fingerprint in [r['fingerprint'] for r in import_result.results]:
                        gpg.delete_keys(fingerprint)
                except Exception as e:
                    print(f"Warning: Failed to delete imported key: {e}")

                user.pgp_public_key = pgp_key
                db.session.commit()

                session['pgp_verified'] = True
                success_message = 'PGP Public Key successfully saved and account is now VERIFIED.'

                return redirect(url_for('profile', success=success_message))

    pgp_verified = bool(user.pgp_public_key)
    pgp_status = 'VERIFIED' if pgp_verified else 'UNVERIFIED'
    pgp_color = 'text-green-500' if pgp_verified else 'text-red-500'

    session['pgp_verified'] = pgp_verified
    session['has_orders'] = user.orders.count() > 0
    session.modified = True

    user_data = {
        'username': session.get('username'),
        'balance': session.get('balance', '₿0.00000'),
        'pgp_key': user.pgp_public_key if user else 'No key on file.',
        'pgp_status': pgp_status,
        'pgp_color': pgp_color
    }

    return render_template('profile.html',
                            user_data=user_data,
                            error=error_message,
                            success=success_message)


@app.route('/orders')
def orders():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user_id = session['user_id']

    user_orders = Order.query.filter_by(user_id=user_id).order_by(desc(Order.order_date)).all()

    orders_data = []
    for order in user_orders:
        item_name = 'Multiple Items'
        item_id = 'N/A'
        item_qty = 0
        vendor_username = 'System'
        vendor_id = None

        try:
            item_ids = json.loads(order.items_json)
            item_qty = len(item_ids)

            if item_ids and item_ids[0] == 'COUPON-REDTEAM' and order.status == 'DEPOSIT' and item_qty == 1:
                continue

            if item_qty >= 1:
                display_id = item_ids[0]

                if display_id == 'COUPON-REDTEAM' and item_qty > 1:
                    display_id = item_ids[1]

                product = get_product_by_id(display_id)

                if product:
                    vendor_username = product.get('Vendor', 'Unknown Vendor')
                    vendor_id = None

                    item_name = product.get('Product Name (Description)', 'Unknown Item')
                    item_id = display_id

                    non_coupon_count = len([id for id in item_ids if id != 'COUPON-REDTEAM'])
                    if non_coupon_count > 1:
                        item_name = f"{item_name} (+{non_coupon_count - 1} more items)"
                    elif non_coupon_count == 1 and 'COUPON-REDTEAM' in item_ids:
                        item_name = f"{item_name} (w/ Coupon)"
                    elif non_coupon_count == 0 and 'COUPON-REDTEAM' in item_ids:
                        item_name = "Coupon Redemption Order"
                        vendor_username = 'ADMIN'

                elif display_id == 'COUPON-REDTEAM' and item_qty == 1:
                    item_name = "Coupon Redemption Order"
                    item_id = 'COUPON-REDTEAM'
                    vendor_username = 'ADMIN'
                else:
                    item_name = f"ERROR: Unknown Product ({display_id})"
                    item_id = display_id


        except (json.JSONDecodeError, TypeError) as e:
            item_name = f"Items List Corrupted"
            item_id = 'N/A'
            item_qty = len(item_ids) if 'item_ids' in locals() else 0


        has_delivery = order.status == 'SHIPPED' or order.status == 'ERROR'

        orders_data.append({
            'id': order.id,
            'display_id': f'54987{order.id}',  # <--- ADDED LINE FOR DISPLAY ID
            'date': order.order_date.strftime('%Y-%m-%d %H:%M:%S'),
            'total': order.total_amount,
            'status': order.status,
            'product_name': item_name,
            'product_id': item_id,
            'quantity': item_qty,
            'has_delivery': has_delivery,
            'encrypted_delivery': order.encrypted_delivery,
            'vendor_username': vendor_username,
            'vendor_id': vendor_id
        })

    error_message = request.args.get('error')
    success_message = request.args.get('success')

    return render_template('orders.html', orders=orders_data, error=error_message, success=success_message)


@app.route('/messages')
def messages():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user_id = session['user_id']
    username = session['username']

    messages = Message.query.filter(
        Message.recipient_id == user_id,
        Message.sender_username != username
    ).order_by(desc(Message.timestamp)).all()

    session['message_count'] = get_user_message_count(user_id)
    session.modified = True

    return render_template('messages.html', messages=messages)

@app.route('/mark_read/<int:message_id>')
def mark_read(message_id):
    if not session.get('logged_in'):
        return "Unauthorized", 401

    message = Message.query.get_or_404(message_id)
    if message.recipient_id != session['user_id']:
        return "Forbidden", 403

    if not message.is_read:
        message.is_read = True
        db.session.commit()

        session['message_count'] = get_user_message_count(session['user_id'])
        session.modified = True

    return "OK", 200

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if not session.get('logged_in'):
        flash('You must be logged in to perform this action.', 'error')
        return redirect(url_for('login'))

    message = Message.query.get_or_404(message_id)

    if message.recipient_id != session['user_id']:
        flash('You do not have permission to delete this message.', 'error')
        abort(403)

    db.session.delete(message)
    db.session.commit()

    session['message_count'] = get_user_message_count(session['user_id'])
    session.modified = True

    return redirect(url_for('messages'))

@app.route('/wallet')
def wallet():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    try:
        transaction_history = json.loads(user.transaction_history_json)
        transaction_history.reverse()
    except (json.JSONDecodeError, TypeError):
        transaction_history = []

    return render_template('wallet.html',
                            balance=user.balance,
                            history=transaction_history)

@app.route('/support', methods=['GET', 'POST'])
def support():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    error = None
    success = None

    if request.method == 'POST':
        subject = request.form.get('subject')
        body = request.form.get('body')

        if not subject or not body:
            error = 'Subject and body cannot be empty.'
        else:
            new_message = Message(
                recipient_id=ADMIN_ID,
                sender_username=session.get('username', 'System'),
                subject=f'[SUPPORT] {subject}',
                body=f"From User ID {session['user_id']} ({session['username']}):\n\n{body}"
            )
            try:
                db.session.add(new_message)
                db.session.commit()
                success = "Support ticket submitted. An administrator will respond via secure message shortly."
            except Exception as e:
                db.session.rollback()
                error = f"Failed to submit ticket due to database error: {e}"

        return redirect(url_for('support', success=success, error=error))

    error_message = request.args.get('error')
    success_message = request.args.get('success')

    return render_template('support.html', error=error_message, success=success_message)

@app.route('/vendor', methods=['GET', 'POST'])
def vendor():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    error = None
    success = None

    if request.method == 'POST':
        specialty = request.form.get('specialty')
        reason = request.form.get('reason')

        if not specialty or not reason:
            error = 'All fields are required for the vendor application.'
        else:
            new_message = Message(
                recipient_id=ADMIN_ID,
                sender_username=session.get('username', 'System'),
                subject=f'[VENDOR APPLICATION] {specialty}',
                body=(f"User ID {session['user_id']} ({session['username']}) is applying to be a vendor.\n\n"
                      f"Specialty: {specialty}\n\n"
                      f"Reason/Experience:\n{reason}")
            )
            try:
                db.session.add(new_message)
                db.session.commit()
                success = "Vendor application submitted. An administrator will contact you via secure message."
            except Exception as e:
                db.session.rollback()
                error = f"Failed to submit application due to database error: {e}"

        return redirect(url_for('vendor', success=success, error=error))

    error_message = request.args.get('error')
    success_message = request.args.get('success')
    return render_template('vendor.html', error=error_message, success=success_message)

@app.route('/vendor_profile/<int:vendor_id>')
def vendor_profile(vendor_id):
    return render_template('vendor.html')

@app.errorhandler(404)
def page_not_found(e):
    return "404 Not Found - Custom Handler", 404

if __name__ == '__main__':
    with app.app_context():
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        db.create_all()