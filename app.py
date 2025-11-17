import os
import json
import csv
import textwrap
import threading
from flask import Flask, render_template, redirect, url_for, session, request, abort, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from sqlalchemy.exc import OperationalError
from collections import Counter
from datetime import datetime
import gnupg
import random
import time
import qrcode
from io import BytesIO
import base64

# Import the honeypot logger
from honeypot_logger import HoneypotLogger, log_page_view
from profiler import ProfileEngine

# Feature flags / config
ENABLE_GPT5 = os.environ.get('ENABLE_GPT5', '1').lower() in ('1', 'true', 'yes', 'on')

app = Flask(__name__)

app.secret_key = 'your_super_secret_key_change_me'

basedir = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(basedir, 'database', 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Expose feature flags to all templates
@app.context_processor
def inject_feature_flags():
    return {
        'ENABLE_GPT5': ENABLE_GPT5,
    }

# Initialize the honeypot logger
logger = HoneypotLogger(db_path=os.path.join(basedir, 'database', 'honeypot_logs.db'))

# Initialize GPG with a specific home directory for key storage
gpg_home = os.path.join(basedir, 'gpg_home')
os.makedirs(gpg_home, exist_ok=True)
gpg = gnupg.GPG(gnupghome=gpg_home)

ADMIN_ID = 1
HOT_LISTING_ID = 'DATA-SIM-CRYPTIC-CUST-B0T'

# Bitcoin Testnet Deposit Lure Configuration
FAKE_BTC_ADDRESS = 'tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'  # Bitcoin Testnet address

# Application-wide coupon code
NEW_COUPON_CODE = "rumblyinmytumbly"

def generate_qr_code(data):
    """Generate a QR code and return as base64 encoded data URI"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.String(50), default='₿0.00000')
    cart_json = db.Column(db.String(5000), default='[]')
    pgp_public_key = db.Column(db.Text, nullable=True)
    transaction_history_json = db.Column(db.Text, default='[]')
    pending_deposit = db.Column(db.Boolean, default=False)

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

def validate_pgp_key(pgp_key_text):
    """
    Validates and imports a PGP public key.
    Returns (success: bool, message: str, fingerprint: str or None)
    """
    if not pgp_key_text or not pgp_key_text.strip():
        return False, "PGP key cannot be empty.", None
    
    if '-----BEGIN PGP PUBLIC KEY BLOCK-----' not in pgp_key_text:
        return False, "Invalid PGP key format. Must contain BEGIN PGP PUBLIC KEY BLOCK.", None
    
    if '-----END PGP PUBLIC KEY BLOCK-----' not in pgp_key_text:
        return False, "Invalid PGP key format. Must contain END PGP PUBLIC KEY BLOCK.", None
    
    import_result = gpg.import_keys(pgp_key_text)
    
    if import_result.count == 0:
        return False, "Failed to import PGP key. Please verify the key is valid.", None
    
    fingerprint = import_result.fingerprints[0] if import_result.fingerprints else None
    
    if not fingerprint:
        return False, "Key imported but fingerprint could not be retrieved.", None
    
    return True, "PGP key successfully validated and imported.", fingerprint

def encrypt_message_for_user(user, plaintext_message):
    """
    Encrypts a plaintext message using the user's PGP public key.
    Returns (success: bool, encrypted_message: str or error_message: str)
    """
    if not user.pgp_public_key:
        return False, "User does not have a PGP public key on file."
    
    import_result = gpg.import_keys(user.pgp_public_key)
    
    if import_result.count == 0:
        return False, "Failed to import user's PGP public key for encryption."
    
    fingerprint = import_result.fingerprints[0] if import_result.fingerprints else None
    
    if not fingerprint:
        return False, "Could not retrieve fingerprint from user's PGP key."
    
    encrypted_data = gpg.encrypt(plaintext_message, fingerprint, always_trust=True)
    
    if not encrypted_data.ok:
        return False, f"Encryption failed: {encrypted_data.status}"
    
    return True, str(encrypted_data)

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
                    
                    if product_id == HOT_LISTING_ID:
                        random_score = 4.8
                    else:
                        random_score = round(random.uniform(2.9, 4.8), 1)
                        random_score = min(random_score, 4.8)

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
@log_page_view(logger)
def index():
    hot_listing_product = get_product_by_id(HOT_LISTING_ID)
    return render_template('index.html', hot_listing=hot_listing_product)

@app.route('/listings')
@log_page_view(logger)
def listings():
    return render_template('listings.html')

@app.route('/product/<string:product_id>')
def product_detail(product_id):
    product = get_product_by_id(product_id)

    if product is None:
        abort(404)

    logger.log_event('PRODUCT_VIEW', product_id=product_id, additional_data={
        'product_name': product.get('Product Name (Description)'),
        'price': product.get('Price (BTC)'),
        'vendor': product.get('Vendor')
    })

    return render_template('product_detail.html', product=product)

@app.route('/add_to_cart/<string:listing_id>', methods=['POST'])
def add_to_cart(listing_id):
    current_cart = get_current_cart()
    current_cart.append(listing_id)
    update_current_cart(current_cart)

    logger.log_event('CART_ADD', product_id=listing_id)

    return redirect(url_for('cart'))

@app.route('/cart')
@log_page_view(logger)
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
            'name': f'{NEW_COUPON_CODE} Coupon Credit',
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
            
            logger.log_event('CART_REMOVE', product_id=listing_id)
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
        confirm_password = request.form.get('confirm_password', '')
        coupon = request.form.get('coupon', '')
        pgp_key = request.form.get('pgp_key', '').strip()

        pgp_valid = False
        pgp_error = None
        if pgp_key:
            is_valid, message, fingerprint = validate_pgp_key(pgp_key)
            if not is_valid:
                return render_template('register.html', error=f'PGP Key Error: {message}')
            pgp_valid = True

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already taken.')

        # Password confirmation validation
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match.')

        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters long.')

        initial_balance = '₿0.000850' if coupon == NEW_COUPON_CODE else '₿0.00000'
        transaction_history = []

        if coupon == NEW_COUPON_CODE:
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
            pgp_public_key=pgp_key if pgp_valid else None,
            transaction_history_json=json.dumps(transaction_history),
            pending_deposit=False
        )

        try:
            db.session.add(new_user)
            db.session.flush()

            create_welcome_message(new_user.id, new_user.username, pgp_valid)

            if coupon == NEW_COUPON_CODE:
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
            session['pgp_verified'] = pgp_valid

            if session.get('cart'):
                db_cart = json.loads(new_user.cart_json)
                anonymous_cart = session.pop('cart')
                new_user.cart_json = json.dumps(db_cart + anonymous_cart)
                db.session.commit()

            session['cart_count'] = len(json.loads(new_user.cart_json))
            session['message_count'] = get_user_message_count(new_user.id)
            session['has_orders'] = Order.query.filter_by(user_id=new_user.id).count() > 0
            session.modified = True

            logger.log_event('REGISTER', additional_data={
                'username': username,
                'used_coupon': coupon == NEW_COUPON_CODE,
                'pgp_verified': pgp_valid
            })

            return redirect(url_for('profile'))

        except Exception as e:
            db.session.rollback()
            return render_template('register.html', error=f'Database error: {e}')

    logger.log_event('PAGE_VIEW', additional_data={'page': 'register'})
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

            logger.log_event('LOGIN', additional_data={
                'username': username,
                'user_id': user.id
            })

            return redirect(url_for('profile'))
        else:
            logger.log_event('LOGIN_FAILED', additional_data={
                'username': username
            })
            return render_template('login.html', error='Invalid credentials.')

    logger.log_event('PAGE_VIEW', additional_data={'page': 'login'})
    return render_template('login.html')

@app.route('/logout')
def logout():
    logger.log_event('LOGOUT', additional_data={
        'username': session.get('username')
    })
    
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
        
        logger.log_event('PASSWORD_CHANGE', additional_data={
            'user_id': user_id
        })
        
        return redirect(url_for('login', success_message='Password updated successfully. Please log in with your new password.'))
    except Exception as e:
        db.session.rollback()
        return redirect(url_for('profile', error=f'Database error: {e}'))


@app.route('/order')
def order_page():
    """Render the checkout/order page where users can review cart, apply coupon, and confirm purchase."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    cart_items = get_current_cart()

    # Build cart details (reuse cart logic)
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
            'name': f'{NEW_COUPON_CODE} Coupon Credit',
            'price': '₿0.00000',
            'qty': item_counts['COUPON-REDTEAM'],
            'subtotal': '₿0.00000'
        })

    total_price_formatted = f'₿{total_btc:.5f}'

    # Determine whether the hot/bait listing is present in this cart
    is_bait = HOT_LISTING_ID in cart_items

    error_message = request.args.get('error')
    success_message = request.args.get('success')

    return render_template('order.html',
                           cart_details=cart_details,
                           total_price=total_price_formatted,
                           is_bait=is_bait,
                           error=error_message,
                           success=success_message)


@app.route('/apply_coupon', methods=['POST'])
def apply_coupon():
    """Process coupon submissions from the cart page and update user's balance if valid."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    try:
        coupon = request.form.get('coupon', '').strip()
        if not coupon:
            return redirect(url_for('cart', error='No coupon code provided.'))

        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))

        # Parse transaction history safely
        transaction_history = json.loads(user.transaction_history_json or '[]')
        
        # Prevent reuse of the same coupon on the same account
        already_used = any((t.get('description', '') == f'Coupon Code: {coupon}') for t in transaction_history)

        if coupon == NEW_COUPON_CODE:
            if already_used:
                return redirect(url_for('cart', error='Coupon has already been redeemed on this account.'))

            try:
                # Safely convert and calculate new balance
                add_amount = 0.00085
                current_balance = btc_to_float(user.balance)
                new_balance = current_balance + add_amount
                user.balance = f'₿{new_balance:.5f}'

                # Record transaction history
                transaction_history.append({
                    'type': 'DEPOSIT',
                    'amount': f'₿{add_amount:.5f}',
                    'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'description': f'Coupon Code: {coupon}'
                })

                user.transaction_history_json = json.dumps(transaction_history)
                db.session.commit()

                session['balance'] = user.balance
                session.modified = True

                logger.log_event('COUPON_APPLIED', additional_data={
                            'username': user.username,
                    'coupon': coupon
                })

                return redirect(url_for('cart', success='Coupon applied successfully.'))

            except ValueError as ve:
                # Handle balance conversion errors
                logger.log_event('COUPON_ERROR', additional_data={
                    'error': str(ve),
                    'user_id': user.id,
                    'balance': user.balance
                })
                return redirect(url_for('cart', error='Error processing coupon. Please try again.'))

        # Invalid coupon code
        return redirect(url_for('cart', error='Invalid coupon code.'))

    except Exception as e:
        # Log the full error for debugging
        logger.log_event('COUPON_ERROR', additional_data={
            'error': str(e),
            'user_id': user.id if user else None,
            'coupon': coupon
        })
        app.logger.error(f"Coupon application error: {str(e)}")
        return redirect(url_for('cart', error='An error occurred while processing your coupon.'))

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
        status='PENDING',  # Start with PENDING, will update to SHIPPED only for bait item
        encrypted_delivery=None  # Initialize as None, only set for bait item
    )
    db.session.add(new_order)
    db.session.flush()

    # Build a human-friendly order reference that will be shown to users
    # and shared across all per-item history entries for this transaction.
    order_ref = f'54987{new_order.id}'

    # Build per-item transaction history entries (one entry per unique item in the cart)
    transaction_history = json.loads(user.transaction_history_json or '[]')

    # Count items so we can create one record per unique item with quantity
    item_counts = Counter(purchased_items)

    # Track per-item logging for the honeypot logger as well
    total_logged_items = 0
    per_item_totals = []

    for item_id, qty in item_counts.items():
        # Skip explicit coupon placeholder rows in purchase history - they are handled separately
        if item_id == 'COUPON-REDTEAM':
            continue

        listing = get_product_by_id(item_id)
        if listing:
            item_price = listing.get('price_float', 0.0)
            item_total = item_price * qty
            per_item_totals.append(item_total)

            # Compose a distinct transaction history entry for this item
            th_entry = {
                'type': 'PURCHASE',
                'amount': f'-₿{item_total:.5f}',
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': f'Order #{order_ref} - {listing.get("Product Name (Description)", "Unknown")} x{qty}',
                'order_id': order_ref,
                'product_id': item_id,
                'qty': qty
            }

            # Insert at the front so new purchases appear first
            transaction_history.insert(0, th_entry)

            # Log a per-item event to honeypot_logs.db for auditing
            logger.log_event('PURCHASE_ITEM', product_id=item_id, additional_data={
                'order_ref': order_ref,
                'price_each': f'₿{item_price:.5f}',
                'qty': qty,
                'item_total': f'₿{item_total:.5f}',
                'username': user.username
            })

            total_logged_items += qty
        else:
            # Unknown product - still record an entry so the audit trail is complete
            th_entry = {
                'type': 'PURCHASE',
                'amount': f'-₿0.00000',
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'description': f'Order #{order_ref} - Unknown Product ({item_id}) x{qty}',
                'order_id': order_ref,
                'product_id': item_id,
                'qty': qty
            }
            transaction_history.insert(0, th_entry)
            logger.log_event('PURCHASE_ITEM', product_id=item_id, additional_data={
                'order_ref': order_ref,
                'price_each': '₿0.00000',
                'qty': qty,
                'item_total': '₿0.00000',
                'username': user.username
            })

    # If the cart also included coupon placeholders, optionally record that info
    if 'COUPON-REDTEAM' in Counter(purchased_items):
        # Add a descriptive coupon usage entry but do not treat as a purchased product
        coupon_qty = Counter(purchased_items)['COUPON-REDTEAM']
        transaction_history.insert(0, {
            'type': 'COUPON',
            'amount': '₿0.00000',
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'description': f'Order #{order_ref} - Coupon usage x{coupon_qty}',
            'order_id': order_ref,
            'product_id': 'COUPON-REDTEAM',
            'qty': coupon_qty
        })

    # Persist transaction history and clear the user's cart
    user.transaction_history_json = json.dumps(transaction_history)
    user.cart_json = '[]'
    db.session.commit()

    # Update session state
    session['balance'] = user.balance
    session['cart_count'] = 0
    session['has_orders'] = True
    session.modified = True

    # Log a higher-level purchase event for the overall transaction
    logger.log_event('PURCHASE', additional_data={
        'order_ref': order_ref,
        'order_id': new_order.id,
        'total': f'₿{total_btc:.5f}',
        'unique_items': len(item_counts),
        'items_count': total_logged_items,
        'contains_bait': HOT_LISTING_ID in cart_items,
        'items': cart_items
    })

    final_encrypted_content = None
    # Default to PENDING for non-bait items; only the HOT_LISTING_ID (bait) will be set to SHIPPED
    final_status = 'PENDING'
    prefixed_order_id = f'54987{new_order.id}'

    # Check if this is a bait item purchase (Cryptic Customer Credential Database)
    if HOT_LISTING_ID in cart_items:
        try:
            file_name = 'cryptic.xlsx'
            file_path = os.path.join(app.root_path, 'static', 'data', file_name)

            if not os.path.exists(file_path):
                raise FileNotFoundError

            # For bait items, set status to SHIPPED and provide encrypted delivery
            final_status = 'SHIPPED'  # Mark as shipped only for bait item
            # Build an authenticated download link that routes through our
            # /download/delivery/<token> endpoint so that downloads are logged.
            try:
                download_token = f"ORDER-{new_order.id}"
                download_url = url_for('download_delivery', token=download_token, _external=True)
            except Exception:
                # Fallback to a relative static path if url_for is unavailable
                download_url = f"/static/data/cryptic.xlsx"

            plaintext_message = f"""Order Fulfillment Status: Completed
Item: Cryptic Customer Credential Database
Your secure download link is:
{download_url}
"""

            success, encrypted_or_error = encrypt_message_for_user(user, plaintext_message)

            if success:
                final_encrypted_content = encrypted_or_error
            else:
                final_encrypted_content = f"ERROR: Encryption failed - {encrypted_or_error}. Contact support with order ID #{prefixed_order_id}."
                final_status = 'ERROR'

        except FileNotFoundError:
            final_encrypted_content = f"ERROR: Product file {file_name} not found on vendor system. Contact support with order ID #{prefixed_order_id}."
            final_status = 'ERROR'
        except Exception as e:
            safe_error_msg = str(e).encode('ascii', errors='replace').decode('ascii')
            final_encrypted_content = f"ERROR: System failed to process delivery ({safe_error_msg}). Contact support."
            final_status = 'ERROR'
    else:
        # Non-bait products should remain PENDING and should not receive a delivery message or download link.
        # Keep encrypted_delivery minimal or empty; delivery will be handled by vendor later.
        final_encrypted_content = None
        final_status = 'PENDING'

    with app.app_context():
        order_to_update = Order.query.get(new_order.id)
        if order_to_update:
            order_to_update.encrypted_delivery = final_encrypted_content
            order_to_update.status = final_status
            db.session.commit()

    return redirect(url_for('orders', success=f'Transaction successful! Order #{prefixed_order_id} placed and processing initiated.'))

@app.route('/download/delivery/<string:token>')
def download_delivery(token):
    if not token.startswith('ORDER-') or not token[6:].isdigit():
        return "Invalid download token.", 403
    
    order_id = int(token[6:])
    order = Order.query.get(order_id)
    
    if not session.get('logged_in') or not order or order.user_id != session['user_id']:
        return "Unauthorized access or invalid order token.", 403

    order_items = json.loads(order.items_json)
    if HOT_LISTING_ID not in order_items:
        return "Download not available for this product.", 403

    if order.status not in ['SHIPPED', 'DELIVERED']:
        return "Delivery is not finalized yet. Decrypt the message for status updates.", 403
    
    file_name = 'cryptic.xlsx'
    file_path = os.path.join(app.root_path, 'static', 'data', file_name)
    
    if not os.path.exists(file_path):
        return "File not found on server.", 404

    logger.log_event('DOWNLOAD', product_id=HOT_LISTING_ID, additional_data={
        'order_id': order_id,
        'file_name': file_name,
        'download_token': token,
        'user_id': session.get('user_id'),
        'username': session.get('username')
    })

    return send_file(file_path, 
                     as_attachment=True, 
                     download_name=file_name,
                     mimetype='text/csv')


@app.route('/profile', methods=['GET', 'POST'])
@log_page_view(logger)
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
            is_valid, message, fingerprint = validate_pgp_key(pgp_key)
            
            if not is_valid:
                error_message = f'PGP Key Validation Failed: {message}'
            else:
                user.pgp_public_key = pgp_key
                db.session.commit()

                session['pgp_verified'] = True
                success_message = f'PGP Public Key successfully validated and saved. Your account is now VERIFIED.'
                
                logger.log_event('PGP_VERIFIED', additional_data={
                    'user_id': user.id,
                    'username': user.username
                })

            return redirect(url_for('profile', success=success_message, error=error_message))

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
@log_page_view(logger)
def orders():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user_id = session['user_id']

    # Prefer showing per-item PURCHASE entries from the user's transaction history
    orders_data = []

    user = User.query.get(user_id)
    if user:
        try:
            tx_history = json.loads(user.transaction_history_json or '[]')
        except Exception:
            tx_history = []

        for tx in tx_history:
            # Only consider PURCHASE entries that were created during checkout
            if tx.get('type') != 'PURCHASE' or not tx.get('order_id'):
                continue

            display_id = tx.get('order_id')
            # Try to extract numeric order id (we prefix with '54987' when creating orders)
            order_db_id = None
            if isinstance(display_id, str) and display_id.startswith('54987') and display_id[5:].isdigit():
                try:
                    order_db_id = int(display_id[5:])
                except Exception:
                    order_db_id = None

            order_obj = Order.query.get(order_db_id) if order_db_id else None

            status = order_obj.status if order_obj else 'PENDING'
            has_delivery = status in ('SHIPPED', 'ERROR')
            encrypted_delivery = order_obj.encrypted_delivery if order_obj else None

            product_id = tx.get('product_id', 'N/A')
            qty = tx.get('qty', 1)
            amount = tx.get('amount', '')
            date = tx.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

            product_name = 'Unknown Item'
            vendor_username = 'System'
            vendor_id = None

            product = get_product_by_id(product_id)
            if product:
                product_name = product.get('Product Name (Description)', product_name)
                vendor_username = product.get('Vendor', vendor_username)
            elif product_id == 'COUPON-REDTEAM':
                product_name = 'Coupon Redemption'
                vendor_username = 'ADMIN'

            orders_data.append({
                'id': order_db_id or display_id,
                'display_id': display_id,
                'date': date,
                'total': amount,
                'status': status,
                'product_name': product_name,
                'product_id': product_id,
                'quantity': qty,
                'has_delivery': has_delivery,
                'encrypted_delivery': encrypted_delivery,
                'vendor_username': vendor_username,
                'vendor_id': vendor_id
            })

    # Fallback: if no per-item purchases found, fall back to the original order aggregation
    if not orders_data:
        user_orders = Order.query.filter_by(user_id=user_id).order_by(desc(Order.order_date)).all()
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
                'display_id': f'54987{order.id}', 
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
@log_page_view(logger)
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

@app.route('/_message_count')
def _message_count():
    """Return the current message count as JSON for AJAX polling."""
    if not session.get('logged_in'):
        return jsonify({'count': 0})
    
    count = get_user_message_count(session['user_id'])
    return jsonify({'count': count})

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


@app.route('/wallet', methods=['GET', 'POST'])
@log_page_view(logger)
def wallet():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        amount_sent = request.form.get('amount_sent', '0.00000')
        
        try:
            amount_float = float(amount_sent.replace('₿', ''))
            if amount_float <= 0:
                flash('Invalid amount. Please enter a positive value.', 'error')
                return redirect(url_for('wallet'))
        except ValueError:
            flash('Invalid amount format. Please enter a valid BTC amount.', 'error')
            return redirect(url_for('wallet'))
        
        transaction_history = json.loads(user.transaction_history_json)
        
        pending_deposit_entry = {
            'type': 'DEPOSIT',
            'amount': amount_float,  # Store raw float value without Bitcoin symbol
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'description': f'Pending - Awaiting 3 confirmations',
            'status': 'PENDING'
        }
        
        print(f"DEBUG: Creating pending deposit entry: {pending_deposit_entry}")
        
        transaction_history.insert(0, pending_deposit_entry)
        user.transaction_history_json = json.dumps(transaction_history)
        
        user.pending_deposit_amount = amount_float  # Already storing raw float
        
        user.pending_deposit = True
        db.session.commit()
        
        print(f"DEBUG: Saved transaction history: {user.transaction_history_json}")
        
        logger.log_event('DEPOSIT_ATTEMPT', additional_data={
            'user_id': user.id,
            'username': user.username,
            'amount_claimed': f'₿{amount_float:.5f}',
            'btc_address': FAKE_BTC_ADDRESS,
            'timestamp': datetime.now().isoformat()
        })
        
        flash('Deposit initiated. Awaiting blockchain confirmation (3 confirmations required).', 'success')
        return redirect(url_for('wallet'))
    # If GET, render the wallet page with transaction history and QR code
    transaction_history = []
    try:
        transaction_history = json.loads(user.transaction_history_json or '[]')
    except Exception:
        transaction_history = []

    qr_code_data_uri = generate_qr_code(FAKE_BTC_ADDRESS)
    logger.log_event('PAGE_VIEW', additional_data={'page': 'wallet'})

    return render_template('wallet.html',
                           user=user,
                           balance=user.balance,
                           btc_address=FAKE_BTC_ADDRESS,
                           qr_code_url=qr_code_data_uri,
                           transactions=transaction_history)

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
                
                logger.log_event('SUPPORT_TICKET', additional_data={
                    'subject': subject,
                    'user_id': session['user_id']
                })
            except Exception as e:
                db.session.rollback()
                error = f"Failed to submit ticket due to database error: {e}"

            return redirect(url_for('support', success=success, error=error))

    error_message = request.args.get('error')
    success_message = request.args.get('success')
    
    logger.log_event('PAGE_VIEW', additional_data={'page': 'support'})

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
                
                # Capture user_id before starting background thread (session not available in thread)
                user_id = session['user_id']
                
                # Send automated response message to user's inbox with coupon code (after delay)
                # Run in background thread so it doesn't block the response
                def send_delayed_message(recipient_id):
                    time.sleep(5)  # 5 second delay
                    with app.app_context():
                        try:
                            message_body = textwrap.dedent(f"""Thank you for submitting your Vendor Request. Your application will be processed and reviewed by our administration team as quickly as possible. We will contact you regarding next steps.

In the meantime, please enjoy this welcome gift: a coupon voucher for a highly sought-after item on the marketplace!

**Your Coupon Code: {NEW_COUPON_CODE}**

Use it wisely.""").strip()
                            
                            user_message = Message(
                                recipient_id=recipient_id,
                                sender_username='System',
                                subject='Vendor Request Received - Your Welcome Gift!',
                                body=message_body,
                                is_read=False  # CRITICAL: Ensures unread status for frontend notification
                            )
                            db.session.add(user_message)
                            db.session.commit()
                            app.logger.info(f"Automated vendor message sent to user_id={recipient_id}")
                            
                        except Exception as e:
                            db.session.rollback()
                            app.logger.error(f"Failed to send automated vendor response: {e}")
                
                # Start background thread to send message after delay
                thread = threading.Thread(target=send_delayed_message, args=(user_id,))
                thread.daemon = True
                thread.start()
                
                success = "Vendor application submitted. An administrator will contact you via secure message."
                
                logger.log_event('VENDOR_APPLICATION', additional_data={
                    'specialty': specialty,
                    'user_id': session['user_id']
                })
            except Exception as e:
                db.session.rollback()
                error = f"Failed to submit application due to database error: {e}"

            return redirect(url_for('vendor', success=success, error=error))

    error_message = request.args.get('error')
    success_message = request.args.get('success')
    
    logger.log_event('PAGE_VIEW', additional_data={'page': 'vendor'})
    
    return render_template('vendor.html', error=error_message, success=success_message)

@app.route('/vendor_profile/<int:vendor_id>')
def vendor_profile(vendor_id):
    return f"Vendor Profile for ID {vendor_id} - Route stub."


@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard to view honeypot logs"""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)
    
    # Web sessions and events
    sessions = logger.get_all_sessions(limit=50)
    recent_events = logger.get_all_events(limit=100)
    
    # SSH sessions and commands
    ssh_sessions = logger.get_all_ssh_sessions(limit=50)
    ssh_commands = logger.get_ssh_commands(limit=100)

    # Profiling / aggregated activity summaries
    profiles = logger.get_activity_profiles(limit=10)

    # Predict attacker profiles for SSH sessions using ProfileEngine
    profile_engine = ProfileEngine(logger=logger)
    # Attempt to load any persisted model if present (non-fatal)
    try:
        profile_engine.load_model(os.path.join(basedir, 'database', 'profiler_model.pkl'))
    except Exception:
        pass

    ssh_predictions = profile_engine.predict_for_ssh_sessions(ssh_sessions)
    
    total_sessions = len(sessions)
    total_downloads = sum(1 for s in sessions if s['downloads_attempted'] > 0)
    total_purchases = sum(1 for s in sessions if s['purchases_made'] > 0)
    total_registrations = sum(1 for s in sessions if s['registered'])
    
    stats = {
        'total_sessions': total_sessions,
        'total_downloads': total_downloads,
        'total_purchases': total_purchases,
        'total_registrations': total_registrations,
        'total_events': sum(s['total_events'] for s in sessions),
        'total_ssh_sessions': len(ssh_sessions),
        'total_ssh_commands': len(ssh_commands)
    }
    
    pending_deposits = User.query.filter_by(pending_deposit=True).all()
    pending_deposits_data = []
    for user in pending_deposits:
        try:
                # Safely obtain the claimed amount: prefer transaction history 'amount',
                # fall back to a user attribute if present, else 0.0
                tx_history = json.loads(user.transaction_history_json or '[]')
                pending_tx = next((tx for tx in tx_history if tx.get('status') == 'PENDING'), None)

                claimed_amount_float = None
                if pending_tx and 'amount' in pending_tx:
                    claimed_amount_float = pending_tx.get('amount')
                else:
                    # use getattr to avoid AttributeError if the column doesn't exist
                    claimed_amount_float = getattr(user, 'pending_deposit_amount', None)

                if claimed_amount_float is None:
                    claimed_amount_float = 0.0

                # Normalize string amounts (strip any currency symbol) to float
                if isinstance(claimed_amount_float, str):
                    try:
                        claimed_amount_float = float(claimed_amount_float.replace('₿', ''))
                    except Exception:
                        claimed_amount_float = 0.0

                # Get current balance as raw float
                try:
                    current_balance = float(user.balance.replace('₿', '')) if isinstance(user.balance, str) else float(user.balance or 0.0)
                except Exception:
                    current_balance = 0.0

                pending_deposits_data.append({
                    'user_id': user.id,
                    'username': user.username,
                    'current_balance': f'₿{current_balance:.5f}',
                    'pending_since': pending_tx.get('date') if pending_tx else datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'claimed_amount_display': f'₿{claimed_amount_float:.5f}',
                    'claimed_amount_raw': claimed_amount_float
                })
        except Exception as e:
            print(f"Error processing pending deposit for user {user.id}: {e}")
            pass
    
    # Debug: print pending deposits data to server logs to verify template input
    print(f"DEBUG: pending_deposits_data (count={len(pending_deposits_data)}): {pending_deposits_data}")
    return render_template('admin_dashboard.html', 
                          sessions=sessions, 
                          events=recent_events,
                          ssh_sessions=ssh_sessions,
                          ssh_commands=ssh_commands,
                          stats=stats,
                          pending_deposits=pending_deposits_data,
                          profiles=profiles,
                          ssh_predictions=ssh_predictions)


@app.route('/admin/label_ssh_session/<string:session_id>', methods=['POST'])
def admin_label_ssh_session(session_id):
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)
    label = request.form.get('label')
    if not label:
        flash('No label provided', 'error')
        return redirect(url_for('admin_dashboard'))
    try:
        logger.label_ssh_session(session_id, label)
        flash(f'Session {session_id[:12]} labeled as {label}', 'success')
    except Exception as e:
        flash(f'Failed to label session: {e}', 'error')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/train_profiler', methods=['POST', 'GET'])
def admin_train_profiler():
    """Train the profiler model from labeled SSH sessions and persist the model file."""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)

    profile_engine = ProfileEngine(logger=logger)
    report = profile_engine.train(limit=1000)
    if report.get('trained'):
        # try to persist model if sklearn was used
        try:
            model_path = os.path.join(basedir, 'database', 'profiler_model.pkl')
            profile_engine.save_model(model_path)
            flash(f"Profiler trained and saved ({report.get('num_examples')} examples).", 'success')
        except Exception as e:
            flash(f"Model trained but failed to save: {e}", 'warning')
    else:
        reason = report.get('reason', 'unknown')
        flash(f"Profiler not trained: {reason}", 'warning')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/export_labeled_ssh', methods=['GET'])
def admin_export_labeled_ssh():
    """Export labeled SSH sessions as CSV for offline analysis."""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)

    labeled = []
    try:
        rows = logger.get_all_ssh_sessions(limit=10000)
        for r in rows:
            if r.get('label'):
                labeled.append(r)
    except Exception as e:
        flash(f"Failed to retrieve labeled sessions: {e}", 'error')
        return redirect(url_for('admin_dashboard'))

    # Create CSV in-memory
    import io, csv
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['session_id', 'ip_address', 'username', 'start_time', 'end_time', 'command_count', 'label'])
    for r in labeled:
        cw.writerow([r.get('session_id'), r.get('ip_address'), r.get('username'), r.get('start_time'), r.get('end_time'), r.get('command_count'), r.get('label')])
    output = si.getvalue()

    from flask import Response
    return Response(output, mimetype='text/csv', headers={"Content-Disposition": "attachment;filename=labeled_ssh_sessions.csv"})


@app.route('/admin/run_predictions', methods=['POST'])
def admin_run_predictions():
    """Run batch predictions for unlabeled SSH sessions and persist predicted labels."""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)

    profile_engine = ProfileEngine(logger=logger)
    # try to load persisted model (optional)
    try:
        profile_engine.load_model(os.path.join(basedir, 'database', 'profiler_model.pkl'))
    except Exception:
        pass

    # Get all ssh sessions (limit large)
    sessions = logger.get_all_ssh_sessions(limit=10000)
    unlabeled = [s for s in sessions if not s.get('label')]
    if not unlabeled:
        flash('No unlabeled SSH sessions found to predict.', 'info')
        return redirect(url_for('admin_dashboard'))

    preds = profile_engine.predict_for_ssh_sessions(unlabeled)
    updated = 0
    for sid, meta in preds.items():
        label = meta.get('label')
        if label:
            try:
                logger.label_ssh_session(sid, label)
                updated += 1
            except Exception:
                pass

    flash(f'Predictions applied to {updated} sessions.', 'success')
    return redirect(url_for('admin_dashboard'))



def reject_deposit(user_id):
    """Admin route to reject a pending deposit"""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)
    
    user = User.query.get(user_id)
    if not user or not user.pending_deposit:
        flash('Invalid user or no pending deposit found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        user.pending_deposit = False
        user.pending_deposit_amount = None  # Clear the pending amount
        
        # Remove pending transaction from history
        transaction_history = json.loads(user.transaction_history_json)
        transaction_history = [tx for tx in transaction_history if tx.get('status') != 'PENDING']
        user.transaction_history_json = json.dumps(transaction_history)
        
        db.session.commit()
        
        # Log the event
        logger.log_event('ADMIN_DEPOSIT_REJECTED', additional_data={
            'admin_user': session.get('username'),
            'target_user_id': user_id,
            'target_username': user.username,
            'timestamp': datetime.now().isoformat()
        })
        
        flash(f'❌ Deposit rejected for user {user.username}.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting deposit: {e}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/confirm_deposit/<int:user_id>', methods=['POST'])
def admin_confirm_deposit(user_id):
    """Admin route to confirm a pending deposit"""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)
    
    user = User.query.get(user_id)
    if not user or not user.pending_deposit:
        flash('Invalid user or no pending deposit found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    deposit_amount = request.form.get('amount', '0.00100')
    
    try:
        # Convert input to raw float, removing Bitcoin symbol if present
        amount_float = float(deposit_amount.replace('₿', ''))
        
        # Get current balance as raw float
        current_balance = btc_to_float(user.balance)
        new_balance = current_balance + amount_float
        
        # Store formatted balance only for final display
        user.balance = f'₿{new_balance:.5f}'
        user.pending_deposit = False
        user.pending_deposit_amount = None  # Clear the pending amount
        
        # Update transaction history with raw float values
        transaction_history = json.loads(user.transaction_history_json)
        for tx in transaction_history:
            if tx.get('status') == 'PENDING':
                tx['status'] = 'CONFIRMED'
                tx['amount'] = amount_float  # Store raw float value
                tx['description'] = f'Bitcoin deposit confirmed (3/3 confirmations)'
                break
        
        user.transaction_history_json = json.dumps(transaction_history)
        db.session.commit()
        
        logger.log_event('ADMIN_DEPOSIT_CONFIRMED', additional_data={
            'admin_user': session.get('username'),
            'target_user_id': user_id,
            'target_username': user.username,
            'amount_confirmed': f'₿{amount_float:.5f}',
            'new_balance': user.balance,
            'timestamp': datetime.now().isoformat()
        })
        
        flash(f'✅ Deposit of ₿{amount_float:.5f} confirmed for user {user.username}. New balance: {user.balance}', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error confirming deposit: {e}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_deposit/<int:user_id>', methods=['POST'])
def reject_deposit(user_id):
    """Admin route to reject a pending deposit"""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)
    
    user = User.query.get(user_id)
    if not user or not user.pending_deposit:
        flash('Invalid user or no pending deposit found.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        user.pending_deposit = False
        
        transaction_history = json.loads(user.transaction_history_json)
        transaction_history = [tx for tx in transaction_history if tx.get('status') != 'PENDING']
        user.transaction_history_json = json.dumps(transaction_history)
        
        db.session.commit()
        
        logger.log_event('ADMIN_DEPOSIT_REJECTED', additional_data={
            'admin_user': session.get('username'),
            'target_user_id': user_id,
            'target_username': user.username,
            'timestamp': datetime.now().isoformat()
        })
        
        flash(f'❌ Deposit rejected for user {user.username}.', 'warning')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting deposit: {e}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export_logs')
def export_logs():
    """Export all honeypot logs as JSON"""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)
    
    output_file = logger.export_logs_json(output_file='honeypot_logs_export.json')
    return send_file(output_file, as_attachment=True)

@app.route('/admin/session/<string:session_id>')
def admin_session_detail(session_id):
    """View detailed information about a specific session"""
    if not session.get('logged_in') or session.get('username').lower() != 'admin':
        abort(403)
    
    session_stats = logger.get_session_stats(session_id)
    session_events = logger.get_all_events(session_id=session_id, limit=500)
    
    return render_template('admin_session_detail.html',
                         session_stats=session_stats,
                         events=session_events)

def setup_admin_user():
    """Initializes the database and creates the admin user if it doesn't exist."""
    db.create_all()
    
    admin_user = User.query.filter_by(username='admin').first()
    
    if not admin_user:
        existing_user_1 = User.query.get(1)
        
        if existing_user_1 and existing_user_1.username != 'admin':
            print(f"Warning: User ID 1 is taken by '{existing_user_1.username}'. Using next available ID for admin.")
            admin_user = User(
                username='admin',
                password='adminadmin',
                balance='₿999.99999',
                pgp_public_key='ADMIN_ACCOUNT'
            )
        else:
            admin_user = User(
                id=1,
                username='admin',
                password='adminadmin',
                balance='₿999.99999',
                pgp_public_key='ADMIN_ACCOUNT'
            )
            
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user created with ID: {admin_user.id}, username: 'admin', password: 'adminadmin'")
    else:
        print(f"Admin user already exists with ID: {admin_user.id}")


with app.app_context():
    setup_admin_user()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)