import os
import json
import csv
from flask import Flask, render_template, redirect, url_for, session, request, abort, flash, send_file
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

app = Flask(__name__)

app.secret_key = 'your_super_secret_key_change_me'

basedir = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(basedir, 'database', 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize the honeypot logger
logger = HoneypotLogger(db_path=os.path.join(basedir, 'database', 'honeypot_logs.db'))

# Initialize GPG with a specific home directory for key storage
gpg_home = os.path.join(basedir, 'gpg_home')
os.makedirs(gpg_home, exist_ok=True)
gpg = gnupg.GPG(gnupghome=gpg_home)

ADMIN_ID = 1
HOT_LISTING_ID = 'DATA-SIM-ORANGE-CUST-B0T'

# Bitcoin Testnet Deposit Lure Configuration
FAKE_BTC_ADDRESS = 'tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'  # Bitcoin Testnet address

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
            pgp_public_key=pgp_key if pgp_valid else None,
            transaction_history_json=json.dumps(transaction_history),
            pending_deposit=False
        )

        try:
            db.session.add(new_user)
            db.session.flush()

            create_welcome_message(new_user.id, new_user.username, pgp_valid)

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
                'used_coupon': coupon == 'REDTEAMBECODE',
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
    db.session.flush()

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

    logger.log_event('PURCHASE', additional_data={
        'order_id': new_order.id,
        'total': f'₿{total_btc:.5f}',
        'items_count': len(purchased_items),
        'contains_bait': HOT_LISTING_ID in cart_items,
        'items': cart_items
    })

    final_encrypted_content = None
    final_status = 'SHIPPED'
    prefixed_order_id = f'54987{new_order.id}'

    if HOT_LISTING_ID in cart_items:
        try:
            file_name = 'orange.xlsx'
            file_path = os.path.join(app.root_path, 'static', 'data', file_name)

            if not os.path.exists(file_path):
                raise FileNotFoundError

            plaintext_message = f"""Order Fulfillment Status: Completed
Item: Orange Customer Credential Database
Your secure download link is:
http://10.40.38.153:5000/static/data/orange.xlsx
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
        plaintext_message = "Your order has been placed. Delivery details for items other than the Orange SIM are pending vendor fulfillment."
        success, encrypted_or_error = encrypt_message_for_user(user, plaintext_message)

        if success:
            final_encrypted_content = encrypted_or_error
        else:
            final_encrypted_content = "Your order has been placed. Delivery details pending."

        final_status = 'SHIPPED'

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
    
    file_name = 'orange.xlsx'
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
        # Handle deposit confirmation
        amount_sent = request.form.get('amount_sent', '0.00000')
        
        # Mark pending deposit
        user.pending_deposit = True
        db.session.commit()
        
        # Log the critical deposit attempt
        logger.log_event('DEPOSIT_ATTEMPT', additional_data={
            'user_id': user.id,
            'username': user.username,
            'amount_claimed': amount_sent,
            'btc_address': FAKE_BTC_ADDRESS,
            'timestamp': datetime.now().isoformat()
        })
        
        flash('Deposit initiated. Awaiting blockchain confirmation (3 confirmations required).', 'success')
        return redirect(url_for('wallet'))

    # Build transaction history
    try:
        transaction_history = json.loads(user.transaction_history_json)
    except (json.JSONDecodeError, TypeError):
        transaction_history = []
    
    # Add pending deposit to history if active
    if user.pending_deposit:
        transaction_history.insert(0, {
            'type': 'DEPOSIT',
            'amount': '₿0.00000',
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'description': 'Pending - Awaiting 3 confirmations',
            'status': 'PENDING'
        })

    # Generate QR code for the Bitcoin address
    qr_code_data_uri = generate_qr_code(FAKE_BTC_ADDRESS)

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
    
    sessions = logger.get_all_sessions(limit=50)
    recent_events = logger.get_all_events(limit=100)
    
    total_sessions = len(sessions)
    total_downloads = sum(1 for s in sessions if s['downloads_attempted'] > 0)
    total_purchases = sum(1 for s in sessions if s['purchases_made'] > 0)
    total_registrations = sum(1 for s in sessions if s['registered'])
    
    stats = {
        'total_sessions': total_sessions,
        'total_downloads': total_downloads,
        'total_purchases': total_purchases,
        'total_registrations': total_registrations,
        'total_events': sum(s['total_events'] for s in sessions)
    }
    
    return render_template('admin_dashboard.html', 
                         sessions=sessions, 
                         events=recent_events,
                         stats=stats)

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