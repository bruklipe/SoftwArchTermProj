from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from patterns.proxy import SensitiveDataProxy
from patterns.chain import PasswordRecoveryChain
from patterns.observer import SecurityNotificationManager, SecuritySubject
from patterns.secure_session import SecureSessionManager, secure_session_required
from patterns.mediator import UIMediator, AlertManager, ClipboardManager, DataMasker, NotificationManager, PasswordGenerator
from patterns.builder import PasswordBuilder
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mypass.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy()
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Initialize UI components with mediator
ui_mediator = UIMediator()
alert_manager = AlertManager()
clipboard_manager = ClipboardManager()
data_masker = DataMasker()
notification_manager = NotificationManager()
password_generator = PasswordGenerator()

# Register components
ui_mediator.register_component("alert_manager", alert_manager)
ui_mediator.register_component("clipboard_manager", clipboard_manager)
ui_mediator.register_component("data_masker", data_masker)
ui_mediator.register_component("notification_manager", notification_manager)
ui_mediator.register_component("password_generator", password_generator)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    security_question1 = db.Column(db.String(200), nullable=False)
    security_answer1 = db.Column(db.String(200), nullable=False)
    security_question2 = db.Column(db.String(200), nullable=False)
    security_answer2 = db.Column(db.String(200), nullable=False)
    security_question3 = db.Column(db.String(200), nullable=False)
    security_answer3 = db.Column(db.String(200), nullable=False)
    vault_items = db.relationship('VaultItem', backref='owner', lazy=True)

    def get_id(self):
        return str(self.id)

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # login, card, identity, note
    title = db.Column(db.String(100), nullable=False)
    data = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        new_user = User(
            email=email,
            password_hash=generate_password_hash(password),
            security_question1=request.form.get('security_question1'),
            security_answer1=request.form.get('security_answer1'),
            security_question2=request.form.get('security_question2'),
            security_answer2=request.form.get('security_answer2'),
            security_question3=request.form.get('security_question3'),
            security_answer3=request.form.get('security_answer3')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            session_manager = SecureSessionManager()
            session_manager.start_session(user.id)
            return redirect(url_for('dashboard'))
            
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user's vault items
        logins = VaultItem.query.filter_by(user_id=current_user.id, type='login').all()
        credit_cards = VaultItem.query.filter_by(user_id=current_user.id, type='card').all()
        identities = VaultItem.query.filter_by(user_id=current_user.id, type='identity').all()
        secure_notes = VaultItem.query.filter_by(user_id=current_user.id, type='note').all()
        
        # Check for expiring items
        security_manager = SecurityNotificationManager(vault_item_model=VaultItem)
        expiring_items = security_manager.check_expiring_items(current_user.id)
        if expiring_items:
            for item in expiring_items:
                flash(f'Warning: {item["title"]} will expire on {item["expiry_date"]}', 'warning')
        
        # Simple expiration check for cards and identities
        for card in credit_cards:
            card_data = json.loads(card.data)
            if card_data.get('expiry_date'):
                expiry = datetime.strptime(card_data['expiry_date'], '%Y-%m')
                if (expiry - datetime.now()).days <= 30:
                    flash(f'Warning: Card "{card.title}" will expire in {(expiry - datetime.now()).days} days', 'warning')
        
        for identity in identities:
            identity_data = json.loads(identity.data)
            if identity_data.get('expiry_date'):
                expiry = datetime.strptime(identity_data['expiry_date'], '%Y-%m-%d')
                if (expiry - datetime.now()).days <= 30:
                    flash(f'Warning: Identity document "{identity.title}" will expire in {(expiry - datetime.now()).days} days', 'warning')
        
        return render_template('dashboard.html',
                             logins=logins,
                             credit_cards=credit_cards,
                             identities=identities,
                             secure_notes=secure_notes,
                             json=json)
    except Exception as e:
        flash('Error loading dashboard: ' + str(e), 'error')
        return redirect(url_for('login'))

@app.route('/logout')
@secure_session_required
def logout():
    session_manager = SecureSessionManager()
    session_manager.end_session()
    logout_user()
    return redirect(url_for('login'))

@app.route('/recover-password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('No account found with that email address.', 'error')
            return render_template('recover_password.html')
        
        # Get answers to security questions
        answer1 = request.form.get('security_answer1')
        answer2 = request.form.get('security_answer2')
        answer3 = request.form.get('security_answer3')
        
        # Initialize the recovery chain
        recovery_chain = PasswordRecoveryChain()
        
        # Verify security answers
        if not all([
            check_security_answer(user, 1, answer1),
            check_security_answer(user, 2, answer2),
            check_security_answer(user, 3, answer3)
        ]):
            flash('One or more security answers are incorrect.', 'error')
            return render_template('recover_password.html')
        
        # If we get here, all security answers are correct
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('recover_password.html')
            
        # Update password
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password has been reset successfully. Please login with your new password.', 'success')
        return redirect(url_for('login'))
        
    return render_template('recover_password.html')

@app.route('/add_login', methods=['GET', 'POST'])
@secure_session_required
def add_login():
    if request.method == 'POST':
        security_manager = SecurityNotificationManager()
        
        password = request.form.get('password')
        # Only check password strength if it wasn't generated by our system
        is_generated = request.form.get('is_generated', 'false') == 'true'
        
        if not is_generated and not security_manager.password_observer.check_password(password, current_user.id):
            flash('Warning: The password you entered is weak', 'warning')
        
        try:
            new_login = VaultItem(
                type='login',
                title=request.form.get('name'),
                data=json.dumps({
                    'username': request.form.get('username'),
                    'password': request.form.get('password'),
                    'url': request.form.get('url'),
                    'notes': request.form.get('notes')
                }),
                user_id=current_user.id
            )
            
            db.session.add(new_login)
            db.session.commit()
            
            flash('Login added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding login: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    return render_template('vault/add_login.html')

@app.route('/add_card', methods=['GET', 'POST'])
@secure_session_required
def add_card():
    if request.method == 'POST':
        try:
            new_card = VaultItem(
                type='card',
                title=request.form.get('name'),
                data=json.dumps({
                    'card_number': request.form.get('card_number'),
                    'cvv': request.form.get('cvv'),
                    'expiration_month': request.form.get('expiration_month'),
                    'expiration_year': request.form.get('expiration_year'),
                    'notes': request.form.get('notes')
                }),
                user_id=current_user.id
            )
            
            db.session.add(new_card)
            db.session.commit()
            
            flash('Credit card added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding credit card: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    return render_template('vault/add_credit_card.html', current_year=datetime.now().year)

@app.route('/add_identity', methods=['GET', 'POST'])
@secure_session_required
def add_identity():
    if request.method == 'POST':
        try:
            # Get form data
            identity_type = request.form.get('identity_type')
            title = request.form.get('title')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            id_number = request.form.get('id_number')
            expiry_date = request.form.get('expiry_date')

            # Basic validation
            if not all([identity_type, title, first_name, last_name, id_number]):
                flash('Please fill in all required fields', 'error')
                return redirect(url_for('add_identity'))

            # Create new identity
            new_identity = VaultItem(
                type='identity',
                title=title,
                data=json.dumps({
                    'identity_type': identity_type,
                    'first_name': first_name,
                    'last_name': last_name,
                    'id_number': id_number,
                    'expiry_date': expiry_date if identity_type != 'ssn' else None
                }),
                user_id=current_user.id
            )
            
            db.session.add(new_identity)
            db.session.commit()
            
            flash('Identity added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error adding identity: {str(e)}")  # Debug log
            flash(f'Error adding identity: {str(e)}', 'error')
            return redirect(url_for('add_identity'))
    
    return render_template('vault/add_identity.html')

@app.route('/edit_identity/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_identity(id):
    identity = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='identity').first_or_404()
    if request.method == 'POST':
        try:
            identity.title = request.form.get('title')
            identity.data = json.dumps({
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'id_number': request.form.get('id_number'),
                'expiry_date': request.form.get('expiry_date'),
                'notes': request.form.get('notes')
            })
            db.session.commit()
            flash('Identity updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating identity: {str(e)}', 'error')
    identity_data = json.loads(identity.data)
    return render_template('vault/add_identity.html', identity=identity, identity_data=identity_data)

@app.route('/add_note', methods=['GET', 'POST'])
@secure_session_required
def add_note():
    if request.method == 'POST':
        try:
            new_note = VaultItem(
                type='note',
                title=request.form.get('name'),
                data=json.dumps({
                    'content': request.form.get('content')
                }),
                user_id=current_user.id
            )
            
            db.session.add(new_note)
            db.session.commit()
            flash('Secure note added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding secure note: {str(e)}', 'error')
    
    return render_template('vault/add_secure_note.html')

@app.route('/edit_note/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_note(id):
    note = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='note').first_or_404()
    if request.method == 'POST':
        try:
            # Get the title with a default value if not provided
            title = request.form.get('name', note.title).strip()
            if not title:
                flash('Title cannot be empty', 'error')
                return redirect(url_for('edit_note', id=id))

            # Update the note
            note.title = title
            note.data = json.dumps({
                'content': request.form.get('content', '')
            })
            
            db.session.commit()
            flash('Note updated successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating note: {str(e)}")  # Debug log
            flash(f'Error updating note: {str(e)}', 'error')
            return redirect(url_for('edit_note', id=id))
    
    note_data = json.loads(note.data)
    return render_template('vault/add_secure_note.html', note=note, note_data=note_data)

@app.route('/delete_login/<int:id>', methods=['POST'])
@login_required
def delete_login(id):
    login = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='login').first_or_404()
    db.session.delete(login)
    db.session.commit()
    flash('Login deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/edit_login/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_login(id):
    login = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='login').first_or_404()
    if request.method == 'POST':
        try:
            # Get the title with a default value if not provided
            title = request.form.get('title', login.title).strip()
            if not title:
                flash('Title cannot be empty', 'error')
                return redirect(url_for('edit_login', id=id))

            # Update the login
            login.title = title
            login.data = json.dumps({
                'username': request.form.get('username', ''),
                'password': request.form.get('password', ''),
                'url': request.form.get('url', ''),
                'notes': request.form.get('notes')
            })
            
            db.session.commit()
            flash('Login updated successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error updating login: {str(e)}")  # Debug log
            flash(f'Error updating login: {str(e)}', 'error')
            return redirect(url_for('edit_login', id=id))
    
    login_data = json.loads(login.data)
    return render_template('vault/add_login.html', login=login, login_data=login_data)

@app.route('/delete_card/<int:id>', methods=['POST'])
@login_required
def delete_card(id):
    try:
        card = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='card').first_or_404()
        db.session.delete(card)
        db.session.commit()
        flash('Credit card deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting credit card: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/edit_card/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_card(id):
    card = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='card').first_or_404()
    if request.method == 'POST':
        try:
            card.title = request.form.get('name', '')  # Changed to match form field
            card.data = json.dumps({
                'card_number': request.form.get('card_number', ''),
                'cvv': request.form.get('cvv', ''),
                'expiration_month': request.form.get('expiration_month', ''),
                'expiration_year': request.form.get('expiration_year', ''),
                'notes': request.form.get('notes', '')
            })
            db.session.commit()
            flash('Credit card updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating credit card: {str(e)}', 'error')
    card_data = json.loads(card.data)
    return render_template('vault/add_credit_card.html', card=card, card_data=card_data, current_year=datetime.now().year)

@app.route('/delete_identity/<int:id>', methods=['POST'])
@login_required
def delete_identity(id):
    try:
        identity = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='identity').first_or_404()
        db.session.delete(identity)
        db.session.commit()
        flash('Identity deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        
        flash(f'Error deleting identity: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

@app.route('/delete_note/<int:id>', methods=['POST'])
@login_required
def delete_note(id):
    try:
        note = VaultItem.query.filter_by(id=id, user_id=current_user.id, type='note').first_or_404()
        db.session.delete(note)
        db.session.commit()
        flash('Secure note deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting secure note: {str(e)}', 'error')
    return redirect(url_for('dashboard'))

# Helper functions
def check_security_answer(user, question_num, answer):
    """Check if the security answer is correct"""
    if not answer:
        return False
        
    stored_answer = getattr(user, f'security_answer{question_num}')
    return answer.lower().strip() == stored_answer.lower().strip()

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    flash('You do not have permission to access this page.', 'error')
    return redirect(url_for('login'))

@app.errorhandler(401)
def unauthorized_error(error):
    flash('Please log in to access this page.', 'error')
    return redirect(url_for('login'))

@app.route('/generate_password', methods=['POST'])
@secure_session_required
def generate_password():
    try:
        options = request.get_json()
        
        # Initialize the password builder
        builder = PasswordBuilder()
        
        # Configure the builder based on options
        if options.get('length'):
            builder.set_length(int(options['length']))
        if options.get('uppercase'):
            builder.include_uppercase()
        if options.get('lowercase'):
            builder.include_lowercase()
        if options.get('numbers'):
            builder.include_numbers()
        if options.get('symbols'):
            builder.include_symbols()
            
        # Generate the password
        password = builder.build()
        
        return jsonify({
            'success': True,
            'password': password
        })
        
    except Exception as e:
        print(f"Password generation error: {str(e)}")  # For debugging
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/dismiss_alert/<alert_id>', methods=['POST'])
@secure_session_required
def dismiss_alert(alert_id):
    try:
        ui_mediator.notify(None, "alert_dismissed", alert_id)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/copy_data', methods=['POST'])
@secure_session_required
def copy_data():
    try:
        data = request.json.get('data')
        ui_mediator.notify(None, "data_copied", data)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/toggle_mask', methods=['POST'])
@secure_session_required
def toggle_mask():
    try:
        element_id = request.json.get('element_id')
        ui_mediator.notify(None, "data_masked", element_id)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.before_request
def before_request():
    # Don't check session for login/register/static routes
    if request.endpoint and not request.endpoint.startswith(('static', 'login', 'register')):
        if current_user.is_authenticated:
            session_manager = SecureSessionManager()
            if not session_manager.is_session_valid():
                logout_user()
                session_manager.end_session()
                flash('Your session has expired. Please log in again.', 'info')
                return redirect(url_for('login'))

@app.after_request
def after_request(response):
    # Add CSP headers to allow necessary functionality
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    print(f"Response status: {response.status_code}")  # Debug log
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=5001, debug=True)
