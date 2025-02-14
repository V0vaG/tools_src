from flask import Flask, render_template, redirect, request, url_for, flash, session
import json
import os
import requests
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
ROOT_USER_FILE = 'root_user.json'
MANAGER_USERS_FILE = 'manager_users.json'
JSQR_FILE = 'static/jsQR.js'
JSQR_URL = 'https://raw.githubusercontent.com/cozmo/jsQR/master/dist/jsQR.js'

def load_root_user():
    if os.path.exists(ROOT_USER_FILE):
        with open(ROOT_USER_FILE, 'r') as file:
            return json.load(file)
    return None

def save_root_user(username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    with open(ROOT_USER_FILE, 'w') as file:
        json.dump({'username': username, 'password_hash': password_hash}, file)

def is_root_registered():
    return os.path.exists(ROOT_USER_FILE)

def load_manager_users():
    if os.path.exists(MANAGER_USERS_FILE):
        with open(MANAGER_USERS_FILE, 'r') as file:
            return json.load(file)
    return []

def save_manager_user(username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    managers = load_manager_users()
    managers.append({'manager_username': username, 'password_hash': password_hash, 'users': []})
    with open(MANAGER_USERS_FILE, 'w') as file:
        json.dump(managers, file)

def load_users(manager_username):
    managers = load_manager_users()
    for manager in managers:
        if manager['manager_username'] == manager_username:
            return manager['users']
    return []

def save_user(manager_username, username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    managers = load_manager_users()
    for manager in managers:
        if manager['manager_username'] == manager_username:
            manager['users'].append({'user': username, 'password_hash': password_hash})
            break
    with open(MANAGER_USERS_FILE, 'w') as file:
        json.dump(managers, file)


def ensure_jsqr_library():
    os.makedirs('static', exist_ok=True)  # Ensure static directory exists
    if not os.path.exists(JSQR_FILE):
        print("Downloading jsQR library...")
        response = requests.get(JSQR_URL)
        if response.status_code == 200:
            with open(JSQR_FILE, 'w', encoding='utf-8') as file:
                file.write(response.text)
            print("jsQR library downloaded successfully.")
        else:
            print("Failed to download jsQR library.")


@app.before_request
def check_root_user():
    if not is_root_registered():
        if request.endpoint not in ('register_root', 'static'):
            return redirect(url_for('register_root'))

@app.route('/register_root', methods=['GET', 'POST'])
def register_root():
    if is_root_registered():
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
        else:
            save_root_user(username, password)
            flash('Root user registered successfully!', 'success')
            return redirect(url_for('login'))
    
    return render_template('register_root.html')

@app.route('/register_manager', methods=['GET', 'POST'])
def register_manager():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
        else:
            save_manager_user(username, password)
            flash('Manager user registered successfully!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('register_manager.html')

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    manager_username = session['user_id']
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
        else:
            save_user(manager_username, username, password)
            flash('User registered successfully!', 'success')
            return redirect(url_for('manager_dashboard'))
    
    return render_template('register_user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    root_user = load_root_user()
    manager_users = load_manager_users()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if root_user and username == root_user['username'] and check_password_hash(root_user['password_hash'], password):
            session['user_id'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        for manager in manager_users:
            if username == manager['manager_username'] and check_password_hash(manager['password_hash'], password):
                session['user_id'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('manager_dashboard'))
            for user in manager['users']:
                if username == user['user'] and check_password_hash(user['password_hash'], password):
                    session['user_id'] = username
                    flash('Login successful!', 'success')
                    return redirect(url_for('user_dashboard'))
        
        flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    managers = load_manager_users()
    return render_template('dashboard.html', managers=managers)

@app.route('/manager_dashboard')
def manager_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    manager_username = session['user_id']
    users = load_users(manager_username)
    return render_template('manager_dashboard.html', users=users)

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_dashboard.html')

@app.route('/log_qr', methods=['POST'])
def log_qr():
    data = request.json
    qr_code = data.get("qr_code", "")
    if qr_code:
        print(f"Scanned QR Code: {qr_code}")
        return jsonify({"message": "QR Code received", "data": qr_code})
    return jsonify({"error": "No QR Code received"}), 400


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    ensure_jsqr_library()
    app.run(debug=True)
