from flask import Flask, render_template, redirect, request, url_for, flash, session, jsonify
import json
import os
import requests
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
USERS_FILE = 'users.json'
JSQR_FILE = 'app/static/jsQR.js'
JSQR_URL = 'https://raw.githubusercontent.com/cozmo/jsQR/master/dist/jsQR.js'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as file:
            return json.load(file)
    return []

def save_users(users):
    with open(USERS_FILE, 'w') as file:
        json.dump(users, file, indent=4)

def get_root_user():
    users = load_users()
    return users[0] if users else None

def is_root_registered():
    return bool(get_root_user())

def save_root_user(username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    users = [{"root_user": username, "password_hash": password_hash}, {"users": []}]
    save_users(users)

def get_managers():
    users = load_users()
    return users[1]["users"] if len(users) > 1 else []

def save_manager_user(username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    users = load_users()
    users[1]["users"].append({"manager_username": username, "password_hash": password_hash, "users": []})
    save_users(users)

def get_users(manager_username):
    for manager in get_managers():
        if manager['manager_username'] == manager_username:
            return manager['users']
    return []

def save_user(manager_username, username, password):
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    users = load_users()
    for manager in users[1]["users"]:
        if manager['manager_username'] == manager_username:
            manager['users'].append({'user': username, 'password_hash': password_hash})
            break
    save_users(users)

def ensure_jsqr_library():
    os.makedirs('static', exist_ok=True)
    if not os.path.exists(JSQR_FILE):
        response = requests.get(JSQR_URL)
        if response.status_code == 200:
            with open(JSQR_FILE, 'w', encoding='utf-8') as file:
                file.write(response.text)

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
            return redirect(url_for('root_dashboard'))
    
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
    root_user = get_root_user()
    manager_users = get_managers()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if root_user and username == root_user['root_user'] and check_password_hash(root_user['password_hash'], password):
            session['user_id'] = username
            return redirect(url_for('root_dashboard'))
        for manager in manager_users:
            if username == manager['manager_username'] and check_password_hash(manager['password_hash'], password):
                session['user_id'] = username
                return redirect(url_for('manager_dashboard'))
            for user in manager['users']:
                if username == user['user'] and check_password_hash(user['password_hash'], password):
                    session['user_id'] = username
                    return redirect(url_for('user_dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/root_dashboard')
def root_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    managers = get_managers()
    return render_template('root_dashboard.html', managers=managers)

@app.route('/manager_dashboard')
def manager_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    manager_username = session['user_id']
    users = get_users(manager_username)
    return render_template('manager_dashboard.html', users=users)

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_dashboard.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    ensure_jsqr_library()
    app.run(debug=True, threaded=True)
