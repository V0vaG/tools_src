from flask import Flask, render_template, redirect, request, url_for, flash, session
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
ROOT_USER_FILE = 'root_user.json'

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    root_user = load_root_user()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if root_user and username == root_user['username'] and check_password_hash(root_user['password_hash'], password):
            session['user_id'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
