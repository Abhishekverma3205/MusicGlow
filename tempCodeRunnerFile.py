from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret-key'
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'mp3'}

# Initialize DB
def init_db():
    with sqlite3.connect('spotify.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE,
                        password TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS songs (
                        id INTEGER PRIMARY KEY,
                        filename TEXT,
                        uploader TEXT)''')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'username' in session:
        with sqlite3.connect('spotify.db') as conn:
            songs = conn.execute("SELECT * FROM songs").fetchall()
        return render_template('home.html', songs=songs, user=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        try:
            with sqlite3.connect('spotify.db') as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                flash('Registration successful. Please log in.')
                return redirect(url_for('login'))
        except:
            flash('Username already exists!')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('spotify.db') as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files or not allowed_file(request.files['file'].filename):
        flash('Only MP3 files are allowed.')
        return redirect(url_for('index'))

    file = request.files['file']
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    with sqlite3.connect('spotify.db') as conn:
        conn.execute("INSERT INTO songs (filename, uploader) VALUES (?, ?)", (filename, session['username']))
    flash('Song uploaded successfully!')
    return redirect(url_for('index'))

@app.route('/play/<filename>')
def play(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    init_db()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
