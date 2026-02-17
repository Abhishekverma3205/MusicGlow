from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import os
import sqlite3
import smtplib
import random
from email.mime.text import MIMEText

app = Flask(__name__)

# ================= PRODUCTION CONFIG =================

app.secret_key = os.environ.get("SECRET_KEY")

UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {"mp3"}

# ================= GOOGLE OAUTH =================

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
#================= DATABASE =================

def init_db():
    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:

        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS songs (
            id INTEGER PRIMARY KEY,
            filename TEXT UNIQUE,
            uploader TEXT
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY,
            user TEXT,
            song_id INTEGER,
            UNIQUE(user, song_id)
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY,
            user TEXT,
            song_id INTEGER,
            UNIQUE(user, song_id)
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS recent (
            id INTEGER PRIMARY KEY,
            user TEXT,
            song_id INTEGER
        )
        """)

        # 🔥 FIXED ADMIN AUTO CREATE
        admin = conn.execute(
            "SELECT * FROM users WHERE username=?",
            ("admin",)
        ).fetchone()

        if not admin:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", generate_password_hash("Vasu@3205"), "Vasu3205"),
            )

        

# ================= EMAIL CONFIG =================
EMAIL_ADDRESS = os.environ.get("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")

def send_otp(email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Music-Glow OTP"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

# ================= HELPERS =================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ================= HOME =================

@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
        songs = conn.execute("SELECT * FROM songs").fetchall()

    return render_template(
        "home.html",
        songs=songs,
        user=session["username"],
        role=session.get("role"),
        page_type="home"
    )


# ================= REGISTER WITH OTP =================

@app.route("/register", methods=["GET", "POST"])
def register():

    # OTP Verification
    if request.method == "POST" and "otp" in request.form:
        if request.form["otp"] != session.get("otp"):
            flash("Invalid OTP")
            return render_template("verify_otp.html")

        username = session["temp_username"]
        password = session["temp_password"]

        with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password),
            )

        session.clear()
        flash("Registration successful!")
        return redirect(url_for("login"))

    # Send OTP
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
            existing = conn.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
            if existing:
                flash("Username already exists!")
                return redirect(url_for("register"))

        otp = str(random.randint(100000, 999999))
        session["otp"] = otp
        session["temp_username"] = username
        session["temp_password"] = password

        #send_otp(email, otp)
        return render_template("verify_otp.html")

    return render_template("register.html")

# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()

        if user and check_password_hash(user[2], password):
            session["username"] = user[1]
            session["role"] = user[3]
            return redirect(url_for("index"))

        flash("Invalid credentials")

    return render_template("login.html")

# ================= GOOGLE LOGIN =================
@app.route("/login/google")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/callback")
def google_callback():
    token = google.authorize_access_token()
    
    # THIS is the correct way
    user_info = token["userinfo"]

    email = user_info["email"]

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db"))as conn:
        existing = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (email,),
        ).fetchone()

        if not existing:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (email, None, "user"),
            )

    session["username"] = email
    session["role"] = "user"

    return redirect(url_for("index"))



# ================= LOGOUT =================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ================= ADMIN UPLOAD =================

@app.route("/upload", methods=["POST"])
def upload():
    if session.get("role") != "admin":
        flash("Only admin can upload")
        return redirect(url_for("index"))

    file = request.files.get("file")

    if not file or not allowed_file(file.filename):
        flash("Invalid file")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db"))as conn:
        existing = conn.execute(
            "SELECT * FROM songs WHERE filename=?", (filename,)
        ).fetchone()

        if existing:
            flash("Song already exists")
            return redirect(url_for("index"))

        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        conn.execute(
            "INSERT INTO songs (filename, uploader) VALUES (?, ?)",
            (filename, session["username"]),
        )

    flash("Song uploaded successfully")
    return redirect(url_for("index"))

# ================= DELETE SONG =================

@app.route("/delete/<int:song_id>")
def delete_song(song_id):
    if session.get("role") != "admin":
        return redirect(url_for("index"))

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
        song = conn.execute(
            "SELECT filename FROM songs WHERE id=?", (song_id,)
        ).fetchone()

        if song:
            path = os.path.join(app.config["UPLOAD_FOLDER"], song[0])
            if os.path.exists(path):
                os.remove(path)
            conn.execute("DELETE FROM songs WHERE id=?", (song_id,))

    flash("Song deleted")
    return redirect(url_for("index"))

# ================= LIKE TOGGLE =================

@app.route("/view_likes")
def view_likes():
    if "username" not in session:
        return redirect(url_for("login"))

    user = session["username"]

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
        songs = conn.execute("""
            SELECT songs.* FROM songs
            JOIN likes ON songs.id = likes.song_id
            WHERE likes.user=?
        """, (user,)).fetchall()

    return render_template(
        "home.html",
        songs=songs,
        user=session["username"],
        role=session.get("role"),
        page_type="likes"
    )

@app.route("/like/<int:song_id>")
def like(song_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user = session["username"]

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
        existing = conn.execute(
            "SELECT * FROM likes WHERE user=? AND song_id=?",
            (user, song_id),
        ).fetchone()

        if existing:
            conn.execute(
                "DELETE FROM likes WHERE user=? AND song_id=?",
                (user, song_id),
            )
        else:
            conn.execute(
                "INSERT INTO likes (user, song_id) VALUES (?, ?)",
                (user, song_id),
            )

    return redirect(url_for("index"))


# ================= FAVORITE TOGGLE =================
@app.route("/favorite/<int:song_id>")
def favorite(song_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user = session["username"]

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db"))as conn:
        existing = conn.execute(
            "SELECT * FROM favorites WHERE user=? AND song_id=?",
            (user, song_id),
        ).fetchone()

        if existing:
            conn.execute(
                "DELETE FROM favorites WHERE user=? AND song_id=?",
                (user, song_id),
            )
        else:
            conn.execute(
                "INSERT INTO favorites (user, song_id) VALUES (?, ?)",
                (user, song_id),
            )

    return redirect(url_for("index"))


@app.route("/view_favorites")
def view_favorites():
    if "username" not in session:
        return redirect(url_for("login"))

    user = session["username"]

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
        songs = conn.execute("""
            SELECT songs.* FROM songs
            JOIN favorites ON songs.id = favorites.song_id
            WHERE favorites.user=?
        """, (user,)).fetchall()

    return render_template(
        "home.html",
        songs=songs,
        user=session["username"],
        role=session.get("role"),
        page_type="favorites"
    )




#================== RECENTLY PLAYED =================

@app.route("/view_recent")
def view_recent():
    if "username" not in session:
        return redirect(url_for("login"))

    user = session["username"]

    with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
        songs = conn.execute("""
            SELECT songs.* FROM songs
            JOIN recent ON songs.id = recent.song_id
            WHERE recent.user=?
            ORDER BY recent.id DESC
        """, (user,)).fetchall()

    return render_template(
        "home.html",
        songs=songs,
        user=session["username"],
        role=session.get("role"),
        page_type="recent"
    )


#================== forgot password =================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=?",
                (email,)
            ).fetchone()

        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_otp'] = otp
            session['reset_user'] = email

            send_otp(email, otp)
            flash("OTP sent to your email.")
            return redirect(url_for('verify_reset_otp'))
        else:
            flash("User not found.")

    return render_template('forgot_password.html')



#================== verify reset OTP =================
@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']

        if user_otp == session.get('reset_otp'):
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP")
            return redirect(url_for('verify_reset_otp'))

    return render_template("verify_reset_otp.html")

#================== reset password =================
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)

        user_email = session.get('reset_user')

        with sqlite3.connect(os.path.join(os.getcwd(), "Musicglow.db")) as conn:
            conn.execute(
                "UPDATE users SET password=? WHERE username=?",
                (hashed_password, user_email)
            )

        session.pop('reset_otp', None)
        session.pop('reset_user', None)

        flash("Password reset successful. Please login.")
        return redirect(url_for('login'))

    return render_template("reset_password.html")


# ================= PLAY =================

@app.route("/play/<filename>")
def play(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ================= RUN =================

init_db()
os.makedirs(UPLOAD_FOLDER, exist_ok=True)





