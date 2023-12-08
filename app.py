from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

load_dotenv()

app = Flask('__name__')
app.secret_key = os.urandom(12)

oauth = OAuth(app)

oauth.register(
    "myApp",
    client_id = os.getenv('OAUTH2_CLIENT_ID'),
    client_secret = os.getenv('OAUTH2_CLIENT_SECRET'),
    client_kwargs={
        'scope': 'openid profile email'
    },
    server_metadata_url=f'{os.getenv("OAUTH2_META_URL")}'
)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = 'rpg_project'

mysql = MySQL(app)

bcrypt = Bcrypt(app)

@app.route('/')
def home():
    if 'user' in session:
        return render_template('home.html', user=session['user'])
    else:
        return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        pwd = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT username, email, password FROM users WHERE username = '{username}'")
        user = cur.fetchone()
        print(user)
        cur.close()
        if user and bcrypt.check_password_hash(user[2], pwd):
            session['user'] = {'username': user[0], 'email': user[1], 'password': user[2]}
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='username or password are incorrect')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        pwd = request.form['password']
        confm = request.form['confirmation']
        cur = mysql.connection.cursor()
        if pwd == confm:
            cur.execute(f"SELECT username FROM users WHERE username = '{username}'")
            user  = cur.fetchone()
            if user:
                return render_template('register.html', error='username already exists')
            cur.execute(f"SELECT email FROM users WHERE email = '{email}'")
            user = cur.fetchone()
            if user:
                return render_template('register.html', error='email already registered')
            hashed_pwd = bcrypt.generate_password_hash(pwd).decode('utf-8')
            cur.execute(f"INSERT INTO users (username, email, password) VALUES ('{username}', '{email}', '{hashed_pwd}')")
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error='passwords don\'t match')
    print('a')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/google-login')
def googleLogin():
    return oauth.myApp.authorize_redirect(redirect_uri=url_for('googleCallback'), _external=True)

@app.route('/sigin-google')
def googleCallback():
    token = oauth.myApp.authorize_access_token()
    print(token)
    session['user'] = token 
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
