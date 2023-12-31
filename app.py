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
        cur.execute(f"SELECT id, username, email, password FROM users WHERE username = '{username}'")
        user = cur.fetchone()
        print(user)
        cur.close()
        if user and bcrypt.check_password_hash(user[3], pwd):
            cur = mysql.connection.cursor()
            cur.execute(f"SELECT id, name, game FROM campaigns WHERE user_id = '{user[0]}'")
            campaigns = cur.fetchall()
            session['user'] = {'id': user[0], 'username': user[1], 'email': user[2], 'campaigns': campaigns}
            print(session['user'])
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

@app.route('/campaigns', methods=['GET', 'POST'])
def campaigns():
    if 'user' in session:
        user_id = session['user']['id']
        if request.method == 'POST':
            name = request.form['name']
            game = request.form['game']
            user_id = session['user']['id']
            print(user_id)
            cur = mysql.connection.cursor()
            cur.execute(f"INSERT INTO campaigns (name, game, image_id, user_id) VALUES ('{name}', '{game}', '1', '{user_id}')")
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('campaigns'))
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT id, name, game, image_id FROM campaigns WHERE user_id='{user_id}'")
        campaigns = cur.fetchall()
        cur.close()
        session['user']['campaigns'] = campaigns
        return render_template('campaigns.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/delete_campaign/<id>', methods=['POST'])
def delete_campaign(id):
    if 'user' in session:
        user_id = session['user']['id']
        if request.method == 'POST':
            user_id = session['user']['id']
            cur = mysql.connection.cursor()
            cur.execute(f"DELETE FROM characters WHERE campaign_id={id}")
            mysql.connection.commit()
            cur.execute(f"DELETE FROM campaigns WHERE id='{id}'")
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('campaigns'))
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT id, name, game, image_id FROM campaigns WHERE user_id='{user_id}'")
        campaigns = cur.fetchall()
        cur.close()
        session['user']['campaigns'] = campaigns
        return redirect(url_for('campaigns'))
    return redirect(url_for('login'))

@app.route('/campaign/<id>', methods=['GET'])
def campaign_details(id):
    if 'user' in session:
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT id, name, game, image_id FROM campaigns WHERE id='{id}'")
        campaign = cur.fetchone()
        cur.execute(f"SELECT id, name, race, class, image_id FROM characters WHERE campaign_id='{id}'")
        characters = cur.fetchall()
        cur.close()
        return render_template('campaign.html', user=session['user'], campaign=campaign, characters=characters)
    return redirect(url_for('login'))

@app.route('/change-campaign-image/<campaign_id>/<image_id>', methods=['POST'])
def changeCampaignImage(campaign_id, image_id):
    cur = mysql.connection.cursor()
    cur.execute(f"UPDATE campaigns SET image_id={image_id} WHERE id={campaign_id}")
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('campaigns'))

@app.route('/create-character/<campaign_id>', methods=['POST'])
def createCharacter(campaign_id):
    if 'user' in session:
        if request.method == 'POST':
            name = request.form['name']
            race = request.form['race']
            _class = request.form['class']
            cur = mysql.connection.cursor()
            cur.execute(f"INSERT INTO characters (name , race, class, image_id, campaign_id) VALUES ('{name}', '{race}', '{_class}', '1', '{campaign_id}')")
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('campaign_details', id=campaign_id))
    return redirect(url_for('login'))

@app.route('/delete-character/<id>', methods=['POST'])
def deleteCharacter(id):
    if 'user' in session:
        cur = mysql.connection.cursor()
        cur.execute(f"SELECT campaign_id FROM characters WHERE id='{id}'")
        campaign_id = cur.fetchone()[0]
        cur.execute(f"DELETE FROM characters WHERE id='{id}'")
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('campaign_details', id=campaign_id))
    return redirect(url_for('home'))

@app.route('/change-character-image/<character_id>/<image_id>', methods=['POST'])
def changeCharacterImage(character_id, image_id):
    cur = mysql.connection.cursor()
    cur.execute(f"UPDATE characters SET image_id={image_id} WHERE id={character_id}")
    mysql.connection.commit()
    cur.execute(f"SELECT campaign_id FROM characters WHERE id={character_id}")
    campaign_id = cur.fetchone()[0]
    cur.close()
    return redirect(url_for('campaign_details', id=campaign_id))

if __name__ == '__main__':
    app.run(debug=True)
