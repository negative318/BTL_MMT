from flask import Flask, request, render_template, redirect, url_for, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from main import download
from db import User, db
import os
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
#app.config['UPLOAD_FOLDER'] = 'static/downloads'
app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123456789@localhost/p2p' 
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            logging.debug(f"Username: {username}, Password: {password}")  

            user = User.query.filter_by(username=username).first()
            if user:
                logging.debug(f"User found: {user.username}")
                if check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    logging.warning("Invalid password")
            else:
                logging.warning("User not found")
        
        return render_template('login.html')
    except Exception as e:
        logging.error("Error in login route: %s", e)
        return "An error occurred while logging in."
    
    


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists", 400  
        
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password, email=email)  
        db.session.add(new_user)
        
        try:
            db.session.commit()  
        except Exception as e:
            db.session.rollback()  
            return str(e), 500  

        return redirect(url_for('login'))  

    return render_template('register.html')


@app.route('/index')
@login_required
def index():
    return render_template('index.html')  


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/user_details')
@login_required
def user_details():
    return render_template('user_details.html', user=current_user)


if __name__ == "__main__":
    with app.app_context():
        db.create_all() 
    app.run(debug=True)
