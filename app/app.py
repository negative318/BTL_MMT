from flask import Flask, request, render_template, redirect, url_for, send_file, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from client import peer
from db import User, db
import os
import logging
import subprocess
from flask_socketio import SocketIO, emit
import socketio
import sys
from server import *
from flask import json




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
                    return redirect(url_for('getInfo'))
                else:
                    logging.warning("Invalid password")
            else:
                logging.warning("User not found")
        
        return render_template('login.html')
    except Exception as e:
        logging.error("Error in login route: %s", e)
        return "An error occurred while logging in."


tracker = server()
server_info = tracker.get_server_info()
current_client = peer()  

@app.route('/getInfo', methods=['GET', 'POST'])
@login_required
def getInfo():
    print(server_info)
    global current_client  
    if request.method == 'POST':
        ip = request.form['ip']
        port = int(request.form['port'])
        tracker_url = request.form['tracker_url']
        tracker_ip = server_info.get("ip")
        tracker_port = server_info.get("port")
        try:
            port = int(port) 
            tracker_port = int(tracker_port)  
            
            logging.info(f"Client created with IP: {ip}, Port: {port}, Tracker IP: {tracker_ip}, Tracker Port: {tracker_port}")
            #subprocess.Popen(['python', 'client.py', str(port), f"{tracker_ip}:{tracker_port}"])
            current_client = peer(ip, port, tracker_url)
            logging.info(f"Client started with IP: {ip}, Port: {port}, Tracker: {tracker_ip}:{tracker_port}")
            print("Client started successfully.")
            return redirect(url_for('uploadFile'))
        except Exception as e:
            logging.error("Error creating peer client: %s", e)
            return "Failed to create peer client.", 500
    return render_template('getInfo.html',server_info = server_info)


current_file = []

@app.route('/getFileInfo', methods=['GET', 'POST'])
@login_required
def getFileInfo():
    if request.method == 'POST':
        torrent_file = request.form['torrent_file']
        output_file = request.form['output_file']
        if torrent_file and output_file:
            current_file[:] = [torrent_file, output_file]  
            try:
                current_client.download(torrent_file, output_file)
                print(f"Downloading {torrent_file} to {output_file}.")
                return redirect(url_for('index'))
            except Exception as e:
                logging.error("Error initiating download: %s", e)
                return "Failed to start download.", 500
    return render_template('getFileInfo.html')



@app.route('/uploadFile', methods=['GET', 'POST'])
@login_required
def uploadFile():
    if request.method == 'POST':
        files = request.files.getlist('uploadFiles')  
        for file in files:
            if file and file.filename:  
                file_path = os.path.join('file', file.filename)
                current_client.register_files_with_tracker(file_path)
        print("Files uploaded successfully!")  
    return render_template('uploadFile.html')


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

current_status = current_client.get_status()

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        torrent_file = request.files.get('torrent')

        if torrent_file:
            current_client.start_download(torrent_file)  
            return jsonify(success=True)
        
        return jsonify(success=False, error="No torrent file provided.")
    
    else:  
        download_status = current_client.get_status()  
        download_info = {
            "file_name": download_status.get("file_name", ""),
            "size": download_status.get("size", 0),
            "status": download_status.get("status", ""),
        }
        
        return render_template('download.html', download_info=download_info)




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

