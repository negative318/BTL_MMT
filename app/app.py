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
import threading
import time



logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
#app.config['UPLOAD_FOLDER'] = 'static/downloads'
app.config['SECRET_KEY'] = 'secret_key'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123456789@localhost/p2p' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
# db.init_app(app)
socketio = SocketIO(app)
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
current_client = None
current_status = None





@app.route('/getInfo', methods=['GET', 'POST'])
# @login_required
def getInfo():
    print(server_info)
    global current_client  
    if request.method == 'POST':
        ip = request.form['ip']
        port = int(request.form['port'])
        tracker_url = request.form['tracker_url']
        try:
            #logging.info(f"Client created with IP: {ip}, Port: {port}, Tracker IP: {tracker_ip}, Tracker Port: {tracker_port}")
            #subprocess.Popen(['python', 'client.py', str(port), f"{tracker_ip}:{tracker_port}"])
            current_client = peer(ip, port, tracker_url)
            #logging.info(f"Client started with IP: {ip}, Port: {port}, Tracker: {tracker_ip}:{tracker_port}")
            print("Client started successfully.")
            return redirect(url_for('uploadFile'))
        except Exception as e:
            logging.error("Error creating peer client: %s", e)
            return "Failed to create peer client.", 500
    return render_template('getInfo.html',server_info = server_info)


current_file = []

"""
@app.route('/getFileInfo', methods=['POST', 'GET'])
def getFileInfo():
    global current_client
    # Kiểm tra nếu đối tượng current_client đã tồn tại
    if not current_client:
        error = "Peer client is not initialized"
        return render_template('getFileInfo.html', error=error)
    
    # Kiểm tra phương thức yêu cầu
    if request.method == 'POST':
        # Lấy thông tin từ request
        torrent_file = request.form.get('torrent_file')
        output_file = request.form.get('output_file')
        
        # Gọi phương thức download của đối tượng current_client
        try:
            download_status = current_client.download(torrent_file, output_file)
            if download_status:
                message = "Download complete"
                return render_template('getFileInfo.html', message=message)
            else:
                error = "Download failed"
                return render_template('getFileInfo.html', error=error)
        except Exception as e:
            error = f"Download error: {e}"
            return render_template('getFileInfo.html', error=error)
    
    # Nếu là GET request, chỉ render template mà không xử lý gì
    return render_template('getFileInfo.html')
"""


@app.route('/getFileInfo', methods=['GET', 'POST'])
# @login_required
def getFileInfo():
    if request.method == 'POST':
        torrent_file = request.files['torrent_file']  # Thay đổi ở đây
        output_file = request.form['output_file']
        if torrent_file and output_file:
            current_file[:] = [torrent_file, output_file]  
            torrent_file_path = os.path.join('torrent', torrent_file.filename)
            try:
                torrent_file.save(torrent_file_path)  # Lưu tệp tải lên vào thư mục
                current_client.download(torrent_file_path, output_file)
                print(f"Downloading {torrent_file} to {output_file}.")
                return redirect(url_for('download'))
            except Exception as e:
                logging.error("Error initiating download: %s", e)
                return "Failed to start download.", 500
    return render_template('getFileInfo.html')


"""
@app.route('/uploadFile', methods=['GET', 'POST'])
# @login_required
def uploadFile():
    if request.method == 'POST':
        files = request.files.getlist('uploadFiles')  
        for file in files:
            if file and file.filename:  
                file_path = os.path.join('file', file.filename)
                current_client.register_files_with_tracker(file_path)
        print("Files uploaded successfully!")  
    return render_template('uploadFile.html')
"""

@app.route('/uploadFile', methods=['GET', 'POST'])
# @login_required
def uploadFile():
    global current_client
    if not current_client:
        error = "Peer client is not initialized"
        return render_template('uploadFile.html', error=error)

    if request.method == 'POST':
        files = request.files.getlist('uploadFiles')
        for file in files:
            if file and file.filename:
                file_path = os.path.join('file', file.filename)
                try:
                    current_client.register_files_with_tracker(file_path)
                    logging.info(f"Registered file: {file_path}")
                except Exception as e:
                    logging.error(f"Error registering file: {file_path}, error: {e}")
                    return render_template('uploadFile.html', error=f"Error registering file: {file_path}")
                
        message = "Files uploaded successfully!"
        return render_template('uploadFile.html', message=message)

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

@socketio.on('connect', namespace='/download')
def handle_download_connect():
    def send_status_updates():
        while True:
            if current_client:
                try:
                    # Lấy thông tin về tiến độ tải xuống
                    ip, port, file_name, size, status = current_client.get_status()
                    
                    # Đảm bảo `status` là phần trăm nếu cần thiết
                    if isinstance(status, float) and status <= 1:
                        status = int(status * 100)  # Chuyển đổi thành phần trăm nếu là số thập phân

                    # Gửi dữ liệu đến client
                    socketio.emit('status_update', {
                        'ip': ip,
                        'port': port,
                        'file_name': file_name,
                        'size': size,
                        'progress': status  # Đổi tên thành 'progress' để đồng nhất với HTML
                    }, namespace='/download')  # Thêm namespace cho sự kiện
                    time.sleep(2)  # Gửi dữ liệu mỗi 2 giây
                except Exception as e:
                    logging.error("Error while getting status: %s", e)
                    break

    # Khởi chạy luồng riêng để gửi dữ liệu
    thread = threading.Thread(target=send_status_updates)
    thread.daemon = True  # Đặt luồng là daemon để nó tự động dừng khi ứng dụng dừng
    thread.start()


@socketio.on('connect', namespace='/upload')
def handle_upload_connect():
    def send_file_upload():
        while True:
            if current_client:
                try:
                    seeding_files = current_client.get_seeding()
                    for ip, port, file_name, size in seeding_files:
                        status = "Seeding"
                        print('Uploading:', ip, port, file_name, size)
                        
                        socketio.emit('status_update', {
                            'ip': ip,
                            'port': port,
                            'file_name': file_name,
                            'size': size,
                            'progress': status
                        }, namespace='/upload')

                    time.sleep(2)
                except Exception as e:
                    logging.error("Error while getting upload status: %s", e)
                    break

    upload_thread = threading.Thread(target=send_file_upload)
    upload_thread.daemon = True
    upload_thread.start()



@app.route('/download', methods= ["GET"])
def download():
    return render_template('download.html')


@app.route('/upload', methods = ["GET"])
def upload():
    return render_template('upload.html')



@app.route('/logout')
# @login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/user_details')
# @login_required
def user_details():
    return render_template('user_details.html', user=current_user)



if __name__ == "__main__":
    with app.app_context():
        db.create_all() 
    #app.run(debug=True)
    socketio.run(app, debug=True)

