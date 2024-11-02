from flask import Flask, request, render_template, redirect, url_for, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from main import download
from db import User, db
import os
import logging
################################################################################
import time
import json
from flask import jsonify
import threading
#################################################################################
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


@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    search_results = []
    if request.method == 'POST':
        search_query = request.form.get('search_query')  
        search_results = search_files(search_query)  
    return render_template('index.html', search_results=search_results)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/user_details')
@login_required
def user_details():
    return render_template('user_details.html', user=current_user)

"""
@app.route('/connect_to_all_peers_and_download/<filename>', methods=['GET'])
def connect_to_all_peers_and_download(filename):
    torrent_file = os.path.join('path_to_torrent_files', filename)  # Đường dẫn tới file torrent
    output_file = os.path.join('path_to_output_files', 'downloaded_file')  # Đường dẫn lưu file tải về

    # Gọi hàm download từ main.py để tải file từ tất cả các peer
    try:
        success = download(torrent_file, output_file)  # Thực hiện tải xuống

        if success:
            # Trả file đã tải xuống cho người dùng
            return send_file(output_file, as_attachment=True)
        else:
            return "Failed to download the file from peers.", 500
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred during download.", 500
"""

def search_files(query):
    files = ["file1.txt", "file2.txt", "file3.txt"]  
    results = [file for file in files if query.lower() in file.lower()]
    return results
#####################################################################################
# Thêm biến global để theo dõi downloads
downloads = {}

# Thêm các route mới vào file app.py hiện tại
@app.route('/downloads')
@login_required
def downloads_page():
    return render_template('downloads.html')

@app.route('/api/add-torrent', methods=['POST'])
@login_required
def add_torrent():
    try:
        torrent_file = request.files['torrent']
        if torrent_file:
            # Tạo thư mục để lưu file nếu chưa tồn tại
            os.makedirs('static/torrents', exist_ok=True)
            os.makedirs('static/downloads', exist_ok=True)
            
            # Lưu file torrent
            torrent_path = os.path.join('static/torrents', torrent_file.filename)
            torrent_file.save(torrent_path)
            
            # Tạo ID cho download
            download_id = len(downloads) + 1
            
            # Tạo thông tin download
            downloads[download_id] = {
                'id': download_id,
                'fileName': torrent_file.filename,
                'size': os.path.getsize(torrent_path),
                'progress': 0,
                'status': 'starting',
                'user_id': current_user.id
            }
            
            # Bắt đầu download trong thread riêng
            thread = threading.Thread(
                target=start_download,
                args=(download_id, torrent_path)
            )
            thread.start()
            
            return jsonify({'success': True, 'downloadId': download_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/downloads', methods=['GET'])
@login_required
def get_downloads():
    user_downloads = {k: v for k, v in downloads.items() 
                     if v['user_id'] == current_user.id}
    return jsonify(list(user_downloads.values()))

@app.route('/api/cancel-download/<int:download_id>', methods=['POST'])
@login_required
def cancel_download(download_id):
    if download_id in downloads and downloads[download_id]['user_id'] == current_user.id:
        downloads[download_id]['status'] = 'cancelled'
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Download not found'})

def start_download(download_id, torrent_path):
    try:
        output_path = os.path.join('static/downloads', 
                                  downloads[download_id]['fileName'])
        
        # Giả lập tiến trình download (thay thế bằng hàm download thật của bạn)
        for i in range(101):
            if downloads[download_id]['status'] == 'cancelled':
                break
            downloads[download_id]['progress'] = i
            time.sleep(0.5)
        
        downloads[download_id]['status'] = 'completed'
    except Exception as e:
        downloads[download_id]['status'] = 'error'
        print(f"Download error: {e}")
##################################################################################################

if __name__ == "__main__":
    with app.app_context():
        db.create_all() 
    app.run(debug=True)
