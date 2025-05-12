from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
import datetime
import os

app = Flask(__name__)
CORS(app)

# 환경 설정
SECRET_KEY = "YOUR_SECRET_KEY"
MONGO_URI = "mongodb://localhost:27017"

# MongoDB 연결
client = MongoClient(MONGO_URI)
db = client['user_db']
users = db['users']

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.get_json()
    nickname = data['nickname']
    username = data['username']
    password = data['password'].encode('utf-8')

    # 중복 유저 확인
    if users.find_one({'username': username}):
        return jsonify({'msg': 'Username already exists'}), 400
    
    if users.find_one({'nickname': nickname}):
        return jsonify({'msg': 'Username already exists'}), 400

    hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
    users.insert_one({'nickname': nickname, 'username': username, 'password': hashed_pw})
    return jsonify({'msg': 'User registered successfully'}), 201

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.get_json()
    username = data['username']
    password = data['password'].encode('utf-8')

    user = users.find_one({'username': username})
    if not user or not bcrypt.checkpw(password, user['password']):
        return jsonify({'msg': 'Invalid credentials'}), 401

    payload = {
        'user_id': str(user['_id']),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return jsonify({'token': token})

# 토큰 검증 예시
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'msg': 'Token is missing'}), 403

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'msg': f"Welcome user {payload['user_id']}!"})
    except jwt.ExpiredSignatureError:
        return jsonify({'msg': 'Token expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'msg': 'Invalid token'}), 403

if __name__ == '__main__':
    app.run('0.0.0.0', port=9000, debug=True)
