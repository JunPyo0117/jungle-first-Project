from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
import datetime
import os
import csv

app = Flask(__name__)
CORS(app, supports_credentials=True)  # credentials 지원 추가   

# 환경 설정
SECRET_KEY = "YOUR_SECRET_KEY"
MONGO_URI = "mongodb://localhost:27017"

# MongoDB 연결
client = MongoClient(MONGO_URI)
db = client['cs_paper']
users = db['users']
questions = db['questions']
answers = db['answers']

# 데이터 삭제
questions.delete_many({})

# 데이터 삽입
with open('question_list.csv', newline='', encoding='utf-8-sig') as csvfile:
    reader = csv.DictReader(csvfile)
    data = list(reader)

questions.insert_many(data)


# 토큰 검증 미들웨어
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'msg': 'Token is missing'}), 403

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return f(payload, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'msg': 'Token expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'msg': 'Invalid token'}), 403
    decorated.__name__ = f.__name__
    return decorated

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    data = request.get_json()
    username = data['username']
    password = data['password'].encode('utf-8')
    nickname = data.get('nickname', '')  # 닉네임 추가

    # 중복 유저 확인
    if users.find_one({'username': username}):
        return jsonify({'msg': 'Username already exists'}), 400

    hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
    users.insert_one({
        'username': username,
        'password': hashed_pw,
        'nickname': nickname
    })
    return jsonify({'msg': 'User registered successfully'}), 201

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    # if request.method == 'GET':
    #     return render_template('login.html')
    
    data = request.get_json()
    username = data['username']
    password = data['password'].encode('utf-8')

    user = users.find_one({'username': username})
    if not user or not bcrypt.checkpw(password, user['password']):
        return jsonify({'msg': 'Invalid credentials'}), 401

    payload = {
        'user_id': str(user['_id']),
        'username': user['username'],
        'nickname': user.get('nickname', ''),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    # HTTP-only 쿠키로 토큰 설정
    response = make_response(jsonify({'msg': 'Login successful'}))
    response.set_cookie(
        'token',
        token,
        httponly=True,
        secure=True,  # HTTPS에서만 전송
        samesite='Strict',  # CSRF 방지
        max_age=3600  # 1시간
    )
    return response


# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({'msg': 'Logout successful'}))
    response.delete_cookie('token')
    return response


# 보호된 라우트 테스트 예시 
@app.route('/protected', methods=['GET'])
@token_required
def protected(payload):
    return jsonify({
        'msg': f"Welcome {payload['nickname'] or payload['username']}!",
        'user_id': payload['user_id']
    })

@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(payload):
    return render_template('dashboard.html', nickname=payload['nickname'])

@app.route('/study', methods=['GET'])
@token_required
def study(payload):
    random_question = questions.aggregate([{"$sample": {"size": 1}}]).next();
    return render_template('study.html', question=random_question)


@app.route('/answers', methods=['POST'])
@token_required
def saveNewAnswer(payload):
    if request.content_type == 'application/json':
        question_id = request.get_json().get('question_id')
        answer_content = request.get_json().get('answer')
    else:
        question_id = request.form.get('question_id')
        answer_content = request.form.get('answer')

    answers.insert_one({'writer_id': payload['user_id'], 'question_id': question_id, 'updated_at': datetime.datetime.now(), 'content': answer_content})
    return redirect(url_for('study'))


if __name__ == '__main__':
    app.run('0.0.0.0', port=9000, debug=True)
