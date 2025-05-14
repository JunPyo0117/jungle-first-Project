from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
import datetime
import os
import csv

from unicodedata import category

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

# csv 파일 데이터 삽입
with open('question_list.csv', newline='', encoding='utf-8-sig') as csvfile:
    reader = csv.DictReader(csvfile)
    data = []
    for row in reader:
        row['number'] = int(row['number'].strip())  # 문자열 → 정수
        data.append(row)

questions.insert_many(data)

# 고정 데이터
categoryList = ['Data_Structure', 'Operating_System', 'Network', 'Database']

# 토큰 검증 미들웨어
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login'))

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return f(payload, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            return redirect(url_for('login'))
    decorated.__name__ = f.__name__
    return decorated

# 초기 페이지
@app.route('/', methods=['GET'])
def home():
    return redirect(url_for('dashboard'))

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

# 대시보드
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(payload):
    # 전체 문제 수 계산
    total_questions = questions.count_documents({})

    # 사용자의 답변 수 계산
    user_answers = answers.count_documents({'writer_id': payload['user_id']})

    # 가장 최근 답변 날짜 가져오기
    latest_answer = answers.find_one(
        {'writer_id': payload['user_id']},
        sort=[('updated_at', -1)]  # updated_at 기준 내림차순 정렬
    )

    latest_date = latest_answer['updated_at'] if latest_answer else None

    return render_template('dashboard.html',
                         nickname=payload['nickname'],
                         total_questions=total_questions,
                         user_answers=user_answers,
                         latest_date=latest_date)

# 학습하기
@app.route('/study', methods=['GET'])
@token_required
def study(user_payload):
    # 학습시간 체크용 토큰 발급
    study_payload = {
        'user_id': user_payload['user_id'],
        'type': 'page',
        'iat': datetime.datetime.now(),
        'exp': datetime.datetime.now() + datetime.timedelta(minutes=5)
    }
    token = jwt.encode(study_payload, 'PAGE_SECRET', algorithm='HS256')

    random_question = questions.aggregate([{"$sample": {"size": 1}}]).next();
    return render_template('study.html', question=random_question, page_token=token);

# 답변 저장하기
@app.route('/answers', methods=['POST'])
@token_required
def saveNewAnswer(payload):
    if request.content_type != 'application/json':
        return jsonify({"type": "error", 'msg': '올바르지 않은 답변 방식입니다.'})

    question_id = request.get_json().get('question_id')
    answer_content = request.get_json().get('answer')
    if answer_content is None or answer_content.replace(" ", "") == "":
        return jsonify({"type": "pass", 'msg': '답변이 입력되지 않아 저장되지 않았습니다.'})

    answers.insert_one({'writer_id': payload['user_id'], 'question_id': question_id, 'updated_at': datetime.datetime.now(), 'content': answer_content})
    return redirect(url_for('study'))

# 내 학습 목록
@app.route('/mystudy', methods=['GET'])
@token_required
def myStudy(payload):
    # 카테고리 목록
    categoryList = ['All', 'Data Structure', 'Operating System', 'Network', 'Database']
    active_cate = request.args.get('cate', 'All')  # 기본값을 'All'로 설정
    
    all_questions = list(questions.find())
    
    # 사용자의 답변 목록 가져오기
    user_answers = list(answers.find(
        {'writer_id': payload['user_id']},
        sort=[('updated_at', -1)]  # 최신순 정렬
    ))
    
    
    # 답변과 문제 정보 결합
    combined_data = []
    for question in all_questions:
        # 해당 문제에 대한 사용자의 답변 찾기
        answer = next((a for a in user_answers if str(a['question_id']) == str(question['_id'])), None)
        
        # 문제 정보와 답변 정보 결합
        combined_data.append({
            'question': {
                'category': question.get('category', ''),
                'question': question.get('question', ''),
                'number': question.get('number', '')
            },
            'content': answer['content'] if answer else None,
            'updated_at': answer['updated_at'] if answer else None
        })
    
    # 카테고리별 필터링 ('All'이 아닐 때만 필터링)
    if active_cate and active_cate != 'All':
        combined_data = [data for data in combined_data if data['question']['category'] == active_cate]
    
    
    return render_template('my_study.html', 
                         category=categoryList, 
                         active_cate=active_cate,
                         answers=combined_data)

if __name__ == '__main__':
    app.run('0.0.0.0', port=9000, debug=True)
