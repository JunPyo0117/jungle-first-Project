from flask import Flask, request, jsonify, render_template, make_response, redirect, url_for, flash
from flask_cors import CORS
from jwt import InvalidTokenError, ExpiredSignatureError
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
import jwt
import datetime
import csv
import random

app = Flask(__name__)
CORS(app, supports_credentials=True)  # credentials 지원 추가   

# 환경 설정
SECRET_KEY = "YOUR_SECRET_KEY"
PAGE_SECRET = "page secret key"
MONGO_URI = "mongodb://localhost:27017"
app.secret_key = 'your_secret_key'

# MongoDB 연결
client = MongoClient(MONGO_URI)
db = client['cs_paper']
users = db['users']
questions = db['questions']
answers = db['answers']
likes = db['likes']  # 좋아요 정보를 저장할 새로운 컬렉션

# 데이터 삭제
# questions.delete_many({})
answers.delete_many({})

# # csv 파일 데이터 삽입
# with open('question_list.csv', newline='', encoding='utf-8-sig') as csvfile:
#     reader = csv.DictReader(csvfile)
#     data = []
#     for row in reader:
#         row['number'] = int(row['number'].strip())  # 문자열 → 정수
#         data.append(row)

# questions.insert_many(data)

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
            if request.content_type == 'application/json':
                return jsonify({
                    'msg': '로그인이 만료되었습니다.',
                    'redirect': url_for('login')
                }), 401
            flash('로그인이 만료되었습니다.')
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            if request.content_type == 'application/json':
                return jsonify({
                    'msg': '비정상적인 접근입니다.',
                    'redirect': url_for('login')
                }), 401
            flash('비정상적인 접근입니다.')
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
        # 이미 로그인된 상태인지 확인
        token = request.cookies.get('token')
        if token:
            try:
                jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                flash('이미 로그인되어 있습니다.')
                return redirect(url_for('dashboard'))
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                pass
        return render_template('login.html')
    
    data = request.get_json()
    username = data['username']
    password = data['password'].encode('utf-8')

    user = users.find_one({'username': username})
    if not user or not bcrypt.checkpw(password, user['password']):
        return jsonify({'msg': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401

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
    # 사용자가 이미 답변한 문제 목록
    answered_questions = answers.find({'writer_id': user_payload['user_id']})
    answered_question_ids = [str(answer['question_id']) for answer in answered_questions]

    # 모든 문제 중에서 아직 답변하지 않은 문제 찾기
    unanswered_questions = list(questions.find({
        '_id': {'$nin': [ObjectId(q_id) for q_id in answered_question_ids]}
    }))

    if not unanswered_questions:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'msg': '모든 문제를 풀었습니다!',
                'redirect': url_for('dashboard')
            }), 400
        flash('모든 문제를 풀었습니다!')
        return redirect(url_for('dashboard'))

    # 학습시간 체크용 토큰 발급
    study_payload = {
        'user_id': user_payload['user_id'],
        'type': 'page',
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    }
    token = jwt.encode(study_payload, PAGE_SECRET, algorithm='HS256')

    # 답변하지 않은 문제 중에서 랜덤 선택
    random_question = random.choice(unanswered_questions)
    return render_template('study.html', question=random_question, page_token=token)


# 답변 저장하기
@app.route('/answers', methods=['POST'])
@token_required
def saveNewAnswer(payload):
    ### json 응답이 아님 (ex. form 응답의 경우 js를 비활성화한 상태에서 저장할 수 없도록 막아뒀음)
    if request.content_type != 'application/json':
        return jsonify({'msg': '올바르지 않은 접근입니다. 학습을 다시 시작해주세요.'})

    # 토큰 검증
    ### 토큰 추출
    page_token = request.get_json().get("page_token")
    if not page_token:
        return jsonify({'msg': '비정상적인 접근이 감지되었습니다. 학습을 종료합니다.'})  # 페이지 토큰 없음

    ### 디코딩
    try:
        decoded = jwt.decode(page_token, PAGE_SECRET, algorithms=['HS256'], options={"verify_iat": True},
                             leeway=5)  # 5초 허용)
        started_at = decoded.get("iat")

        if started_at is None:
            raise InvalidTokenError()

        started_at = datetime.datetime.fromtimestamp(started_at)
        now = datetime.datetime.now()
        duration = datetime.timedelta(seconds=20)

        if (started_at + duration < now):
            return jsonify({'msg': '입력시간이 정해진 시간을 비정상적으로 초과하였습니다. 학습을 종료합니다.'})

    except ExpiredSignatureError:
        return jsonify({'msg': '입력시간이 정해진 시간을 비정상적으로 초과하였습니다. 학습을 종료합니다.'}), 400
    except InvalidTokenError:
        return jsonify({'msg': '비정상적인 접근이 감지되었습니다. 학습을 종료합니다. 2'}), 400

    question_id = request.get_json().get('question_id')
    answer_content = request.get_json().get('answer')
    if answer_content is None or answer_content.replace(" ", "") == "":
        return jsonify({'msg': '답변이 입력되지 않았습니다. 학습을 다시 시작해주세요.'})

    answers.insert_one(
        {'writer_id': payload['user_id'], 'question_id': question_id, 'updated_at': datetime.datetime.now(),
         'content': answer_content})
    return redirect(url_for('study'))


# 답변 수정 페이지
@app.route('/answers/<answer_id>', methods=['GET'])
@token_required
def editPage(payload, answer_id):
    my_id = payload['user_id']
    answer = answers.find_one({'_id': ObjectId(answer_id)})
    question = questions.find_one({'_id': ObjectId(answer['question_id'])})
    writer_id = answer['writer_id']
    if (my_id != writer_id):  # 사용자 != 작성자
        return redirect(url_for('myStudy'))

    return render_template('editor.html', question=question, answer=answer)


# 수정 값 저장
@app.route('/answers/<answer_id>', methods=['POST'])
@token_required
def edit(payload, answer_id):
    answer_content = request.form.get('answer')
    question_id = request.form.get('question_id')

    if answer_content is None or answer_content.replace(" ", "") == "":
        return redirect(url_for('orderAnswer', mine=True, question_id=question_id))

    answers.update_one({'_id': ObjectId(answer_id)},
                       {'$set': {'content': answer_content, 'updated_at': datetime.datetime.now()}})
    return redirect(url_for('orderAnswer', mine=True, question_id=question_id))


# 내 학습 목록
@app.route('/mystudy', methods=['GET'])
@token_required
def myStudy(payload):
    # 카테고리 목록
    categoryList = ['All', 'Data Structure', 'Operating System', 'Network', 'Database']
    active_cate = request.args.get('cate', 'All')  # 기본값을 'All'로 설정
    query = request.args.get('q', '').strip()

    # 페이지 번호 (기본값 1)
    page = int(request.args.get('page', 1))
    per_page = 10  # 페이지당 항목 수

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
                '_id': str(question['_id']),  # ObjectId를 문자열로 변환
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

    if query:
        combined_data = [
            data for data in combined_data
            if query.lower() in data['question']['question'].lower()
        ]

    # 전체 페이지 수 계산
    total_items = len(combined_data)
    total_pages = (total_items + per_page - 1) // per_page

    # 페이지 범위 확인 및 조정
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages

    # 페이지네이션을 위한 페이지 범위 계산
    start_page = max(1, page - 1)
    end_page = min(total_pages, page + 1)

    # 현재 페이지의 데이터만 슬라이싱
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page

    # All 카테고리일 때는 페이징하지 않음
    if active_cate == 'All':
        paginated_data = combined_data
    else:
        paginated_data = combined_data[start_idx:end_idx]

    return render_template('my_study.html',
                           category=categoryList,
                           active_cate=active_cate,
                           answers=paginated_data,
                           query=query,
                           current_page=page,
                           total_pages=total_pages,
                           show_pagination=active_cate != 'All',
                           start_page=start_page,
                           end_page=end_page)


# 답변 보기
@app.route('/questions/<question_id>/answers', methods=['GET'])
@token_required
def orderAnswer(payload, question_id):
    # question_id = request.args.get('question_id')
    my_id = payload['user_id']

    if not question_id:
        return redirect(url_for('myStudy'))

    # 문제 정보 가져오기
    question = questions.find_one({'_id': ObjectId(question_id)})
    if not question:
        return redirect(url_for('myStudy'))

    mine = request.args.get('mine') == 'true'
    if mine:
        all_answers = list(answers.find({'question_id': question_id, 'writer_id': my_id}))
        print(all_answers)
    else:
        all_answers = list(answers.find({'question_id': question_id}))

    # 각 답변의 작성자 정보와 좋아요 여부 가져오기
    for answer in all_answers:
        writer = users.find_one({'_id': ObjectId(answer['writer_id'])})
        answer['writer_nickname'] = writer['nickname'] if writer else '알 수 없음'

        # 수정 버튼 표시 여부
        answer['editable'] = (answer['writer_id'] == my_id)

        # 현재 사용자가 이 답변에 좋아요를 눌렀는지 확인
        answer['is_liked'] = bool(likes.find_one({
            'user_id': payload['user_id'],
            'answer_id': str(answer['_id'])
        }))

    return render_template('order_answer.html',
                           question=question,
                           answers=all_answers)


# 다른 사람의 답변 좋아요
@app.route('/like_answer', methods=['POST'])
@token_required
def likeAnswer(payload):
    if request.content_type != 'application/json':
        return jsonify({"type": "error", 'msg': '잘못된 요청입니다.'})

    answer_id = request.get_json().get('answer_id')
    user_id = payload['user_id']

    if not answer_id:
        return jsonify({"type": "error", 'msg': '답변 ID가 필요합니다.'})

    # 이미 좋아요를 눌렀는지 확인
    existing_like = likes.find_one({
        'user_id': user_id,
        'answer_id': answer_id
    })

    if existing_like:
        # 이미 좋아요를 눌렀다면 좋아요 취소
        likes.delete_one({
            'user_id': user_id,
            'answer_id': answer_id
        })
        # 답변의 좋아요 수 감소
        answers.update_one(
            {'_id': ObjectId(answer_id)},
            {'$inc': {'likes': -1}}
        )
        is_liked = False
    else:
        # 좋아요 추가
        likes.insert_one({
            'user_id': user_id,
            'answer_id': answer_id,
            'created_at': datetime.datetime.now()
        })
        # 답변의 좋아요 수 증가
        answers.update_one(
            {'_id': ObjectId(answer_id)},
            {'$inc': {'likes': 1}}
        )
        is_liked = True

    # 업데이트된 답변의 좋아요 수 가져오기
    answer = answers.find_one({'_id': ObjectId(answer_id)})
    return jsonify({
        "type": "success",
        "likes": answer.get('likes', 0),
        "is_liked": is_liked
    })


# 답변 전체 삭제
@app.route('/remove_all', methods=['POST'])
@token_required
def removeAll(payload):
    try:
        answers.delete_many({'writer_id': payload['user_id']})
        return jsonify({'message': 'Deletion completed successfully', 'status': 'success'})
    except Exception:
        return jsonify({'message': 'Deletion failed', 'status': 'error'}), 200


if __name__ == '__main__':
    app.run('0.0.0.0', port=9000, debug=True)
