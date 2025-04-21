from flask import Flask, render_template, redirect, url_for, request, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from flask_socketio import SocketIO, emit
from models import db, User, Product, Chat, Transaction, Report
from routes.mypage import mypage_bp
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-coding-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bcrypt = Bcrypt(app)
db.init_app(app)
socketio = SocketIO(app)
app.register_blueprint(mypage_bp)

# 인증 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 전용
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("관리자 권한이 필요합니다.")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    query = request.args.get('q', '')
    if query:
        products = Product.query.filter(Product.name.contains(query)).all()
    else:
        products = Product.query.all()
    return render_template('index.html', products=products, query=query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('회원가입 성공! 로그인해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.is_dormant:
                flash("휴면 계정은 로그인할 수 없습니다. 관리자에게 문의하세요.")
                return redirect(url_for('login'))
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
        flash('로그인 실패. 아이디 또는 비밀번호를 확인해주세요.')
    return render_template('login.html')


@app.route('/admin/dormant_check', methods=['POST'])
@admin_required
def check_dormant_users():
    threshold = 3
    since = datetime.utcnow() - timedelta(days=7)

    subquery = db.session.query(
        Report.target_user_id,
        db.func.count(Report.id).label("report_count")
    ).filter(
        Report.target_user_id != None,
        Report.created_at >= since
    ).group_by(Report.target_user_id).subquery()

    flagged_users = db.session.query(User).join(
        subquery, User.id == subquery.c.target_user_id
    ).filter(subquery.c.report_count >= threshold).all()

    for user in flagged_users:
        user.is_dormant = True

    db.session.commit()
    flash(f"휴면 처리된 유저 수: {len(flagged_users)}명")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unmark_dormant/<int:user_id>', methods=['POST'])
@admin_required
def unmark_user_dormant(user_id):
    user = User.query.get_or_404(user_id)
    user.is_dormant = False
    db.session.commit()
    flash(f"{user.username} 계정의 휴면이 해제되었습니다.")
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    products = Product.query.all()
    transactions = Transaction.query.order_by(Transaction.id.desc()).limit(10).all()
    user_count = User.query.count()
    product_count = Product.query.count()
    total_points = db.session.query(db.func.sum(Transaction.amount)).scalar() or 0
    return render_template('admin_dashboard.html', users=users, products=products,
                           transactions=transactions, user_count=user_count,
                           product_count=product_count, total_points=total_points)

@app.route('/admin/reports')
@admin_required
def manage_reports():
    user_reports = Report.query.filter(Report.target_user_id != None).all()
    product_reports = Report.query.filter(Report.target_product_id != None).all()
    return render_template('admin_reports.html', user_reports=user_reports, product_reports=product_reports)

@app.route('/admin/reports/delete/user/<int:report_id>', methods=['POST'])
@admin_required
def delete_user_report(report_id):
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    flash("사용자 신고가 삭제되었습니다.")
    return redirect(url_for('manage_reports'))

@app.route('/admin/reports/delete/product/<int:report_id>', methods=['POST'])
@admin_required
def delete_product_report(report_id):
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    flash("상품 신고가 삭제되었습니다.")
    return redirect(url_for('manage_reports'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session['user_id']:
        flash('자기 자신은 삭제할 수 없습니다.')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(user)
    db.session.commit()
    flash(f'사용자 {user.username}가 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@admin_required
def delete_product_admin(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash(f'상품 {product.name}이 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dormant/<int:user_id>', methods=['POST'])
@admin_required
def mark_user_dormant(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash("관리자는 휴면 처리할 수 없습니다.")
        return redirect(url_for('admin_dashboard'))
    user.is_dormant = True
    db.session.commit()
    flash(f"{user.username} 계정이 휴면 처리되었습니다.")
    return redirect(url_for('admin_dashboard'))


@app.route('/products/new', methods=['GET', 'POST'])
@login_required
def create_product():
    user = User.query.get(session['user_id'])
    if user.is_dormant:
        flash("휴면 계정은 상품을 등록할 수 없습니다. 관리자에게 문의하세요.")
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        product = Product(name=name, description=description, seller_id=user.id)
        db.session.add(product)
        db.session.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('index'))
    return render_template('create_product.html')


@app.route('/admin/transactions')
@admin_required
def all_transactions():
    transactions = Transaction.query.order_by(Transaction.id.desc()).all()
    return render_template('admin_transactions.html', transactions=transactions)

@app.route('/products/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    seller = User.query.get(product.seller_id)
    return render_template('product_detail.html', product=product, seller=seller)

@app.route('/products/<int:product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)
    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        db.session.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('product_detail', product_id=product.id))
    return render_template('edit_product.html', product=product)

@app.route('/products/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    if product.seller_id != session['user_id']:
        abort(403)
    db.session.delete(product)
    db.session.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('index'))

@app.route('/chat/send/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def send_chat(receiver_id):
    receiver = User.query.get_or_404(receiver_id)
    if request.method == 'POST':
        message = request.form['message']
        chat = Chat(sender_id=session['user_id'], receiver_id=receiver_id, message=message)
        db.session.add(chat)
        db.session.commit()
        flash('메시지를 보냈습니다.')
        return redirect(url_for('chat_history', user_id=receiver_id))
    return render_template('send_chat.html', receiver=receiver)

@app.route('/chat/<int:user_id>')
@login_required
def chat_history(user_id):
    chats = Chat.query.filter(
        ((Chat.sender_id == session['user_id']) & (Chat.receiver_id == user_id)) |
        ((Chat.sender_id == user_id) & (Chat.receiver_id == session['user_id']))
    ).order_by(Chat.id.asc()).all()
    other_user = User.query.get(user_id)
    return render_template('chat_history.html', chats=chats, other_user=other_user)

@app.route('/chat/room')
@login_required
def global_chat():
    return render_template('chat_room.html', username=session.get('username'))

@socketio.on('send_message')
def handle_send_message(data):
    emit('receive_message', {
        'username': session.get('username'),
        'message': data['message']
    }, broadcast=True)

@app.route('/transfer/<int:receiver_id>', methods=['GET', 'POST'])
@login_required
def transfer(receiver_id):
    receiver = User.query.get_or_404(receiver_id)
    if receiver.id == session['user_id']:
        flash('자기 자신에게는 송금할 수 없습니다.')
        return redirect(url_for('index'))
    if request.method == 'POST':
        amount = int(request.form['amount'])
        if amount <= 0:
            flash('올바른 금액을 입력하세요.')
        else:
            transaction = Transaction(sender_id=session['user_id'], receiver_id=receiver_id, amount=amount)
            db.session.add(transaction)
            db.session.commit()
            flash(f'{receiver.username}님에게 {amount}포인트를 송금했습니다.')
            return redirect(url_for('transaction_history'))
    return render_template('transfer.html', receiver=receiver)

@app.route('/transactions')
@login_required
def transaction_history():
    sent = Transaction.query.filter_by(sender_id=session['user_id']).all()
    received = Transaction.query.filter_by(receiver_id=session['user_id']).all()
    return render_template('transactions.html', sent=sent, received=received)

@app.route('/report/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def report_user(user_id):
    if request.method == 'POST':
        reason = request.form['reason']
        report = Report(reporter_id=session['user_id'], target_user_id=user_id, reason=reason)
        db.session.add(report)
        db.session.commit()
        flash('사용자를 신고했습니다.')
        return redirect(url_for('index'))
    return render_template('report_form.html')

@app.route('/report/product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def report_product(product_id):
    if request.method == 'POST':
        reason = request.form['reason']
        report = Report(reporter_id=session['user_id'], target_product_id=product_id, reason=reason)
        db.session.add(report)
        db.session.commit()
        flash('상품을 신고했습니다.')
        return redirect(url_for('index'))
    return render_template('report_form.html')

# ------------------ MAIN ------------------
if __name__ == '__main__':
    import gevent.monkey
    gevent.monkey.patch_all()

    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password=bcrypt.generate_password_hash('admin').decode('utf-8'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print('✅ 관리자 계정(admin / admin)이 생성되었습니다.')

    # gevent를 사용하는 HTTPS 서버 실행
    from gevent.pywsgi import WSGIServer
    from geventwebsocket.handler import WebSocketHandler

    http_server = WSGIServer(
        ('0.0.0.0', 5000),
        app,
        keyfile='certs/key.pem',
        certfile='certs/cert.pem',
        handler_class=WebSocketHandler
    )
    print("🚀 서버 시작: https://localhost:5000")
    http_server.serve_forever()
