from flask import Flask, render_template, redirect, url_for, request, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from functools import wraps
from models import db, User, Product, Chat, Transaction
from routes.mypage import mypage_bp
import os

# Blueprint import
from routes.mypage import mypage_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-coding-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
bcrypt = Bcrypt(app)
db.init_app(app)

# Register Blueprints
app.register_blueprint(mypage_bp)

# ---------------------- AUTH DECORATORS ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("관리자 권한이 필요합니다.")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- ROUTES ----------------------
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
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
        flash('로그인 실패. 아이디 또는 비밀번호를 확인해주세요.')
    return render_template('login.html')

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

    return render_template(
        'admin_dashboard.html',
        users=users,
        products=products,
        transactions=transactions,
        user_count=user_count,
        product_count=product_count,
        total_points=total_points
    )

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

@app.route('/products/new', methods=['GET', 'POST'])
@login_required
def create_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        product = Product(name=name, description=description, seller_id=session['user_id'])
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

# ---------------------- MAIN ----------------------
if __name__ == '__main__':
    os.makedirs('certs', exist_ok=True)
    if not os.path.exists('certs/cert.pem') or not os.path.exists('certs/key.pem'):
        print("🔐 인증서가 없습니다. openssl로 self-signed 인증서를 생성해주세요.")
    else:
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

        app.run(ssl_context=('certs/cert.pem', 'certs/key.pem'), debug=True)