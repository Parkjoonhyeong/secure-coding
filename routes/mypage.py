from flask import Blueprint, render_template, session, redirect, url_for, flash
from models import db, User, Product, Transaction
from functools import wraps

mypage_bp = Blueprint('mypage', __name__)

# 로그인 필요 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("로그인이 필요합니다.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@mypage_bp.route('/mypage')
@login_required
def mypage():
    user = User.query.get(session['user_id'])
    my_products = Product.query.filter_by(seller_id=user.id).all()
    sent_transactions = Transaction.query.filter_by(sender_id=user.id).all()
    received_transactions = Transaction.query.filter_by(receiver_id=user.id).all()

    return render_template(
        'mypage.html',
        user=user,
        my_products=my_products,
        sent_transactions=sent_transactions,
        received_transactions=received_transactions
    )
