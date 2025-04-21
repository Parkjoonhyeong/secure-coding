from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_dormant = db.Column(db.Boolean, default=False)

    # 관계 설정
    products = db.relationship('Product', backref='seller', lazy=True)
    sent_chats = db.relationship('Chat', foreign_keys='Chat.sender_id', backref='sender', lazy=True)
    received_chats = db.relationship('Chat', foreign_keys='Chat.receiver_id', backref='receiver', lazy=True)
    sent_transactions = db.relationship('Transaction', foreign_keys='Transaction.sender_id', backref='sender', lazy=True)
    received_transactions = db.relationship('Transaction', foreign_keys='Transaction.receiver_id', backref='receiver', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text, nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Integer, nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    target_product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    reason = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    # 관계 설정 (backref 없이, 명시적 관계만 설정)
    reporter = db.relationship('User', foreign_keys=[reporter_id], lazy=True)
    target_user = db.relationship('User', foreign_keys=[target_user_id], lazy=True)
    target_product = db.relationship('Product', foreign_keys=[target_product_id], lazy=True)
