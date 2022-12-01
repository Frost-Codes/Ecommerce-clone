from flask import Flask, render_template, redirect, request, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, FileField, IntegerField
from wtforms.validators import DataRequired, length, NumberRange
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime
from base64 import b64encode
import requests
import smtplib
import time
from time import sleep

gmail_account = ''
gmail_password = ''


def send_mail(recipient):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_account, gmail_password)
        server.sendmail(gmail_account, recipient, 'Congratulations for signing up!!!')
        print('Sign up mail sent')
    except:
        print('Mail not sent')


# Mpesa details
SHORT_CODE = 174379
CONSUMER_KEY = 'euPmFSqivio2JrC6slwOZtT0NnUAisZA'
CONSUMER_SECRET = 'TsHdpG2TGl5dBMPZ'
PASS_KEY = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'


def generate_pass_key():
    time_now = datetime.now().strftime("%Y%m%d%H%M%S")
    s = str(SHORT_CODE) + str(PASS_KEY) + time_now
    encoded = b64encode(s.encode('utf-8')).decode('utf-8')
    return encoded


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SECRET_KEY'] = 'my secret key'
database_password = 'ianmurimi'
database_hash = generate_password_hash(database_password)
db = SQLAlchemy(app)


# login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    """Log in user to shop if details are correct"""
    return Customer.query.get(int(user_id))


# Phone number form class
class PhoneNumberForm(FlaskForm):
    number = IntegerField(validators=[DataRequired(), length(min=10, max=10)])


# Sign up form class
class SignUpForm(FlaskForm):
    username = StringField(validators=[DataRequired(), length(min=3)])
    email = StringField(validators=[DataRequired(), length(min=4)])
    password1 = PasswordField(validators=[DataRequired(), length(min=6)])
    password2 = PasswordField(validators=[DataRequired(), length(min=6)])
    submit = SubmitField('Sign up')


# Log in form class
class LogInForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    submit = SubmitField('Log in')


# Shop items class
class ShopItemsForm(FlaskForm):
    # picture = FileField(validators=[DataRequired()])
    name = StringField('Name of item', validators=[DataRequired()])
    current_price = IntegerField(validators=[DataRequired()])
    previous_price = IntegerField(validators=[DataRequired()])
    remaining = IntegerField(validators=[NumberRange(min=1)])
    quantity = IntegerField(validators=[DataRequired(), NumberRange(min=1)])
    update_cart = SubmitField('Update')
    add_item = SubmitField('Add item')


# Customer class
class Customer(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    email = db.Column(db.String(20), nullable=False, unique=True)
    password_hash = db.Column(db.String(100))
    cart_items = db.relationship('CartItem', backref='cartItems', uselist=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Customer %r>' % self.id


# Items class
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    current_price = db.Column(db.Integer, nullable=False)
    previous_price = db.Column(db.Integer, nullable=False)
    remaining = db.Column(db.Integer, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Item %r>' % self.id


# Cart items class
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_link = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    item_name = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return '<CartItem %r>' % self.id


# log in users
@app.route('/', methods=['POST', 'GET'])
def login():
    email = None
    password = None
    form = LogInForm()
    if form.validate_on_submit():
        customer = Customer.query.filter_by(email=form.email.data).first()
        if customer:
            if check_password_hash(customer.password_hash, form.password.data):
                check = customer.id
                login_user(customer)
                return redirect('/amazon/')
            else:
                flash('Wrong password!! Try again...', category='error')
        else:
            flash('Account does not exit...Create one from the sign up page...', category='error')

        form.email.data = ''
        form.password.data = ''
    return render_template('login.html', email=email, password=password, form=form)


# sign up new users
@app.route('/signup/', methods=['POST', 'GET'])
def signup():
    email = None
    username = None
    password1 = None
    password2 = None
    form = SignUpForm()
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password1 = form.password1.data
        password2 = form.password2.data
        if password1 == password2:
            new_customer = Customer()
            new_customer.email = email
            new_customer.username = username
            new_customer.password = password2
            try:
                db.session.add(new_customer)
                db.session.commit()
                send_mail(new_customer.email)
                flash('Account created successfully', category='success')
                return redirect('/')
            except:
                flash('There was an error adding the new account', category='error')
        form.email.data = ''
        form.username.data = ''
        form.password1.data = ''
        form.password2.data = ''
    return render_template('signup.html', email=email, username=username, password1=password1, password2=password2,
                           form=form)


# log out current user
@app.route('/logout', methods=['POST', 'GET'])
@login_required
def log_out():
    logout_user()
    flash('Thank you for shopping with us...', category='success')
    return redirect('/')


# display current customers
@app.route('/customers', methods=['POST', 'GET'])
@login_required
def customer_display():
    customers = Customer.query.order_by(Customer.date_joined).all()
    return render_template('customers.html', customers=customers)


# remove customer
@app.route('/removecustomer/<int:id>')
def remove_customer(id):
    customer_to_remove = Customer.query.get_or_404(id)
    try:
        db.session.delete(customer_to_remove)
        db.session.commit()
        return redirect('/customers')
    except:
        return 'There was an error removing that customer'


# shop display
@app.route('/amazon/', methods=['GET', 'POST'])
@login_required
def amazon():
    items = Item.query.order_by(Item.date_added).all()
    items_list = [item for item in items]
    return render_template('shop.html', items_list=items_list)


# Admin section adding, updating add deleting shop items
@app.route('/databaseupdate/', methods=['POST', 'GET'])
def database_update():
    password = None
    form = LogInForm()
    if form.validate_on_submit():
        if check_password_hash(database_hash, form.password.data):
            flash('Admin log in')
            return redirect('/')
        else:
            flash('Invalid password!!!!')
        form.password.data = ''
    return render_template('database.html', form=form, password=password)


# display add remove shop items
@app.route('/shopitems/', methods=['GET', 'POST'])
@login_required
def shop_items():
    if request.method == 'POST':
        name = request.form.get('name')
        current_price = request.form.get('current_price')
        previous_price = request.form.get('previous_price')
        remaining = request.form.get('remaining')
        new_item = Item(name=name, current_price=current_price, previous_price=previous_price, remaining=remaining)
        try:
            db.session.add(new_item)
            db.session.commit()
            return redirect('/shopitems/')
        except:
            flash('There was an  error adding a new shop item', category='error')

    items = Item.query.order_by(Item.date_added).all()
    return render_template('shopitems.html', items=items)


# deleting items from database
@app.route('/delete/<int:id>')
def delete(id):
    item_to_delete = Item.query.get_or_404(id)
    try:
        db.session.delete(item_to_delete)
        db.session.commit()
        return redirect('/shopitems/')
    except:
        return 'There was an error deleting that item'


# updating shop items
@app.route('/update/<int:id>', methods=['POST', 'GET'])
def update(id):
    item = Item.query.get_or_404(id)
    if request.method == 'POST':
        item.name = request.form.get('name')
        item.current_price = request.form.get('current_price')
        item.previous_price = request.form.get('previous_price')
        item.remaining = request.form.get('remaining')
        try:
            db.session.commit()
            return redirect('/shopitems/')
        except:
            return 'There was an error updating that item'
    else:
        return render_template('update.html', item=item)


# adding items to current user cart
@app.route('/addtocart/<int:id>', methods=['POST', 'GET'])
def add_to_cart(id):
    item = Item.query.get_or_404(id)
    new_cart_item = CartItem()
    new_cart_item.item_name = item.name
    new_cart_item.price = item.current_price
    new_cart_item.quantity = 1
    new_cart_item.customer_link = current_user.id
    try:
        db.session.add(new_cart_item)
        db.session.commit()
        return redirect('/amazon/')
    except:
        return 'Item not added'


# update cart item
@app.route('/updatecart/<int:id>', methods=['POST', 'GET'])
def update_item(id):
    item = CartItem.query.get_or_404(id)
    quantity = None
    form = ShopItemsForm()
    if form.validate_on_submit():
        item.quantity = form.quantity.data
        try:
            db.session.commit()
            return redirect('/cart/')
        except:
            flash('There was an error updating your cart', category='error')
    return render_template('updatecart.html', form=form, quantity=quantity)


# removing items from current user cart
@app.route('/remove/<int:id>', methods=['POST', 'GET'])
def remove_item(id):
    item_to_remove = CartItem.query.get_or_404(id)
    try:
        db.session.delete(item_to_remove)
        db.session.commit()
        return redirect('/cart/')
    except:
        return 'Item not deleted'


# displaying current user cart
@app.route('/cart/', methods=['POST', 'GET'])
def cart():
    items = CartItem.query.filter_by(customer_link=current_user.id).all()
    total, quantity_total = 0, 0
    for item in items:
        quantity_total = quantity_total + item.quantity
        value = item.price * item.quantity
        total = total+value
    return render_template('cart.html', items=items, total=total, quantity_total=quantity_total)


# payment page
@app.route('/payment', methods=['POST', 'GET'])
def payment():
    # do payment staff and delete items from current user cart
    return render_template('payment.html')


# paying logic
@app.route('/pay', methods=['POST', 'GET'])
def pay():
    if request.method == 'POST':
        number = request.form.get('phone')
        number = str(number)
        number = number[1:]
        str_number = '254' + number
        final_no = int(str_number)
        items = CartItem.query.filter_by(customer_link=current_user.id).all()
        total, quantity_total = 0, 0
        for item in items:
            quantity_total = quantity_total + item.quantity
            value = item.price * item.quantity
            total = total + value
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer c8O4xyARyxfUTJ6WGe5xjdyeGjGB'
        }

        payload = {
            "BusinessShortCode": SHORT_CODE,
            "Password": generate_pass_key(),
            "Timestamp": datetime.now().strftime("%Y%m%d%H%M%S"),
            "TransactionType": "CustomerPayBillOnline",
            "Amount": total,
            "PartyA": final_no,
            "PartyB": SHORT_CODE,
            "PhoneNumber": final_no,
            "CallBackURL": "https://mydomain.com/path",
            "AccountReference": "Ian LTD",
            "TransactionDesc": "Confirm payment to Ian Limited"
        }

        response = requests.request("POST", 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
                                    headers=headers, data=payload)

        print(payload.items())
        print(total)
        print(response.text.encode('utf8'))
        return 'Thank you for shopping with us...Enter PIN to confirm payment'


if __name__ == '__main__':
    app.run(debug=True)

