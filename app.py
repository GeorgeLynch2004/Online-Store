from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField, EmailField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import asc
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

# Initialisation _________________________________________________________________________________________________

#Create a Flask Instance
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Super Secret Key'

#Create database for Flask
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
db = SQLAlchemy(app)

# Flask_login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# End Of Initialisation ___________________________________________________________________________________________

# Database Models _______________________________________________________________________________________________

# Create database model for review page
class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    item_concerning = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return super().__repr__()

# Create database model for users
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return super().__repr__()


# Create database model for products
class products(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String, nullable=False)
    impact = db.Column(db.String, nullable=False)
    image = db.Column(db.String, nullable=False)

    def __repr__(self) -> str:
        return super().__repr__()


# Create basket model to keep track of what is in who's basket
class baskets(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    basket_id = db.Column(db.Integer)
    item_id = db.Column(db.Integer)

# End Of Database Models _______________________________________________________________________________________________

# Forms ________________________________________________________________________________________________________

# Create a form class for the Review Page
class ReviewForm(FlaskForm):
    name = StringField("What's your name?", validators=[DataRequired()])
    item = StringField("What item does this concern?", validators=[DataRequired()])
    review = StringField("Leave your review here:", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a form class for the Login Page
class LoginForm(FlaskForm):
    username = StringField("Enter Username:", validators=[DataRequired()])
    password = PasswordField("Enter Password:", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a form class for Signup Page
class SignupForm(FlaskForm):
    email = EmailField("Enter Email:", validators=[DataRequired()])
    username = StringField("Enter Username:", validators=[DataRequired()])
    password1 = PasswordField("Enter Password:", validators=[DataRequired()])
    password2 = PasswordField("re-enter Password:", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Create a form class for Checkout page
class CheckoutForm(FlaskForm):
    cardholder = StringField("Enter cardholder name: ", validators=[DataRequired()])
    telephone = StringField("Enter Telephone Number: ", validators=[DataRequired()])
    address = StringField("Delivery Address: ", validators=[DataRequired()])
    postcode = StringField("Postcode: ", validators=[DataRequired()])
    card = StringField("Enter Credit Card Details: ", validators=[DataRequired()])
    expiry = StringField("Enter Card Expiry Date: ", validators=[DataRequired()])
    CVV = StringField("Enter Card CVV: ", validators=[DataRequired()])
    submit = SubmitField("Submit")

# End of Forms _________________________________________________________________________________________

# Routes _______________________________________________________________________________________________________

# Checkout Code _____________________________________________________________________________________________________

@app.route('/<name>/checkout', methods=['GET', 'POST'])
@login_required
def checkout(name):
    cardholder = None
    telephone = None
    address = None
    postcode = None
    card = None
    expiry = None
    cvv = None
    form = CheckoutForm()
    # Get the corresponding basket contents using the current user id
    current_user_id = Users.query.filter_by(username=current_user.username).with_entities(Users.id).scalar()
    contents = baskets.query.filter_by(basket_id=current_user_id).with_entities(baskets.item_id).all()
    fixed = []
    for item in contents:
        item = str(item)
        item = item.replace("(","")
        item = item.replace(")","")
        item = item.replace(",","")
        fixed.append(item)
    details = []
    for item in fixed:
        detail = products.query.filter_by(id=item).with_entities(products.id, products.name, products.price).first()
        details.append(detail)
    max = 0
    for detail in details:
        max = max + detail.price
        
    if max <= 0:
        return render_template("basket.html")
        
    if form.validate_on_submit():
        cardholder = form.cardholder.data
        form.cardholder.data = ''
        address = form.address.data
        form.address.data = ''
        card = form.card.data
        form.card.data = ''
        telephone = form.telephone.data
        form.telephone.data = ''
        postcode = form.postcode.data
        form.postcode.data = ''
        expiry = form.expiry.data
        form.expiry.data = ''
        cvv = form.CVV.data
        form.CVV.data = ''

        current_user_id = Users.query.filter_by(username=current_user.username).with_entities(Users.id).scalar()
        item_remove = baskets.query.filter_by(basket_id=current_user_id).all()

        for item in item_remove:
            db.session.delete(item)
            db.session.commit()


        print("form submitted")

        # Checking the credit card
        check = credit_card_check(card)
        if check == True:
            flash("Checkout Complete")
            return render_template('complete.html', name=name)
        else:
            flash("Details Invalid")
            return render_template('checkout.html', total=max, cardholder=cardholder, address=address, card=card, form=form)
        
         
    return render_template('checkout.html', total=max, cardholder=cardholder, address=address, card=card, form=form)

# Email checker to ensure it is a valid format
def email_checker(email):
    requirements = "@", "."
    count = 0
    for requirement in requirements:
        if requirement in email:
            count += 1
    
    if count == 2:
        return True
    else:
        return False


# Credit card checker to ensure it is a valid format
def credit_card_check(card):
    numbers = ("1","2","3","4","5","6","7","8","9","0")
    strippers = (" ", "-")
    card = str(card)
    
    for digit in card:
        if digit in strippers:
            card = card.replace(digit, "")

    print("Card: " + card)

    if len(card) == 16:
        for digit in card:
            if digit not in numbers:
                return False
        return True
    else:
        print("length issue")
        return False

# End Of Checkout Code _____________________________________________________________________________________________________

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/user/<name>')
def user(name):
    return render_template('user.html', name=name)

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

# Item Page Handling Code _______________________________________________________________________________

# Code to display the items page
@app.route('/items')
@login_required
def items():
    data = products.query.all()
    return render_template('items.html', data=data)

@app.route('/expansion/<select_name>')
@login_required
def expansion(select_name):
    data = products.query.filter_by(name=select_name).with_entities(products.id, products.name, products.price, products.description, products.impact, products.image).first()
    print(data)
    return render_template('expansion.html', data=data)

# Code for ordering the way items appear
@app.route('/alphabetical')
@login_required
def alphabetical():
    data = products.query.order_by(asc(products.name)).all()
    return render_template('items.html', data=data)

@app.route('/price-low-to-high')
@login_required
def price_low_to_high():
    data = products.query.order_by(asc(products.price)).all()
    return render_template('items.html', data=data)


@app.route('/env-low-to-high')
@login_required
def env_low_to_high():
    data = products.query.order_by(asc(products.impact)).all()
    return render_template('items.html', data=data)

# End Of Item Page Handling Code _______________________________________________________________________________

# Basket Page Handling Code ____________________________________________________________________________________

# Code to implement removing from basket
@app.route('/basket/remove', methods=['GET', 'POST'])
@login_required
def remove_from_basket():
    if request.method == 'POST':
        product_id = request.form['id']
        remove(product_id)
        return redirect(url_for('basket'))
    else:
        data = products.query.all()
        return render_template('items.html', data=data)

def remove(product_id):
    current_user_id = Users.query.filter_by(username=current_user.username).with_entities(Users.id).scalar()
    item_remove = baskets.query.filter_by(basket_id=current_user_id, item_id=product_id).first()
    print(current_user_id, product_id)
    db.session.delete(item_remove)
    db.session.commit()

# Code to implement adding to basket
@app.route('/basket/add', methods=['GET', 'POST'])
@login_required
def add_to_basket():
    if request.method == 'POST':
        product_id = request.form['id']
        add(product_id)
        return redirect(url_for('basket'))

    else:
        data = products.query.all()
        return render_template('items.html', data=data)

def add(product_id):
    # Get the id for the current user
    current_user_id = Users.query.filter_by(username=current_user.username).with_entities(Users.id).scalar()
    print(current_user_id)
    print(product_id)
    new_add = baskets(basket_id=current_user_id, item_id=product_id)
    db.session.add(new_add)
    db.session.commit()

# The basket page
@app.route('/basket', methods=['GET', 'POST'])
@login_required
def basket():
    # Get the id for the current user
    current_user_id = Users.query.filter_by(username=current_user.username).with_entities(Users.id).scalar()
    print(current_user_id)
    # Get the corresponding basket contents using the current user id
    contents = baskets.query.filter_by(basket_id=current_user_id).with_entities(baskets.item_id).all()
    fixed = []
    for item in contents:
        item = str(item)
        item = item.replace("(","")
        item = item.replace(")","")
        item = item.replace(",","")
        fixed.append(item)

    details = []
    for item in fixed:
        detail = products.query.filter_by(id=item).with_entities(products.id, products.name, products.price, products.image).first()
        details.append(detail)

    max = 0
    for detail in details:
        max = max + detail.price

    print(details)
    print(max)

    return render_template('basket.html', data=details, total=max)

# End Of Basket Page Handling Code ____________________________________________________________________________________

# Review Page Handling Code ________________________________________________________________________________________________

# Page allowing the user to leave a review
@app.route('/review', methods=['GET', 'POST'])
@login_required
def review():
    name = None
    submission = None
    form = ReviewForm()
    # Validate Form
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        item = form.item.data
        form.item.data = ''
        review = form.review.data
        form.review.data = ''

        new_review = Reviews(name=name, item_concerning=item, content=review)
        db.session.add(new_review)
        db.session.commit()

        flash("Form Successfully Submitted. Great Job!")

    return render_template('review_submission.html', name=name, submission=submission, form=form)

# End Of Review Page Handling Code ________________________________________________________________________________________________

# Signup Page Handling Code __________________________________________________________________________________________________________

# The signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    username = None
    email = None
    password1 = None
    password2 = None
    form = SignupForm()
    #Validate Form
    if form.validate_on_submit():
        new_username = form.username.data
        form.username.data = ''

        new_email = form.email.data
        form.email.data = ''
        
        new_password1 = form.password1.data
        form.password1.data = ''

        new_password2 = form.password2.data
        form.password2.data = ''

        registeredUsernames = Users.query.filter_by(username=new_username).first()
        if registeredUsernames != None:
            flash("This username is already taken")
            return render_template('signup.html', username=username, email=email, password1=password1, password2=password2, form=form)

        registeredEmails = Users.query.filter_by(email=new_email).first()
        if registeredEmails != None:
            flash("This email is already in use")
            return render_template('signup.html', username=username, email=email, password1=password1, password2=password2, form=form)

        if email_checker(new_email) == False:
            flash("This email is not a valid format")
            return render_template('signup.html', username=username, email=email, password1=password1, password2=password2, form=form)

        if new_password1 != new_password2:
            flash("The passwords you entered do not match")
            return render_template('signup.html', username=username, email=email, password1=password1, password2=password2, form=form)

        new_user = Users(username=new_username, email=new_email, password_hash=generate_password_hash(new_password2))
        db.session.add(new_user)
        db.session.commit()

        flash("Success! Your new account has now been created, please go to the sign in page to enter the site.")
        return redirect(url_for('items'))
        
    return render_template('signup.html', username=username, email=email, password1=password1, password2=password2, form=form)

# End Of Signup Page Handling Code __________________________________________________________________________________________________________

# Login Page Handling Code __________________________________________________________________________________________________________________

# The Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # Validation
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login accepted.")
                return redirect(url_for('items'))
            else:
                flash("Password Incorrect.")
        else:
            flash("User not found in database.")
                
    return render_template('login.html',form=form)


# Logout function
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash("Successfully logged out.")
    return redirect(url_for('login'))

# End Of Login Page Handling Code __________________________________________________________________________________________________________________

# Error Pages

# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500

if __name__ == '__main__':
    app.run(debug=True)