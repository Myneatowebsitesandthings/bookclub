from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pymysql

app = Flask(__name__, static_folder='public_html', template_folder='.')

app.config['DEBUG'] = True

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://bookclub:This is fucking stupidd@localhost/fine05434922_book_club'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    profile_image = db.Column(db.String(120), nullable=True)

class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    author = db.Column(db.String(120), nullable=False)
    pages = db.Column(db.Integer, nullable=False)
    chapters = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    archived = db.Column(db.Boolean, default=False)

class CurrentBook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    suggestion_id = db.Column(db.Integer, db.ForeignKey('suggestion.id'), nullable=False)
    suggestion = db.relationship('Suggestion', backref=db.backref('current_book', uselist=False))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('login'))
        except:
            flash('Error: Username already exists', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect('/dashboard')
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_book_entry = CurrentBook.query.first()
    current_book = current_book_entry.suggestion if current_book_entry else None
    users = User.query.all()
    return render_template('dashboard.html', current_book=current_book, users=users)

@app.route('/profile.html', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if no user is in session
    
    user = User.query.get(session['user_id'])  # Fetch the user based on session user_id
    if user is None:
        return redirect(url_for('login'))  # Redirect to login if user is not found
    
    if request.method == 'POST':
        # Fetching form data
        title = request.form.get('title')
        author = request.form.get('author')
        pages = request.form.get('pages', type=int)
        chapters = request.form.get('chapters', type=int)
        description = request.form.get('description')
        
        # Create a new suggestion instance
        new_suggestion = Suggestion(
            title=title,
            author=author,
            pages=pages,
            chapters=chapters,
orn.description=description,
            user_id=user.id,
            date_added=datetime.utcnow()  # Ensure the date is set to current time
        )
        
        # Add to the session and commit to the database
        db.session.add(new_suggestion)
        db.session.commit()
        
        flash('Suggestion added successfully!', 'success')
        return redirect('profile.html')  # Redirect back to the profile page to see the new suggestion

    # Fetch all non-archived suggestions for the user
    suggestions = Suggestion.query.filter_by(user_id=user.id, archived=False).all()

    return render_template('profile.html', user=user, suggestions=suggestions)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/user/<int:user_id>')
def public_profile(user_id):
    user = User.query.get(user_id)
    suggestions = Suggestion.query.filter_by(user_id=user.id, archived=False).all()
    return render_template('public_profile.html', user=user, suggestions=suggestions)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.username != 'MasterAdmin':
        return redirect(url_for('dashboard'))
    users = User.query.all()
    suggestions = Suggestion.query.all()
    if request.method == 'POST':
        current_book_id = request.form.get('current_book_id')
        current_book = CurrentBook.query.first()
        if current_book:
            current_book.suggestion_id = current_book_id
        else:
            current_book = CurrentBook(suggestion_id=current_book_id)
            db.session.add(current_book)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('admin.html', users=users, suggestions=suggestions)

@app.route('/delete_suggestion/<int:suggestion_id>', methods=['POST'])
def delete_suggestion(suggestion_id):
    suggestion = Suggestion.query.get(suggestion_id)
    db.session.delete(suggestion)
    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/set_current_book/<int:suggestion_id>', methods=['POST'])
def set_current_book(suggestion_id):
    current_book = CurrentBook.query.first()
    if current_book:
        current_book.suggestion_id = suggestion_id
    else:
        current_book = CurrentBook(suggestion_id=suggestion_id)
        db.session.add(current_book)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/reset_password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    user = User.query.get(user_id)
    new_password = generate_password_hash('newpassword', method='pbkdf2:sha256', salt_length=8)
    user.password = new_password
    db.session.commit()
    flash('Password reset successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='MasterAdmin').first():
        hashed_password = generate_password_hash('adminpassword', method='pbkdf2:sha256', salt_length=8)
        master_admin = User(username='MasterAdmin', password=hashed_password)
        db.session.add(master_admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Clear the user session
    return redirect(url_for('logout_page'))  # Redirect to the logout page

@app.route('/logout_page')
def logout_page():
    return render_template('logout.html')

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='MasterAdmin').first():
        hashed_password = generate_password_hash('adminpassword', method='pbkdf2:sha256', salt_length=8)
        master_admin = User(username='MasterAdmin', password=hashed_password)
        db.session.add(master_admin)
        db.session.commit()
