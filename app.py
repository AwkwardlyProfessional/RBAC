from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, login_required, current_user, login_user, logout_user
from functools import wraps
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask application, SQLAlchemy, Flask-Login, and Flask-Migrate
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # You can change this to any DB URI (e.g., MySQL or PostgreSQL)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Change to a real secret key

# Initialize database and migration tools
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize LoginManager for Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # The route to redirect for login if not authenticated
login_manager.login_message = 'Please log in to access this page.'  # Optional custom message

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin', 'moderator', 'user'
    is_active = db.Column(db.Boolean, default=True)  # This indicates whether the user is active

    def __repr__(self):
        return f'<User {self.username}>'

    # Flask-Login required methods
    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True  # Assuming the user is authenticated if they are logged in

    def is_active(self):
        return self.is_active  # Returns whether the user is active

    def is_anonymous(self):
        return False  # Return False because we don't want anonymous users

    # For flask-login to load user by ID
    def get_id(self):
        return str(self.id)

# Define BlogPost model
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=False)  # Whether the blog is approved or not
    review = db.Column(db.Text)  # Review comment by the moderator

    def __repr__(self):
        return f'<BlogPost {self.title}>'

def role_required(role):
    """
    Decorator to check if the user has the required role.
    """
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            # Check if the user is authenticated
            if not current_user.is_authenticated:
                flash('Please log in first.', 'danger')
                return redirect(url_for('login'))

            # Debugging - Print current user's role
            print(f"Checking role: {current_user.role} (required: {role})")

            # Check if the user has the correct role
            if current_user.role != role:
                flash(f'You must be {role} to access this page.', 'danger')
                return redirect(url_for('index'))

            return func(*args, **kwargs)

        return wrapped_function
    return decorator

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, session['user_id'])

# Route for the home page (index)
@app.route('/')
def index():
    return render_template('index.html')

# Route for the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')  # 'admin', 'user', or 'moderator'

        # Ensure role is 'moderator' for a moderator registration
        if role not in ['admin', 'moderator', 'user']:
            flash('Invalid role selected!', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already in use. Please use a different email address.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Login failed. Please check your credentials and try again.', 'danger')
            return redirect(url_for('login'))

        login_user(user)

        flash(f'Welcome back, {user.username}!', 'success')

        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'moderator':
            return redirect(url_for('moderator_dashboard'))
        else:
            return redirect(url_for('dashboard'))

    return render_template('login.html')


# Route for logging out
@app.route('/logout')
def logout():
    logout_user()  # Use Flask-Login's `logout_user()` method
    flash('You have successfully logged out.', 'info')
    return redirect(url_for('index'))

# Admin Dashboard Route
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))

    users = User.query.all()

    if request.method == 'POST':
        for user in users:
            if f'update_{user.id}' in request.form:
                new_role = request.form.get(f'role_{user.id}')
                user.role = new_role
                db.session.commit()

                flash(f'{user.username}\'s role has been updated to {new_role.capitalize()} successfully!', 'success')

        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', users=users)

@app.route('/promote/<int:user_id>', methods=['POST'])
def promote_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.role = 'moderator'
        db.session.commit()
        flash(f'User {user.username} has been promoted to moderator.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/demote/<int:user_id>', methods=['POST'])
def demote_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.role = 'user'
        db.session.commit()
        flash(f'User {user.username} has been demoted to user.', 'success')
    return redirect(url_for('admin_dashboard'))

# User dashboard route
@app.route('/user/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        new_username = request.form.get('username')
        if new_username:
            current_user.username = new_username
            db.session.commit()
            flash('Username updated successfully!', 'success')

        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        if old_password and new_password:
            if check_password_hash(current_user.password, old_password):
                # Hash the new password correctly
                hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                current_user.password = hashed_password
                db.session.commit()
                flash('Password updated successfully!', 'success')
            else:
                flash('Old password is incorrect', 'danger')


        blog_title = request.form.get('blog_title')
        blog_content = request.form.get('blog_content')
        if blog_title and blog_content:
            new_post = BlogPost(title=blog_title, content=blog_content, author_id=current_user.id)
            db.session.add(new_post)
            db.session.commit()
            flash('Blog post created successfully!', 'success')

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html')


@app.route('/moderator/dashboard', methods=['GET', 'POST'])
@role_required('moderator')  # Ensure this is here
def moderator_dashboard():
    # Fetch all blog posts that are not yet approved
    blogs = BlogPost.query.filter_by(approved=False).all()

    if request.method == 'POST':
        blog_id = request.form.get('blog_id')
        action = request.form.get('action')
        review = request.form.get('review')

        blog = BlogPost.query.get(blog_id)
        if blog:
            if action == 'approve':
                blog.approved = True
                blog.review = review
                flash(f'Blog "{blog.title}" has been approved.', 'success')
            elif action == 'reject':
                db.session.delete(blog)
                flash(f'Blog "{blog.title}" has been rejected and deleted.', 'danger')

            db.session.commit()

        return redirect(url_for('moderator_dashboard'))

    return render_template('moderator_dashboard.html', blogs=blogs)

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)
