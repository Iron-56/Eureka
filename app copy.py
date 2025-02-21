from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

from config import get_client


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = '24b9'

supabase = get_client()

# db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(100), unique=True, nullable=False)
	email = db.Column(db.String(150), unique=True, nullable=False)
	password = db.Column(db.String(200), nullable=False)

class Post(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	content = db.Column(db.Text, nullable=False)
	tags = db.Column(db.String(200), nullable=True)
	user = db.relationship('User', backref=db.backref('posts', lazy=True))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

@app.route('/')
def home():
	user_posts = []
	if current_user.is_authenticated:
		user_posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.id.desc()).all()

	return render_template('index.html', user_posts=user_posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form['username']
		email = request.form['email']
		password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

		user = User(username=username, email=email, password=password)
		db.session.add(user)
		db.session.commit()

		flash('Account created successfully!', 'success')
		return redirect(url_for('login'))

	return render_template('register.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		user = User.query.filter_by(email=request.form['email']).first()
		if user and bcrypt.check_password_hash(user.password, request.form['password']):
			login_user(user)
			flash('Login successful!', 'success')
			return redirect(url_for('home'))
		flash('Invalid credentials!', 'danger')

	return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('Logged out successfully!', 'success')
	return redirect(url_for('login'))

@app.route('/post', methods=['POST'])
@login_required
def post():
	content = request.form.get('content')
	tags = request.form.get('tags')

	if not content:
		flash('Post content cannot be empty', 'danger')
		return redirect(url_for('home'))

	new_post = Post(user_id=current_user.id, content=content, tags=tags)
	db.session.add(new_post)
	db.session.commit()
	
	flash('Post created successfully!', 'success')
	return redirect(url_for('home'))

@app.route('/posts')
def view_posts():
	tag_filter = request.args.get('tag')
	posts = []
	if tag_filter:
		posts = Post.query.filter(Post.tags.like(f"%{tag_filter}%")).order_by(Post.id.desc()).all()
	else:
		posts = Post.query.order_by(Post.id.desc()).all()

	# posts = Post.query.order_by(Post.id.desc()).all()
	return render_template('posts.html', posts=posts, tag_filter=tag_filter)


if __name__ == '__main__':
	with app.app_context():
		db.create_all()
	app.run(debug=True)
