from flask import Flask, render_template, redirect, url_for, request, flash
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

class User(UserMixin):
	def __init__(self, user_data):
		self.id = user_data["id"]
		self.username = user_data["username"]
		self.email = user_data["email"]
		self.password = user_data["password"]

# class Post(db.Model):
# 	id = db.Column(db.Integer, primary_key=True)
# 	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
# 	content = db.Column(db.Text, nullable=False)
# 	tags = db.Column(db.String(200), nullable=True)
# 	user = db.relationship('User', backref=db.backref('posts', lazy=True))

@login_manager.user_loader
def load_user(user_id):
	user = supabase.table("users").select("*").eq("id", user_id).single().execute()
	if user.data:
		return User(user.data)
	return None

@app.route('/')
def home():
	user_posts = []
	if current_user.is_authenticated:
		user_posts = user_posts = (
			supabase.table("posts")
			.select("*")
			.eq("user_id", current_user.id)
			.order("id", desc=True)
			.execute()
		).data

	return render_template('index.html', user_posts=user_posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		username = request.form['username']
		email = request.form['email']
		password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

		user = supabase.table("users").insert({
			"username": username,
			"email": email,
			"password": password
		}).execute()

		if user.data:
			flash('Account created successfully!', 'success')
			return redirect(url_for('login'))
		else:
			flash('Error creating account!', 'danger')
			
		return redirect(url_for('login'))

	return render_template('register.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		response = supabase.table("users").select("*").eq("email", request.form['email']).single().execute()
		user = response.data  # Extract user data (dictionary)

		if user and bcrypt.check_password_hash(user["password"], request.form["password"]):  # Use dictionary access
			login_user(User(user))  # Convert to Flask-Login User object
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

	post = supabase.table("posts").insert({
		"user_id": current_user.id,
		"content": content,
		"tags": tags
	}).execute()

	flash('Post created successfully!', 'success')
	return redirect(url_for('home'))

@app.route('/posts')
def view_posts():
	tag_filter = request.args.get('tag')
	query = supabase.table("posts").select("*, users(username)").order("id", desc=True)
	
	if tag_filter:
		query = query.like("tags", f"%{tag_filter}%")

	print("-------------------------------------------------------------------------------------------------")
	print(query)
	posts = query.execute()
	print(posts.data)
	print("-------------------------------------------------------------------------------------------------")
	return render_template('posts.html', posts=posts.data, tag_filter=tag_filter)

if __name__ == '__main__':
	app.run(debug=True)
