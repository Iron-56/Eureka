from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from config import get_client


app = Flask(__name__)
app.config['SECRET_KEY'] = '24b9'
CORS(app)
supabase = get_client()

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
	def __init__(self, user_data):
		self.id = user_data["id"]
		self.username = user_data["username"]
		self.email = user_data["email"]
		self.password = user_data["password"]

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
		user_posts = supabase.table("posts").select("*, interested(user_id, users(username))").eq("user_id", current_user.id).order("id", desc=True).execute().data

	return render_template('index.html', user_posts=user_posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'POST':
		r = request.get_json()
		username = r['username']
		email = r['email']
		password = bcrypt.generate_password_hash(r['password']).decode('utf-8')
		user = supabase.table("users").insert({
			"username": username,
			"email": email,
			"password": password
		}).execute()
		if user.data:
			flash('Account created successfully!', 'success')
			return {"Account Created":1},200
		else:
			flash('Error creating account!', 'danger')
			return {"Account Not Created":1},400





@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		r=request.get_json()
		response = supabase.table("users").select("*").eq("email", r['email']).single().execute()
		user = response.data
		print(user)
		if user and bcrypt.check_password_hash(user["password"], r["password"]):
			login_user(User(user))
			flash('Login successful!', 'success')
			return {'msg':"Logged In"},200
		flash('Invalid credentials!', 'danger')
		return {"msg":"Invalid Credentials"},200


@app.route('/logout')
@login_required
def logout():
	logout_user()
	flash('Logged out successfully!', 'success')
	return redirect(url_for('login'))

@app.route('/post', methods=['POST'])
@login_required
def post():
	content = request.get('content')
	tags = request.get('tags')
	title = request.get('title')
	if not content:
		flash('Post content cannot be empty', 'danger')
		return {'Failed':400},400

	post = supabase.table("posts").insert({
		"user_id": current_user.id,
		"content": content,
		"tags": tags,
		"title":title,
	}).execute()
	return {'Sucess':'Added Post'},200



@app.route('/posts',methods=['GET'])
def view_posts():
	tag_filter = request.args.get('tag')
	query = supabase.table("posts").select("*, users(username), replies(*, users(username)), interested(count)").order("id", desc=True)
	if tag_filter:
		query = query.like("tags", f"%{tag_filter}%")
	posts = query.execute()
	return posts.data,200

@app.route('/reply/<post_id>', methods=['POST'])
@login_required
def add_reply(post_id):
	content = request.form.get('content')

	if not content:
		flash('Reply cannot be empty!', 'danger')
		return redirect(url_for('view_posts'))

	supabase.table("replies").insert({
		"post_id": post_id,
		"user_id": current_user.id,
		"content": content
	}).execute()

	flash('Reply added!', 'success')
	return redirect(url_for('view_posts'))



@app.route('/interest/<post_id>', methods=['POST'])
@login_required
def add_interest(post_id):
    existing_interest = supabase.table("interested").select("*").eq("post_id", post_id).eq("user_id", current_user.id).execute().data

    if existing_interest:
        flash("You have already shown interest in this post!", "warning")
        return redirect(url_for('view_posts'))

    supabase.table("interested").insert({
        "post_id": post_id,
        "user_id": current_user.id
    }).execute()

    flash("Marked as interested!", "success")
    return redirect(url_for('view_posts'))


if __name__ == '__main__':
	app.run(debug=True)
