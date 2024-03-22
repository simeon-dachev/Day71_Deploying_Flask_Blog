from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
# Move to environment variables
import os


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

# app = Flask(__name__, instance_path="C:/Users/Lenovo/Desktop/Udemy_courses/Python_100-day_Bootcamp/Day69_Blog_Flask_Authentication/instance")
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///blog.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "registered_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    posts: Mapped[list["BlogPost"]] = relationship(back_populates="author")
    comments: Mapped[list["Comment"]] = relationship(back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[str] = mapped_column(ForeignKey("registered_users.id"))
    author: Mapped["User"] = relationship(back_populates="posts")
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments: Mapped[list["Comment"]] = relationship(back_populates="post")


class Comment(db.Model):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(ForeignKey("registered_users.id"))
    text: Mapped[str] = mapped_column(String(1500), nullable=False, primary_key=True)
    author: Mapped["User"] = relationship(back_populates="comments")
    post: Mapped["BlogPost"] = relationship(back_populates="comments")
    post_id: Mapped[str] = mapped_column(ForeignKey("blog_posts.id"))


with app.app_context():
    db.create_all()

gravatar = Gravatar(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# Write a custom decorator to admit only admin to /new-post, /make-post, /delete-post
def admin_only(func):
    @wraps(func)
    def execute_only_if_admin(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1:
                return func(*args, **kwargs)
        return abort(403, "Access forbidden. You are not the admin of this blog, so you cannot access this route.")
    return execute_only_if_admin


# Create a relationship between the 2 tables in the db (users, blog_posts) to
# see which posts a user has written -> use ForeignKey and relationship()


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        reg_name = request.form["name"]
        reg_email = request.form["email"]
        existing_user = db.session.execute(db.select(User).where(User.email == reg_email)).scalar()
        if existing_user:
            flash("A user with this email already exists. Please log in instead of registering.")
            return redirect(url_for("login"))
        reg_password = request.form["password"]
        secure_pass = generate_password_hash(reg_password, method="pbkdf2:sha256", salt_length=12)
        new_user = User(name=reg_name, email=reg_email, password=secure_pass)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST":
        login_email = request.form["email"]
        login_password = request.form["password"]
        existing_user = db.session.execute(db.select(User).where(User.email == login_email)).scalar()
        if not existing_user:
            flash("A user with this email does not exist. Please try again.")
            return redirect(url_for("login"))
        saved_password = existing_user.password
        if not check_password_hash(pwhash=saved_password, password=login_password):
            flash("Password incorrect. Please try again.")
            return redirect(url_for("login"))
        if check_password_hash(pwhash=saved_password, password=login_password):
            login_user(existing_user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if request.method == "POST":
        if not current_user.is_authenticated:
            flash("Please log in to be able to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(text=request.form["comment"], author=current_user,
                              post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False, port=5002)
