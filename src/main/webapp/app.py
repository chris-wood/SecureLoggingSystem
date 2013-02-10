#!/usr/bin/env python
# coding=utf8

from flask import Flask, render_template, json, request, redirect, url_for, flash, Response
from flask.ext.bootstrap import Bootstrap
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)

# Configure the application
app = Flask(__name__)
Bootstrap(app)

app.config['BOOTSTRAP_USE_MINIFIED'] = True
app.config['BOOTSTRAP_USE_CDN'] = True
app.config['BOOTSTRAP_FONTAWESOME'] = True
#app.config['SECRET_KEY'] = 'devkey'
#app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lfol9cSAAAAADAkodaYl9wvQCwBMr3qGR_PPHcw'

class User(UserMixin):
	''' A class for storing the users.
	'''
	def __init__(self, name, id, active=True):
		self.name = name
		self.id = id
		self.active = active

	def is_active(self):
		return self.active

class Anonymous(AnonymousUser):
	name = u"Anonymous"

# Some hard-coded users for testing purposes
USERS = {
	1: User(u"Alice", 1),
	2: User(u"Bob", 2),
	3: User(u"Chris", 3, False),
}
USER_NAMES = dict((u.name, u) for u in USERS.itervalues())

SECRET_KEY = "yeah, not actually a secret"
DEBUG = True

# Create the app and login manager information
app.config.from_object(__name__)
login_manager = LoginManager()
login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"

@login_manager.user_loader
def load_user(id):
	return USERS.get(int(id))

login_manager.setup_app(app)

@app.route('/', methods=('GET', 'POST',))
def index():
    return render_template('dashboard.html')

@app.route("/secret")
@fresh_login_required
def secret():
	return render_template("secret.html")


@app.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "POST" and "username" in request.form:
		username = request.form["username"]
		if username in USER_NAMES:
			remember = request.form.get("remember", "no") == "yes"
			if login_user(USER_NAMES[username], remember=remember):
				flash("Logged in!")
				return redirect(request.args.get("next") or url_for("index"))
			else:
				flash("Sorry, but you could not log in.")
		else:
			flash(u"Invalid username.")
	return render_template("login.html")

@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
	if request.method == "POST":
		confirm_login()
		flash(u"Reauthenticated.")
		return redirect(request.args.get("next") or url_for("index"))
	return render_template("reauth.html")


@app.route("/logout")
@login_required
def logout():
	logout_user()
	flash("Logged out.")
	return redirect(url_for("index"))

@app.route('/submitLog', methods = ['POST'])
@login_required
def api_echo():
	if request.method == 'POST':
		if (request.headers['Content-Type'] == 'application/json'):

			# TODO: handle the incoming log data here

			jsResp = json.dumps({"success": True, "message": "Success. Accepted the log data."})
			resp = Response(jsResp, status=200, mimetype='application/json')
			return resp
		else:
			jsResp = json.dumps({"success": False, "message": "Log messages must be submitted as JSON strings."})
			resp = Response(jsResp, status=400, mimetype='application/json')
			return resp
	else:
		jsResp = json.dumps({"success": False, "message": "Only HTTP POST commands accepted for /submitLog."})
		resp = Response(jsResp, status=400, mimetype='application/json')
		return resp

def startApp():
	''' Start the app....
	'''
	app.run(debug=True)

if '__main__' == __name__:
    app.run(debug=True)


