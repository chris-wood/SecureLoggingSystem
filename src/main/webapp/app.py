#!/usr/bin/env python
# coding=utf8

from flask import Flask, render_template
from flask.ext.bootstrap import Bootstrap

app = Flask(__name__)
Bootstrap(app)

app.config['BOOTSTRAP_USE_MINIFIED'] = True
app.config['BOOTSTRAP_USE_CDN'] = True
app.config['BOOTSTRAP_FONTAWESOME'] = True
#app.config['SECRET_KEY'] = 'devkey'
#app.config['RECAPTCHA_PUBLIC_KEY'] = '6Lfol9cSAAAAADAkodaYl9wvQCwBMr3qGR_PPHcw'

@app.route('/', methods=('GET', 'POST',))
def index():
    return render_template('dashboard.html')


if '__main__' == __name__:
    app.run(debug=True)