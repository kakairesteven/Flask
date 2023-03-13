import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

# Read about http methods 
"""
http verbs comprise of POST (Create), GET (Read), PUT(Update/Replace), PATCH (update/Modify) and DELETE (delete)
Referred to as CRUD (Create), Read, Update, Delete) operations

POST method often utilized to create new resources, create subordinate
resources, reutrns http status 201, returning a location header with a
link to the newly created resource.

GET is used to read the representation of a resource. Returns 
a representation in XML or JSON and HTTP response code of 200 (OK) or 
404 (Not Found) or 400 (Bad Request) in error case.

PUT utilized to update capabilities, PUT-ting to a known resource URI 
with the request body containing the newly updated representation
of the original resour.center()

PATCH used to modify, request only needs to contain changes to the
resource, not the complete resource.

DELETE, used to delete a resource identified by the URI

"""

# This function reads and creates a resource
@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        # initialize the error to be None
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'

        # if error (None) is None, negate the None statement
        if error is None:
            try:
                # generate_password_hash() is used to securely hash the password
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()

            # sqlite3.IntegrityError occurs if the user already exists
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
        flash(error)

    return render_template('auth/register.html')

# Login view
@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        # fetchone() returns one row from the query, None if no results
        # fetchall() returns a list of all results

        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        # check_password_hash hashed the sumbitted password and
        # and compares them. If they match, the password is valid.

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        # session is a dict that stores data across requests. when validation succeeds,
        # the user's id is stored in a new session. The data is stored
        # in a cookie that is sent to the browser 
        
        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

# bp.before_app_request() registers a function that runs before the
# view function, no matter what URL is requested.
# load_logged_in_user checks if the user id is stored in the session

# LOGOUT
# Remove the user id from the session

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Creating, editing and deleting blog posts will require a user
# to be logged in. A decorator is used to check this for each view it's
# applied to.

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        
        return view(**kwargs)
    return wrapped_view

# The decorator returns a new view function that wraps the original view
# it's applied to. The new function checks if the user is loaded 
# and redirects to the login page otherwise

"""
    Endpoints and URLs
    The url_for() function generates the URL to a view based on a name
    and arguments. The name associated with a view is also called
    the endpoint, and by default it's the same as the name of the view function
"""
