from flask import Flask, render_template, request, redirect, session
import requests

app = Flask(__name__)

app.secret_key = "cybersecurity"

API_URL = "http://127.0.0.1:5000/predict"

VALID_USERNAME = "admin"
VALID_PASSWORD = "admin123"

posts = []
comments = []


# =====================================
# SECURITY SCAN FUNCTION
# =====================================

def scan_input(payload,
               page_type="general",
               username="",
               password=""):

    response = requests.post(
        API_URL,
        json={
            "payload": payload,
            "type": page_type,
            "username": username,
            "password": password
        }
    )

    return response.json()


# =====================================
# LOGIN PAGE
# =====================================

@app.route("/", methods=["GET", "POST"])
def login():

    result = None

    if request.method == "POST":

        username = request.form.get("username", "")

        password = request.form.get("password", "")

        payload = f"{username} {password}"

        result = scan_input(
            payload,
            page_type="login",
            username=username,
            password=password
        )

        # BRUTE FORCE DETECTION
        if result.get("attack") == "BRUTE_FORCE":

            return render_template(
                "login.html",
                result=result
            )

        # VALID LOGIN
        if username == VALID_USERNAME and password == VALID_PASSWORD:

            session["user"] = username

            return redirect("/home")

        # INVALID LOGIN
        result = {
            "attack": "INVALID_LOGIN",
            "severity": "LOW"
        }

    return render_template(
        "login.html",
        result=result
    )


# =====================================
# HOME PAGE
# =====================================

@app.route("/home", methods=["GET", "POST"])
def home():

    if "user" not in session:

        return redirect("/")

    result = None

    # CREATE POST
    if request.method == "POST":

        post = request.form.get("post", "").strip()

        # EMPTY POST
        if not post:

            result = {
                "attack": "EMPTY_POST",
                "severity": "LOW"
            }

            return render_template(
                "home.html",
                result=result,
                posts=posts,
                comments=comments
            )

        # SECURITY SCAN
        result = scan_input(post)

        print("POST RESULT:", result)

        # STORE ONLY NORMAL POSTS
        if result.get("attack") == "Normal":

            posts.append(post)

    return render_template(
        "home.html",
        result=result,
        posts=posts,
        comments=comments
    )


# =====================================
# COMMENT ROUTE
# =====================================

@app.route("/comment", methods=["POST"])
def comment():

    if "user" not in session:

        return redirect("/")

    comment_text = request.form.get("comment", "").strip()

    result = scan_input(comment_text)

    print("COMMENT RESULT:", result)

    # STORE ONLY NORMAL COMMENTS
    if result.get("attack") == "Normal":

        comments.append(comment_text)

    return render_template(
        "home.html",
        result=result,
        posts=posts,
        comments=comments
    )


# =====================================
# SEARCH ROUTE
# =====================================

@app.route("/search", methods=["POST"])
def search():

    if "user" not in session:

        return redirect("/")

    query = request.form.get("query", "").strip()

    # EMPTY SEARCH
    if not query:

        return render_template(
            "home.html",
            result={
                "attack": "EMPTY_SEARCH",
                "severity": "LOW"
            },
            posts=posts,
            comments=comments
        )

    result = scan_input(query)

    print("SEARCH RESULT:", result)

    # BLOCK ATTACKS
    if result.get("attack") != "Normal":

        return render_template(
            "home.html",
            result=result,
            posts=posts,
            comments=comments
        )

    # SEARCH POSTS
    filtered_posts = []

    for post in posts:

        if query.lower() in post.lower():

            filtered_posts.append(post)

    return render_template(
        "home.html",
        result=result,
        posts=filtered_posts,
        comments=comments
    )


# =====================================
# PROFILE PAGE
# =====================================

@app.route("/profile", methods=["GET", "POST"])
def profile():

    if "user" not in session:

        return redirect("/")

    result = None

    if request.method == "POST":

        bio = request.form.get("bio", "").strip()

        result = scan_input(bio)

        print("PROFILE RESULT:", result)

    return render_template(
        "profile.html",
        result=result
    )


# =====================================
# LOGOUT
# =====================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# =====================================
# RUN WEBSITE
# =====================================

if __name__ == "__main__":

    app.run(port=8000, debug=True)