from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

# Fake database (memory me hi users list)
USERS = [
    {
        "id": 1,
        "username": "admin",
        "password": "admin123",
        "full_name": "Admin User",
        "email": "admin@rb-education-hub.local",
        "role": "admin",
        "balance": 100000
    },
    {
        "id": 2,
        "username": "student1",
        "password": "student1",
        "full_name": "Student One",
        "email": "student1@rb-education-hub.local",
        "role": "student",
        "balance": 1500
    },
    {
        "id": 3,
        "username": "student2",
        "password": "student2",
        "full_name": "Student Two",
        "email": "student2@rb-education-hub.local",
        "role": "student",
        "balance": 2500
    }
]


def find_user_by_username(username):
    for u in USERS:
        if u["username"] == username:
            return u
    return None


def find_user_by_id(user_id):
    for u in USERS:
        if u["id"] == user_id:
            return u
    return None


@app.route("/")
def index():
    # Agar login hai to seedha vulnerable profile pe bhej do
    if "user_id" in session:
        return redirect(url_for("profile_vulnerable", id=session["user_id"]))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = find_user_by_username(username)

        if user and user["password"] == password:
            session["user_id"] = user["id"]
            return redirect(url_for("profile_vulnerable", id=user["id"]))
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------
#   VULNERABLE IDOR ENDPOINT
# ------------------------------
@app.route("/profile")
def profile_vulnerable():
    """
    IDOR vulnerability:
    Yaha pe hum logged in user ke session se ID nahi le rahe,
    URL parameter ?id= se le rahe hain.

    Example:
    /profile?id=2
    /profile?id=3
    """
    if "user_id" not in session:
        return redirect(url_for("login"))

    # IDOR: user khud URL me id change kar sakta hai
    user_id = request.args.get("id", type=int)
    if not user_id:
        # agar id nai di to apni id dikha do
        user_id = session["user_id"]

    user = find_user_by_id(user_id)
    if not user:
        return "User not found", 404

    return render_template("profile.html", user=user)


# ------------------------------
#   SECURE VERSION (FIXED)
# ------------------------------
@app.route("/profile-secure")
def profile_secure():
    """
    Secure version:
    Yaha pe humesha session se hi user_id uthate hain,
    URL se diya hua id ignore kar dete hain.
    """
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    user = find_user_by_id(user_id)
    if not user:
        return "User not found", 404

    return render_template("profile_secure.html", user=user)


if __name__ == "__main__":
    # 0.0.0.0 use karo agar same network wale mobile/pc se open karna hai
    app.run(host="0.0.0.0", port=5000, debug=True)
