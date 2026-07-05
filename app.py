from flask import Flask,render_template,request,redirect,session
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import datetime
import sqlite3
import pyotp
import qrcode
import os

app=Flask(__name__)
app.secret_key="secretkey123"

if not os.path.exists("static/qrcodes"):
    os.makedirs("static/qrcodes")

conn=sqlite3.connect("users.db")
cursor=conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
username TEXT PRIMARY KEY,
password TEXT,
secret TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_history(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT,
time TEXT,
status TEXT
)
""")

conn.commit()
conn.close()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register",methods=["GET","POST"])
def register():

    if request.method=="POST":

        username=request.form["username"]

        password=generate_password_hash(
        request.form["password"]
        )

        secret=pyotp.random_base32()

        conn=sqlite3.connect("users.db")
        cursor=conn.cursor()

        try:

            cursor.execute(
            "INSERT INTO users VALUES(?,?,?)",
            (username,password,secret)
            )

            conn.commit()

        except:
            conn.close()
            return "User already exists"

        conn.close()

        totp=pyotp.TOTP(secret)

        uri=totp.provisioning_uri(
        username,
        issuer_name="SecureAuthProject"
        )

        img=qrcode.make(uri)

        qr_path=f"static/qrcodes/{username}.png"

        img.save(qr_path)

        return render_template(
        "register.html",
        qr=qr_path
        )

    return render_template("register.html")


@app.route("/login",methods=["GET","POST"])
def login():

    if request.method=="POST":

        username=request.form["username"]
        password=request.form["password"]

        conn=sqlite3.connect("users.db")
        cursor=conn.cursor()

        cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
        )

        user=cursor.fetchone()

        if user and check_password_hash(
        user[1],
        password
        ):

            session["username"]=username

            cursor.execute(
            "INSERT INTO login_history(username,time,status) VALUES(?,?,?)",
            (
            username,
            datetime.now().strftime("%d-%m-%Y %I:%M %p"),
            "Success"
            )
            )

            conn.commit()
            conn.close()

            return redirect("/verify")

        else:

            cursor.execute(
            "INSERT INTO login_history(username,time,status) VALUES(?,?,?)",
            (
            username,
            datetime.now().strftime("%d-%m-%Y %I:%M %p"),
            "Failed"
            )
            )

            conn.commit()
            conn.close()

            return "Invalid Credentials"

    return render_template("login.html")


@app.route("/verify",methods=["GET","POST"])
def verify():

    if "username" not in session:
        return redirect("/login")

    if request.method=="POST":

        otp=request.form["otp"]

        conn=sqlite3.connect("users.db")
        cursor=conn.cursor()

        cursor.execute(
        "SELECT secret FROM users WHERE username=?",
        (session["username"],)
        )

        secret=cursor.fetchone()[0]

        conn.close()

        totp=pyotp.TOTP(secret)

        if totp.verify(otp):

            session["authenticated"]=True

            return redirect("/dashboard")

        return "Invalid OTP"

    return render_template("verify.html")


@app.route("/dashboard")
def dashboard():

    if not session.get("authenticated"):
        return redirect("/login")

    conn=sqlite3.connect("users.db")
    cursor=conn.cursor()

    cursor.execute(
    """SELECT time,status
    FROM login_history
    WHERE username=?
    ORDER BY id DESC LIMIT 5""",
    (session["username"],)
    )

    history=cursor.fetchall()

    cursor.execute(
    """SELECT COUNT(*) FROM login_history
    WHERE username=?"""
    ,
    (session["username"],)
    )

    total=cursor.fetchone()[0]

    cursor.execute(
    """SELECT COUNT(*) FROM login_history
    WHERE username=? AND status='Failed'""",
    (session["username"],)
    )

    failed=cursor.fetchone()[0]

    conn.close()

    return render_template(
    "dashboard.html",
    user=session["username"],
    history=history,
    total=total,
    failed=failed
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


if __name__=="__main__":
    app.run(debug=True)