import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import dateutil.parser

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    results = db.execute("SELECT symbol, shares, action FROM history WHERE user_id = ?", session["user_id"])
    stocks = {}
    net = 0
    for result in results:
        symbol = result["symbol"].upper()
        shares = result["shares"]
        price = lookup(symbol)["price"]
        if result["action"] == "buy":
            if symbol in stocks:
                shares += stocks[symbol]["shares"]
        elif result["action"] == "sell":
            if symbol in stocks:
                shares = stocks[symbol]["shares"] - shares
        total = price * shares
        if symbol in stocks:
            stocks[symbol].update({'shares': shares, 'price': usd(price), 'total': usd(total), 'net': total})
        else:
            stocks.update({symbol: {'shares': shares, 'price': usd(price), 'total': usd(total), 'net': total}})

    for symbol in stocks:
        IEX = lookup(symbol)
        stocks[symbol].update({'name': IEX["name"]})
        net += stocks[symbol]["net"]

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    total = net + cash
    # return apology("shares must be a positive number")
    return render_template("index.html", symbols=stocks.keys(), stocks=stocks, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol").upper()
        try:
            shares = int(request.form.get("shares"))
        except:
            shares = 0
        result = lookup(symbol)

        if not result:
            return apology("incorrect symbol")

        if shares <= 0:
            return apology("shares must be a positive number")

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        price = result["price"]

        if cash < price * shares:
            return apology("not enough cash")

        # Make a purchase
        cash = cash - price * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        date = datetime.now().isoformat()

        # Insert values into database
        db.execute("INSERT INTO history(user_id, symbol, shares, price, timestamp, action) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol, shares, price, date, "buy")

        return redirect("/")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])
    i = 0
    for entry in history:
        if entry["action"] == "buy":
            history[i]["action"] = "Purchase"
        else:
            history[i]["action"] = "Sell"
        date = dateutil.parser.parse(history[i]["timestamp"])
        history[i].update({'date': date.strftime("%x"), 'time': date.strftime("%X")})
        i += 1

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        results = []
        results.append(lookup(request.form.get("symbol")))
        if results == [None]:
            return apology("not found")
        for i in range(len(results)):
            results[i]["price"] = usd(results[i]["price"])
        return render_template("quoted.html", results=results)
    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")

        # Validate Username
        if username == "" or username == None:
            return apology("username is blank")
        elif len(db.execute("SELECT username FROM users WHERE username = ?", username)) != 0:
            return apology("username already exists")

        # Validate Password
        if password != confirm:
            return apology("password confirmation does not match")

        # Conditions for password
        if len(password) < 8:
            return apology("password must be at least 8 characters long")

        if password.islower() or password.isupper():
            return apology("must include at least one lower and one upper case characters")

        # Hashes password
        password = generate_password_hash(password)

        # Adds user to database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password)

    """Register user"""
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        n = request.form.get("symbol").upper()
        results = db.execute("SELECT symbol, shares, action FROM history WHERE user_id = ?", session["user_id"])
        stocks = {}
        for result in results:
            symbol = result["symbol"].upper()
            shares = result["shares"]
            price = lookup(symbol)["price"]
            if result["action"] == "buy":
                if symbol in stocks:
                    shares += stocks[symbol]["shares"]
            elif result["action"] == "sell":
                if symbol in stocks:
                    shares = stocks[symbol]["shares"] - shares
            total = price * shares
            if symbol in stocks:
                stocks[symbol].update({'shares': shares, 'price': usd(price), 'total': usd(total), 'net': total})
            else:
                stocks.update({symbol: {'shares': shares, 'price': usd(price), 'total': usd(total), 'net': total}})

        try:
            shares = int(request.form.get("shares"))
        except:
            shares = 0
        symbol = n
        result = lookup(symbol)

        if not result:
            return apology("incorrect symbol")

        if shares > stocks[symbol]["shares"]:
            return apology("shares must be a positive number")

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        price = result["price"]

        # Sell
        cash = cash + price * shares
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        date = datetime.now().isoformat()

        # Insert values into database
        db.execute("INSERT INTO history(user_id, symbol, shares, price, timestamp, action) VALUES (?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol, shares, price, date, "sell")

        return redirect("/")
    stocks = set()
    results = db.execute("SELECT symbol, shares, action FROM history WHERE user_id = ?", session["user_id"])
    for result in results:
        stocks.add(result["symbol"])
    return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
