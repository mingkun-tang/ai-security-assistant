from flask import request

def save_nickname(cursor):
    nick = request.form.get("nick")
    cursor.execute("UPDATE prefs SET nickname = '" + nick + "' WHERE user_id = 1")

def greet(cursor, nickname):
    cursor.execute("SELECT msg FROM greetings WHERE nick = '" + nickname + "'")
