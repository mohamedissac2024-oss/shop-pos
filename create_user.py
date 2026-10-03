from werkzeug.security import generate_password_hash
from db import get_connection

username = "admin"
password = "admin123"

password_hash = generate_password_hash(password)

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    INSERT INTO users (username, password_hash)
    VALUES (%s, %s)
""", (username, password_hash))

connection.commit()

cursor.close()
connection.close()

print("User created successfully!")