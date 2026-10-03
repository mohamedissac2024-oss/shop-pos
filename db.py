import os
import psycopg2
from dotenv import load_dotenv

# Load the information from .env
load_dotenv()


def get_connection():
    connection = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )

    return connection


if __name__ == "__main__":
    try:
        connection = get_connection()

        print("Database connection successful!")

        connection.close()

    except Exception as e:
        print("Database connection failed!")
        print(e)