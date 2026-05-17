"""Phase 2: seed testdb with synthetic PII data using Faker."""

import os
import random
import sys

from dotenv import load_dotenv
from faker import Faker
import mysql.connector

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "user": "root",
    "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
}

USERS_COUNT = 1000
ORDERS_COUNT = 3000
LOGS_COUNT = 200
BATCH_SIZE = 250

fake = Faker()
Faker.seed(42)
random.seed(42)

PRODUCTS = [
    "Laptop", "Keyboard", "Mouse", "Monitor", "Headphones",
    "Webcam", "USB Hub", "SSD 1TB", "RAM 16GB", "Charger",
    "Tablet", "Smartphone", "Printer", "Router", "Cable Kit",
]

ORDER_STATUSES = ["pending", "processing", "shipped", "delivered", "cancelled"]

LOG_ACTIONS = [
    "login", "logout", "view_profile", "update_profile",
    "place_order", "cancel_order", "change_password",
    "export_report", "search_products", "failed_login",
]


def connect():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"[ERROR] Cannot connect to MySQL: {err}")
        sys.exit(1)


def table_has_data(cursor, table):
    cursor.execute(f"SELECT COUNT(*) FROM {table}")
    return cursor.fetchone()[0] > 0


def seed_users(cursor):
    if table_has_data(cursor, "users"):
        print("[SKIP]  users table already has data")
        return
    print(f"[SEED]  Inserting {USERS_COUNT} users ...")
    rows = []
    for _ in range(USERS_COUNT):
        rows.append((
            fake.first_name(),
            fake.last_name(),
            fake.email(),
            fake.phone_number(),
            fake.address().replace("\n", ", "),
            fake.credit_card_number(card_type=None),
            fake.ssn(),
        ))
    sql = (
        "INSERT INTO users (first_name, last_name, email, phone, address, credit_card, ssn) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)"
    )
    for i in range(0, len(rows), BATCH_SIZE):
        cursor.executemany(sql, rows[i:i + BATCH_SIZE])
    print(f"[OK]    {USERS_COUNT} users inserted")


def seed_orders(cursor):
    if table_has_data(cursor, "orders"):
        print("[SKIP]  orders table already has data")
        return
    print(f"[SEED]  Inserting {ORDERS_COUNT} orders ...")
    rows = []
    for _ in range(ORDERS_COUNT):
        rows.append((
            random.randint(1, USERS_COUNT),
            random.choice(PRODUCTS),
            round(random.uniform(5.0, 2500.0), 2),
            random.choice(ORDER_STATUSES),
        ))
    sql = (
        "INSERT INTO orders (user_id, product, amount, status) "
        "VALUES (%s, %s, %s, %s)"
    )
    for i in range(0, len(rows), BATCH_SIZE):
        cursor.executemany(sql, rows[i:i + BATCH_SIZE])
    print(f"[OK]    {ORDERS_COUNT} orders inserted")


def seed_activity_logs(cursor):
    if table_has_data(cursor, "activity_logs"):
        print("[SKIP]  activity_logs table already has data")
        return
    print(f"[SEED]  Inserting {LOGS_COUNT} activity_logs ...")
    rows = []
    for _ in range(LOGS_COUNT):
        action = random.choice(LOG_ACTIONS)
        notes = _make_log_note(action)
        rows.append((
            random.randint(1, USERS_COUNT),
            action,
            notes,
            fake.ipv4(),
        ))
    sql = (
        "INSERT INTO activity_logs (user_id, action, notes, ip_address) "
        "VALUES (%s, %s, %s, %s)"
    )
    for i in range(0, len(rows), BATCH_SIZE):
        cursor.executemany(sql, rows[i:i + BATCH_SIZE])
    print(f"[OK]    {LOGS_COUNT} activity_logs inserted")


def _make_log_note(action):
    """Generate a free-text note; some deliberately contain PII for discovery demo."""
    r = random.random()
    if r < 0.15:
        return f"User contacted support from email {fake.email()}"
    elif r < 0.25:
        return f"Callback requested at phone {fake.phone_number()}"
    elif r < 0.35:
        return f"Payment with card ending {fake.credit_card_number()}"
    elif r < 0.42:
        return f"SSN provided for verification: {fake.ssn()}"
    elif r < 0.50:
        return f"Shipping to address: {fake.address().replace(chr(10), ', ')}"
    else:
        templates = [
            f"User performed {action} successfully",
            f"Action {action} completed from browser",
            f"Session refreshed after {action}",
            f"Routine {action} event logged",
            f"User triggered {action} via mobile app",
        ]
        return random.choice(templates)


def main():
    conn = connect()
    cursor = conn.cursor()
    try:
        seed_users(cursor)
        seed_orders(cursor)
        seed_activity_logs(cursor)
        conn.commit()
        print("[DONE]  Seed complete.")
    except Exception as exc:
        conn.rollback()
        print(f"[ERROR] Seed failed: {exc}")
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
