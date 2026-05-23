"""Phase 5: generate sustained mixed query load to produce visible Grafana metrics.

Creates concurrent workers that run SELECTs, INSERTs, UPDATEs and intentional
slow queries for a configurable duration (default 60s). Designed to make the
Phase 5 performance dashboard light up with real traffic.
"""

import argparse
import os
import sys
import threading
import time
import random

from dotenv import load_dotenv
import mysql.connector

load_dotenv()

DB_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_HOST_PORT", "3307")),
    "database": os.getenv("MYSQL_DATABASE", "testdb"),
    "user": "root",
    "password": os.getenv("MYSQL_ROOT_PASSWORD", "rootpass"),
    "use_pure": True,
}

stop_event = threading.Event()
counters = {"select": 0, "insert": 0, "update": 0, "slow": 0, "error": 0}
counter_lock = threading.Lock()

valid_user_ids = []
max_order_id = 0


def inc(key):
    with counter_lock:
        counters[key] += 1


def worker_select():
    conn = mysql.connector.connect(**DB_CFG)
    cur = conn.cursor()
    while not stop_event.is_set():
        try:
            q = random.choice([
                "SELECT id, first_name, email FROM users ORDER BY RAND() LIMIT 10",
                "SELECT id, product, amount FROM orders WHERE status='shipped' LIMIT 20",
                "SELECT COUNT(*) FROM orders WHERE amount > 500",
                "SELECT user_id, action FROM activity_logs ORDER BY created_at DESC LIMIT 10",
                "SELECT u.id, COUNT(o.id) FROM users u JOIN orders o ON o.user_id=u.id GROUP BY u.id LIMIT 10",
            ])
            cur.execute(f"/* phase5:select */ {q}")
            cur.fetchall()
            inc("select")
        except mysql.connector.Error:
            inc("error")
        time.sleep(random.uniform(0.01, 0.05))
    cur.close()
    conn.close()


def worker_write():
    conn = mysql.connector.connect(**DB_CFG)
    cur = conn.cursor()
    while not stop_event.is_set():
        try:
            action = random.choice(["insert", "update"])
            if action == "insert":
                uid = random.choice(valid_user_ids) if valid_user_ids else None
                cur.execute(
                    "/* phase5:insert */ INSERT INTO activity_logs (user_id, action, notes, ip_address) "
                    "VALUES (%s, %s, %s, %s)",
                    (uid, "phase5_load", "load test entry", "10.0.0.1"),
                )
                conn.commit()
                inc("insert")
            else:
                oid = random.randint(1, max_order_id) if max_order_id > 0 else 1
                new_status = random.choice(["pending", "processing", "shipped", "delivered"])
                cur.execute(
                    "/* phase5:update */ UPDATE orders SET status=%s WHERE id=%s",
                    (new_status, oid),
                )
                conn.commit()
                inc("update")
        except mysql.connector.Error:
            inc("error")
        time.sleep(random.uniform(0.02, 0.1))
    cur.close()
    conn.close()


def worker_slow():
    conn = mysql.connector.connect(**DB_CFG)
    cur = conn.cursor()
    while not stop_event.is_set():
        try:
            q = random.choice([
                "SELECT SQL_NO_CACHE BENCHMARK(1500000, MD5(RAND()))",
                "SELECT SQL_NO_CACHE u.id, SUM(o.amount) FROM users u "
                "CROSS JOIN orders o GROUP BY u.id ORDER BY RAND() LIMIT 5",
            ])
            cur.execute(f"/* phase5:slow */ {q}")
            cur.fetchall()
            inc("slow")
        except mysql.connector.Error:
            inc("error")
        time.sleep(random.uniform(2, 5))
    cur.close()
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Phase 5 load generator")
    parser.add_argument("--duration", type=int, default=60, help="seconds to run (default 60)")
    parser.add_argument("--select-workers", type=int, default=4, help="concurrent SELECT workers")
    parser.add_argument("--write-workers", type=int, default=2, help="concurrent INSERT/UPDATE workers")
    parser.add_argument("--slow-workers", type=int, default=1, help="concurrent slow-query workers")
    args = parser.parse_args()

    print(f"Phase 5 - load generator: {args.duration}s, "
          f"{args.select_workers} select + {args.write_workers} write + {args.slow_workers} slow workers")

    global valid_user_ids, max_order_id
    pre = mysql.connector.connect(**DB_CFG)
    pc = pre.cursor()
    pc.execute("SELECT id FROM users")
    valid_user_ids = [r[0] for r in pc.fetchall()]
    pc.execute("SELECT COALESCE(MAX(id), 0) FROM orders")
    max_order_id = pc.fetchone()[0]
    pc.close()
    pre.close()
    if not valid_user_ids:
        print("  [WARN] users table is empty — inserts will use user_id=NULL")
    if max_order_id == 0:
        print("  [WARN] orders table is empty — updates will be no-ops")

    threads = []
    for _ in range(args.select_workers):
        threads.append(threading.Thread(target=worker_select, daemon=True))
    for _ in range(args.write_workers):
        threads.append(threading.Thread(target=worker_write, daemon=True))
    for _ in range(args.slow_workers):
        threads.append(threading.Thread(target=worker_slow, daemon=True))

    for t in threads:
        t.start()

    start = time.time()
    try:
        while time.time() - start < args.duration:
            elapsed = int(time.time() - start)
            with counter_lock:
                snap = dict(counters)
            total = snap["select"] + snap["insert"] + snap["update"] + snap["slow"]
            print(f"\r  [{elapsed:3d}s/{args.duration}s] "
                  f"sel={snap['select']}  ins={snap['insert']}  upd={snap['update']}  "
                  f"slow={snap['slow']}  err={snap['error']}  total={total}",
                  end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        pass

    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    with counter_lock:
        snap = dict(counters)
    total = snap["select"] + snap["insert"] + snap["update"] + snap["slow"]
    print(f"\n\n[DONE] {total} queries in {args.duration}s "
          f"(sel={snap['select']} ins={snap['insert']} upd={snap['update']} "
          f"slow={snap['slow']} err={snap['error']})")


if __name__ == "__main__":
    try:
        main()
    except mysql.connector.Error as err:
        print(f"[FATAL] {err}")
        sys.exit(1)
