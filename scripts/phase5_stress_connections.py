"""Phase 5: open many concurrent MySQL connections to stress the connection limit.

Designed to trigger MySQLHighConnections (Phase 1) and MySQLConnectionUsageHigh
(Phase 5) alerts and show a visible spike on the Grafana connections panel.
"""

import argparse
import os
import sys
import time

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


def main():
    parser = argparse.ArgumentParser(description="Phase 5 connection stress test")
    parser.add_argument("--count", type=int, default=100, help="connections to open (default 100)")
    parser.add_argument("--hold", type=int, default=30, help="seconds to hold them open (default 30)")
    args = parser.parse_args()

    print(f"Phase 5 - connection stress: opening {args.count} connections, holding {args.hold}s")

    connections = []
    opened = 0
    errors = 0
    for i in range(args.count):
        try:
            conn = mysql.connector.connect(**DB_CFG)
            connections.append(conn)
            opened += 1
            if (i + 1) % 10 == 0:
                print(f"  opened {i + 1}/{args.count} ...")
        except mysql.connector.Error as err:
            errors += 1
            if errors == 1:
                print(f"  first error at connection {i + 1}: {err.msg}")

    print(f"\n  {opened} connections open, {errors} failed")

    if opened > 0:
        cur = connections[0].cursor()
        cur.execute("SHOW STATUS LIKE 'Threads_connected'")
        row = cur.fetchone()
        if row:
            print(f"  MySQL Threads_connected = {row[1]}")
        cur.close()

    print(f"  holding connections for {args.hold}s (watch Grafana) ...")
    try:
        time.sleep(args.hold)
    except KeyboardInterrupt:
        print("\n  interrupted, closing early")

    print("  closing connections ...")
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass

    print(f"[DONE] stress test complete: {opened} opened, {errors} errors")


if __name__ == "__main__":
    try:
        main()
    except mysql.connector.Error as err:
        print(f"[FATAL] {err}")
        sys.exit(1)
