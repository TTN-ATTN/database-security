#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
M="docker exec dbsec-mysql mysql"

echo "############ DBF #1: legit query via ProxySQL (should return rows) ############"
$M --ssl-mode=DISABLED -h dbsec-proxysql -P6033 -udbfuser -pdbfpass testdb \
  -t -e "SELECT id, product, amount FROM orders LIMIT 3;" 2>/dev/null

echo
echo "############ DBF #2: DROP via ProxySQL (should be BLOCKED) ############"
$M --ssl-mode=DISABLED -h dbsec-proxysql -P6033 -udbfuser -pdbfpass testdb \
  -e "DROP TABLE orders;" 2>&1 | grep -v insecure || true

echo
echo "############ DBF #3: ProxySQL rule hit counters ############"
$M --ssl-mode=DISABLED -h dbsec-proxysql -P6032 -uradmin -pradmin \
  -t -e "SELECT rule_id, hits FROM stats_mysql_query_rules;" 2>/dev/null

echo
echo "############ ENC #1: read secure_cards DIRECT from MySQL (ciphertext) ############"
$M -uroot -p"$MYSQL_ROOT_PASSWORD" testdb \
  -t -e "SELECT holder, HEX(card_number) AS ciphertext_hex, LENGTH(card_number) AS bytes FROM secure_cards;" 2>/dev/null

echo
echo "############ ENC #2: read secure_cards THROUGH acra-server (plaintext) ############"
$M --ssl-mode=DISABLED -h dbsec-acra-server -P9393 -udbfuser -pdbfpass testdb \
  -t -e "SELECT holder, card_number FROM secure_cards;" 2>/dev/null
