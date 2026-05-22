-- Phase 4 - ProxySQL DBF deny rules.
-- Loaded into ProxySQL's admin interface (port 6032) by scripts/phase4_proxysql_setup.sh.
--
-- Notes on the regex (RE2 engine):
--   * Backslashes are avoided on purpose. ProxySQL stores patterns in SQLite, where
--     backslash handling is ambiguous, so we use POSIX classes ([[:space:]]) and
--     character classes ([*], [']) instead of \s, \*, \'.
--   * Single quotes inside a SQL string literal are escaped by doubling them ('').
--   * A rule with a non-empty error_msg returns that error to the client and never
--     forwards the query to MySQL -- that is the firewall action.

DELETE FROM mysql_query_rules;

INSERT INTO mysql_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES
(10, 1,
 '(?i)drop[[:space:]]+(table|database|schema)',
 'DBF: DROP statements are blocked by ProxySQL firewall', 1),
(20, 1,
 '(?i)truncate[[:space:]]+table',
 'DBF: TRUNCATE statements are blocked by ProxySQL firewall', 1),
(30, 1,
 '(?i)select[[:space:]]+[*][[:space:]]+from[[:space:]]+users([[:space:]]|$)',
 'DBF: SELECT * FROM users is blocked by ProxySQL firewall', 1),
(40, 1,
 '(?i)or[[:space:]]+['']?1['']?[[:space:]]*=[[:space:]]*['']?1',
 'DBF: SQL injection tautology blocked by ProxySQL firewall', 1);

LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;
