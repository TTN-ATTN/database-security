-- Phase 4: MySQL users for the ProxySQL DBF path.
-- These use mysql_native_password because ProxySQL's backend auth against MySQL 8.4's
-- default caching_sha2_password is unreliable without TLS. MySQL must be started with
-- --mysql-native-password=ON (see compose.yaml) for these to be creatable.
USE testdb;

-- Monitor user: ProxySQL pings the backend for health/read-only checks.
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED WITH mysql_native_password BY 'monitorpass';
GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';

-- DBF demo user: connects through ProxySQL. Granted broad privileges on testdb so that
-- MySQL itself would ALLOW dangerous queries. This proves that when a DROP/TRUNCATE is
-- rejected, it is ProxySQL's firewall doing it, not MySQL permissions.
CREATE USER IF NOT EXISTS 'dbfuser'@'%' IDENTIFIED WITH mysql_native_password BY 'dbfpass';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP ON testdb.* TO 'dbfuser'@'%';

FLUSH PRIVILEGES;
