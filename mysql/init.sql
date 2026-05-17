-- Phase 1: monitoring user for mysqld_exporter.
CREATE USER IF NOT EXISTS 'exporter'@'%' IDENTIFIED BY 'exporterpass' WITH MAX_USER_CONNECTIONS 3;
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'%';
FLUSH PRIVILEGES;
