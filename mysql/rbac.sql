-- Phase 2: role-based access control.
USE testdb;

-- appuser: read-only on masked view and orders, no access to raw users table.
-- The GRANTs below are the authoritative set. Any previous grants are cleaned up
-- by the Makefile target which runs this file with mysql --force so that REVOKE
-- errors (1141) on a fresh database are ignored.
REVOKE ALL PRIVILEGES ON testdb.*              FROM 'appuser'@'%';
REVOKE ALL PRIVILEGES ON testdb.users          FROM 'appuser'@'%';
REVOKE ALL PRIVILEGES ON testdb.users_masked   FROM 'appuser'@'%';
REVOKE ALL PRIVILEGES ON testdb.orders         FROM 'appuser'@'%';
REVOKE ALL PRIVILEGES ON testdb.activity_logs  FROM 'appuser'@'%';

GRANT SELECT ON testdb.users_masked   TO 'appuser'@'%';
GRANT SELECT ON testdb.orders          TO 'appuser'@'%';
GRANT SELECT ON testdb.activity_logs   TO 'appuser'@'%';

FLUSH PRIVILEGES;
