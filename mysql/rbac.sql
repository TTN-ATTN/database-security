-- Phase 2: role-based access control.
USE testdb;

-- appuser: read-only on masked view and orders, no access to raw users table.
REVOKE ALL PRIVILEGES ON testdb.* FROM 'appuser'@'%';

GRANT SELECT ON testdb.users_masked   TO 'appuser'@'%';
GRANT SELECT ON testdb.orders          TO 'appuser'@'%';
GRANT SELECT ON testdb.activity_logs   TO 'appuser'@'%';

FLUSH PRIVILEGES;
