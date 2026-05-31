-- Phase 7.5 (Data Classification refactor) - SQL migration.
--
-- Moves users.ssn and users.credit_card from "MySQL view masking" (Tier 2) up to
-- "Acra encrypt-at-rest" (Tier 1). Adds two new MySQL identities (support, fraud)
-- that ProxySQL will pass through, so MySQL can apply per-user RBAC + view masking
-- on the columns that stay in Tier 2 (email, phone, address).
--
--   Tier 1 - Encrypt @ Acra:  ssn, credit_card
--   Tier 2 - Mask @ MySQL:    email, phone, address
--   Tier 3 - Clear:           id, names, timestamps
--
-- Idempotent: safe to re-run.

USE testdb;

-- ── Tier 1: widen the columns Acra will encrypt. AcraStruct ciphertext for one card
-- is ~169 bytes (measured in Phase 4); 512 leaves headroom for SSN/CC + format growth.
ALTER TABLE users
  MODIFY COLUMN ssn         VARBINARY(512),
  MODIFY COLUMN credit_card VARBINARY(512);

-- ── Tier 2: rebuild users_masked WITHOUT ssn/cc. Once they are encrypted at rest,
-- MySQL only sees ciphertext for those columns, so SUBSTRING-style masking on them
-- would produce garbage. Access to ssn/cc is enforced purely by RBAC instead.
DROP VIEW IF EXISTS users_masked;
CREATE VIEW users_masked AS
SELECT
    id,
    first_name,
    last_name,
    CONCAT(
        LEFT(email, 1),
        '***@',
        SUBSTRING_INDEX(email, '@', -1)
    ) AS email,
    CONCAT('***-***-', RIGHT(REPLACE(REPLACE(phone, '-', ''), ' ', ''), 4)) AS phone,
    CONCAT(
        LEFT(address, 3),
        REPEAT('*', 10),
        '...'
    ) AS address,
    created_at
FROM users;

-- ── Three new role identities. Drop-and-recreate is the idempotent path: a fresh
-- CREATE has no implicit grants, so we can apply the exact tier permissions below
-- without a REVOKE step (REVOKE on a newly-created user errors out with ER_NONEXISTING_GRANT).
DROP USER IF EXISTS 'support'@'%';
DROP USER IF EXISTS 'fraud'@'%';
DROP USER IF EXISTS 'self_service'@'%';
CREATE USER 'support'@'%'      IDENTIFIED WITH mysql_native_password BY 'supportpass';
CREATE USER 'fraud'@'%'        IDENTIFIED WITH mysql_native_password BY 'fraudpass';
CREATE USER 'self_service'@'%' IDENTIFIED WITH mysql_native_password BY 'selfpass';

-- support tier: low-priv staff. Read masked view + business tables only.
-- Cannot SELECT raw users at all -> ssn/cc are unreachable.
GRANT SELECT ON testdb.users_masked  TO 'support'@'%';
GRANT SELECT ON testdb.orders        TO 'support'@'%';
GRANT SELECT ON testdb.activity_logs TO 'support'@'%';

-- fraud tier: privileged role with business need-to-know. Reads raw users; ssn/cc
-- arrive decrypted thanks to Acra in the chained data path. Every access is captured
-- by MySQL general.log (Phase 3 audit pipeline) - this is the "audit full PII reads"
-- requirement.
GRANT SELECT ON testdb.users         TO 'fraud'@'%';
GRANT SELECT ON testdb.orders        TO 'fraud'@'%';
GRANT SELECT ON testdb.activity_logs TO 'fraud'@'%';

-- self_service tier (Phase 7 self-service path): each customer reads their OWN raw
-- profile (including ssn/cc, Acra-decrypted) but NOTHING ELSE. Implementation pattern:
-- the user has NO direct SELECT on users; the ONLY thing it can do is EXECUTE a stored
-- procedure get_my_profile(customer_id, self_token). The token simulates an app-issued
-- proof of self-auth (HMAC over the customer_id); without it the procedure refuses.
-- This blocks IDOR-style enumeration: caller cannot just bump the id parameter.
-- (GRANT EXECUTE is below, after the procedure is (re)created.)

-- ── Self-service stored procedure. SQL SECURITY DEFINER so it runs with root's grant
-- (which CAN read raw users), but callable only by self_service (the only grantee
-- below). Two-arg signature locks each call to one row + a matching token.
-- Token recipe: SHA2(CONCAT(customer_id, ':', 'self_service_secret'), 256). In real
-- production, the app would compute this with a per-environment secret loaded from a
-- vault and hand the token to the DB so the DB does not have to trust the caller's
-- claim of identity blindly.
DROP PROCEDURE IF EXISTS get_my_profile;
DELIMITER //
CREATE DEFINER='root'@'localhost' PROCEDURE get_my_profile(
    IN p_customer_id INT,
    IN p_self_token  CHAR(64)
)
SQL SECURITY DEFINER
BEGIN
    DECLARE expected CHAR(64);
    SET expected = SHA2(CONCAT(p_customer_id, ':', 'self_service_secret'), 256);
    IF p_self_token IS NULL OR p_self_token <> expected THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Self-service: invalid or missing self-auth token';
    END IF;
    -- ssn / credit_card come back as AcraStruct bytes here; Acra in the chain decrypts
    -- them to plaintext before the response reaches the customer.
    SELECT id, first_name, last_name, email, phone, address, ssn, credit_card, created_at
      FROM users
     WHERE id = p_customer_id;
END //
DELIMITER ;

-- Re-grant after recreating the procedure (procedure-level GRANT references the object).
GRANT EXECUTE ON PROCEDURE testdb.get_my_profile TO 'self_service'@'%';

FLUSH PRIVILEGES;
