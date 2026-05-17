-- Phase 2: masked view for PII obfuscation.
USE testdb;

CREATE OR REPLACE VIEW users_masked AS
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
    CONCAT('**** **** **** ', RIGHT(REPLACE(REPLACE(credit_card, '-', ''), ' ', ''), 4)) AS credit_card,
    CONCAT('***-**-', RIGHT(REPLACE(ssn, '-', ''), 4)) AS ssn,
    created_at
FROM users;
