-- Phase 4: demo table for Acra transparent encryption.
-- card_number is VARBINARY because acra-server stores an AcraStruct (binary ciphertext).
-- Data written through acra-server is encrypted; a direct MySQL read sees only ciphertext.
USE testdb;

CREATE TABLE IF NOT EXISTS secure_cards (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    holder      VARCHAR(100)   NOT NULL,
    card_number VARBINARY(1024) NOT NULL,
    created_at  DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- dbfuser already has SELECT/INSERT on testdb.*, so it can use this table through acra.
