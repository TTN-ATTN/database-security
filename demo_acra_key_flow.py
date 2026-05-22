#!/usr/bin/env python3
"""
Mock simulation: Acra RSA key management + AES data encryption flow.
Shows exactly what happens when a client INSERT through acra-server.

NOT real crypto (uses basic XOR for demo), just to visualize the FLOW.
"""

import base64
import json

print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                  ACRA CLIENT-SERVER KEY FLOW DEMO                          ║
╚════════════════════════════════════════════════════════════════════════════╝
""")

# ============================================================================
# PHASE 1: KEY GENERATION (happens ONCE, offline via acra-keymaker)
# ============================================================================
print("\n[PHASE 1] KEY GENERATION (offline, via acra-keymaker)\n")
print("Command: acra-keymaker --keystore=v1 --generate_master_key=/keys/master.key")
print()

# Simulate RSA master key (real: 2048-bit, here: simplified bytes)
RSA_MASTER_KEY = b"RSA_PRIVATE_KEY_2048bit_" + b"x" * 100  # Mock
print(f"Step 1: Master key generated (raw bytes)")
print(f"  master.key = {RSA_MASTER_KEY[:40]}... ({len(RSA_MASTER_KEY)} bytes)")
print()

# Base64 encode for ACRA_MASTER_KEY env var
ACRA_MASTER_KEY_ENV = base64.b64encode(RSA_MASTER_KEY).decode()
print(f"Step 2: Base64 encode master key for .env")
print(f"  ACRA_MASTER_KEY={ACRA_MASTER_KEY_ENV[:50]}... (base64, {len(ACRA_MASTER_KEY_ENV)} chars)")
print()

# Simulate generating storage keys (AES key wrapped with RSA)
AES_DATA_KEY = b"AES_256_KEY_1234"  # Real: 32 bytes = 256 bits
print(f"Step 3: Generate storage key for client_id=dbsec_client")
print(f"  AES_DATA_KEY = {AES_DATA_KEY} (256-bit AES key)")
print()

# Simulate RSA encryption of AES key
def mock_rsa_wrap(plaintext_key, rsa_master_key):
    """Mock RSA encryption - just XOR for demo visualization."""
    return bytes(a ^ b for a, b in zip(plaintext_key, rsa_master_key[:len(plaintext_key)]))

def mock_rsa_unwrap(wrapped_key, rsa_master_key):
    """Mock RSA decryption."""
    return bytes(a ^ b for a, b in zip(wrapped_key, rsa_master_key[:len(wrapped_key)]))

WRAPPED_AES_KEY = mock_rsa_wrap(AES_DATA_KEY, RSA_MASTER_KEY)
print(f"Step 4: RSA-wrap the AES key (store in keystore file)")
print(f"  RSA.encrypt(AES_DATA_KEY) = {WRAPPED_AES_KEY} (ciphertext)")
print(f"  → File: /keys/dbsec_client_storage.private (encrypted)")
print()

print("=" * 80)
print()

# ============================================================================
# PHASE 2: ACRA-SERVER STARTUP
# ============================================================================
print("[PHASE 2] ACRA-SERVER STARTUP\n")
print("Environment: ACRA_MASTER_KEY (from .env)")
print()

# Step 1: acra-server reads ACRA_MASTER_KEY from env
print(f"Step 1: acra-server reads ACRA_MASTER_KEY from environment")
print(f"  ACRA_MASTER_KEY={ACRA_MASTER_KEY_ENV[:50]}... (base64)")
print()

# Step 2: Decode base64
decoded_master = base64.b64decode(ACRA_MASTER_KEY_ENV)
print(f"Step 2: Decode base64 → raw RSA private key bytes")
print(f"  decoded_master = {decoded_master[:40]}... ({len(decoded_master)} bytes)")
assert decoded_master == RSA_MASTER_KEY, "Master key mismatch!"
print(f"  ✓ Matches original master key")
print()

# Step 3: Load storage key file from /keys/dbsec_client_storage.private
print(f"Step 3: Load storage key file from /keys/dbsec_client_storage.private")
print(f"  File content (encrypted): {WRAPPED_AES_KEY} ")
print()

# Step 4: Unwrap AES key using RSA private key
unwrapped_aes = mock_rsa_unwrap(WRAPPED_AES_KEY, RSA_MASTER_KEY)
print(f"Step 4: RSA.decrypt(storage_key_file) → get AES key back")
print(f"  RSA.decrypt(WRAPPED_AES_KEY) = {unwrapped_aes}")
assert unwrapped_aes == AES_DATA_KEY, "AES key unwrap failed!"
print(f"  ✓ Successfully unwrapped AES key")
print()

# Step 5: Load into acra-server memory
print(f"Step 5: Cache AES key in acra-server memory")
print(f"  [acra-server memory]")
print(f"    client_id: dbsec_client → AES_KEY: {unwrapped_aes}")
print(f"  Status: READY for encryption/decryption")
print()

print("=" * 80)
print()

# ============================================================================
# PHASE 3: CLIENT INSERTS DATA THROUGH ACRA-SERVER
# ============================================================================
print("[PHASE 3] CLIENT INSERT DATA\n")
print("Client code:")
print('  conn = pymysql.connect(host="127.0.0.1", port=9393, ...)')
print('  cursor.execute("INSERT INTO secure_cards VALUES (1, "John", "4111-1111-1111-1111")")')
print()

plaintext_data = "4111-1111-1111-1111"
print(f"Step 1: Client sends plaintext data")
print(f"  INSERT ... VALUES (..., '{plaintext_data}')")
print()

print(f"Step 2: Query arrives at acra-server (port 9393)")
print(f"  acra-server parses SQL query")
print(f"  Identifies: table=secure_cards, column=card_number, value='{plaintext_data}'")
print()

# Simulate AES encryption (real: AES-256-GCM with IV, here: simplified XOR)
def mock_aes_encrypt(plaintext, aes_key):
    """Mock AES encryption - simplified for visualization."""
    ciphertext = bytes(a ^ b for a, b in zip(plaintext.encode(), (aes_key * ((len(plaintext)//len(aes_key))+1))[:len(plaintext)]))
    return ciphertext

ciphertext_data = mock_aes_encrypt(plaintext_data, AES_DATA_KEY)
print(f"Step 3: acra-server encrypts data with AES-256-GCM")
print(f"  AES.encrypt('{plaintext_data}', AES_KEY) = {ciphertext_data}")
print(f"  (Real: AES-256-GCM + IV + metadata → AcraStruct)")
print()

print(f"Step 4: Create AcraStruct (encrypted wrapper)")
acrastruct = json.dumps({
    "ciphertext": ciphertext_data.hex(),
    "client_id": "dbsec_client",
    "iv": "mock_iv_value",
    "metadata": "mock"
}, indent=2)
print(f"  AcraStruct = {acrastruct}")
print()

print(f"Step 5: Forward modified INSERT to MySQL")
print(f'  INSERT INTO secure_cards VALUES (1, "John", <ACRASTRUCT_BINARY>)')
print()

print(f"Step 6: MySQL stores ciphertext (cannot understand it)")
print(f"  MySQL data (bytes): {ciphertext_data}")
print(f"  SELECT card_number FROM secure_cards WHERE id=1;")
print(f"  → {ciphertext_data} (binary garbage, no plaintext visible)")
print()

print("=" * 80)
print()

# ============================================================================
# PHASE 4A: CLIENT READS DATA THROUGH ACRA-SERVER (NORMAL PATH)
# ============================================================================
print("[PHASE 4A] CLIENT READS DATA (through acra-server)\n")
print("Client code:")
print('  conn = pymysql.connect(host="127.0.0.1", port=9393, ...)')
print('  cursor.execute("SELECT card_number FROM secure_cards WHERE id=1")')
print()

print(f"Step 1: acra-server intercepts SELECT query")
print(f"  SELECT card_number FROM secure_cards WHERE id=1")
print()

print(f"Step 2: acra-server forwards to MySQL, gets encrypted data")
print(f"  MySQL returns: {ciphertext_data} (binary)")
print()

def mock_aes_decrypt(ciphertext, aes_key):
    """Mock AES decryption."""
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, (aes_key * ((len(ciphertext)//len(aes_key))+1))[:len(ciphertext)]))
    return plaintext.decode()

decrypted = mock_aes_decrypt(ciphertext_data, AES_DATA_KEY)
print(f"Step 3: acra-server decrypts with AES key from memory")
print(f"  AES.decrypt({ciphertext_data}, AES_KEY) = '{decrypted}'")
print()

print(f"Step 4: Return plaintext to client")
print(f"  Client receives: '{decrypted}'")
print(f"  ✓ Application sees: plaintext credit card number")
print()

print("=" * 80)
print()

# ============================================================================
# PHASE 4B: DIRECT MYSQL QUERY (ATTACKER PATH)
# ============================================================================
print("[PHASE 4B] DIRECT MYSQL QUERY (bypass acra-server)\n")
print("Attacker connects directly to MySQL (port 3307):")
print('  mysql -h 127.0.0.1 -P 3307 -uroot -p... -e "SELECT card_number FROM secure_cards"')
print()

print(f"Step 1: Attacker queries MySQL directly (NO acra-server)")
print(f"  SELECT card_number FROM secure_cards WHERE id=1")
print()

print(f"Step 2: MySQL returns stored data")
print(f"  card_number = {ciphertext_data} (binary ciphertext)")
print()

print(f"Step 3: Attacker cannot decrypt (no AES key access)")
print(f"  ✗ Attacker sees: {ciphertext_data} (garbage)")
print(f"  ✗ Cannot decrypt without AES_KEY from acra-server memory")
print(f"  ✗ Cannot access /keys volume (needs ACRA_MASTER_KEY to unwrap)")
print()

print("=" * 80)
print()

# ============================================================================
# SUMMARY
# ============================================================================
print("[SUMMARY] Data Flow\n")

summary_table = f"""
┌────────────────────────────────────────────────────────────────┐
│ PATH 1: Client → acra-server → MySQL                          │
├────────────────────────────────────────────────────────────────┤
│ Client action:  INSERT plaintext → '{plaintext_data}'         │
│ acra-server:    AES.encrypt(plaintext) → {ciphertext_data}    │
│ MySQL stores:   {ciphertext_data} (binary ciphertext)         │
│ Client reads:   acra-server decrypts → '{decrypted}'          │
│ Result:         ✓ Application works with plaintext            │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│ PATH 2: Attacker → MySQL (direct)                             │
├────────────────────────────────────────────────────────────────┤
│ Attacker query: SELECT card_number ...                         │
│ MySQL returns:  {ciphertext_data} (binary)                    │
│ Result:         ✗ Cannot read plaintext (no decryption key)   │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│ KEY STORAGE                                                    │
├────────────────────────────────────────────────────────────────┤
│ AES_DATA_KEY:         In acra-server MEMORY ONLY               │
│ WRAPPED_AES_KEY:      File /keys/dbsec_client_storage.private │
│ RSA_MASTER_KEY:       Environment ACRA_MASTER_KEY (.env)      │
│ MySQL data:           {ciphertext_data} (binary)              │
│ Application code:     plaintext (via acra-server decryption)  │
│ Database disk:        ciphertext only                         │
└────────────────────────────────────────────────────────────────┘
"""
print(summary_table)

print("""
KEY INSIGHT:
  If ACRA_MASTER_KEY is compromised → RSA.decrypt(keystore) → AES key exposed
  If /keys volume is stolen → Still need ACRA_MASTER_KEY to unwrap AES keys
  If MySQL database is stolen → Only sees ciphertext (useless without keys)
  
  The 2-layer RSA+AES design ensures:
    1. Storage keys are encrypted at rest (RSA-wrapped)
    2. Data is encrypted with high-speed AES
    3. No single attack gives plaintext without multiple secrets
""")
