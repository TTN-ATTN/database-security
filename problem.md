# Phase 3: AcraCensor Problems Encountered

## 1. Outdated Config Format

**Error**: `acra-censor's config is outdated`

**Cause**: AcraCensor requires a `version` field in `acra-censor.yaml`.

**Fix**: Added `version: 0.85.0` to the YAML config.

---

## 2. Keystore Directory Permissions (WSL2)

**Error**: `Keystore folder has incorrect permissions -rwxr-xr-x, expected -rwx------`

**Cause**: WSL2 mounts Windows filesystem with fixed permissions (`rwxr-xr-x`). Bind-mounting a host directory into the container cannot satisfy `chmod 700`.

**Fix**: Replaced bind mount with a Docker named volume (`acra_keys`) and a `busybox` init container (`acra-keys-init`) that runs `chmod 700 /keys` inside the volume.

---

## 3. No Shell in Acra Image

**Error**: `exec: /bin/sh: no such file or directory`

**Cause**: The `cossacklabs/acra-server` Docker image is scratch/distroless — it contains only the binary, no shell.

**Fix**: Cannot run shell commands inside the Acra container. Used a separate `busybox:1.37` init container (`acra-keys-init`) to prepare the keys volume instead.

---

## 4. Invalid `--keystore` Flag

**Error**: `flag provided but not defined: -keystore`

**Cause**: The `--keystore` flag is only valid for `acra-keymaker`, not for `acra-server`.

**Fix**: Removed the `--keystore` flag from the `acra-server` command.

---

## 5. Client ID Too Short

**Error**: `Invalid client ID, 5 <= len(client ID) <= 256`

**Cause**: `--client_id=demo` is only 4 characters; minimum is 5.

**Fix**: Changed to `--client_id=dbsec_client`.

---

## 6. Invalid Master Key Format

**Error**: `Failed to parse ACRA_MASTER_KEY` / `invalid character 'C'`

**Cause**: Keystore v2 master key is a JSON object that must be base64-encoded. A raw JSON string or incorrectly formatted key causes a parse error.

**Fix**: Base64-encoded the JSON master key properly.

---

## 7. Keystore v2 Cache Incompatibility

**Error**: `keystore cache is not supported for keystore v2`

**Cause**: Acra's keystore v2 format does not support the caching mechanism that acra-server enables by default.

**Fix**: Regenerated keys using keystore v1 format instead of v2.

---

## 8. TLS Handshake Failure

**Error**: `tlsv1 unrecognized name` (TLS handshake error)

**Cause**: The Python client (`mysql-connector-python`) attempts an SSL/TLS connection by default. Acra-server in this setup has no TLS certificates configured.

**Fix**: Added `ssl_disabled=True` in the Python test script's connection parameters, and `--tls_client_id_from_cert=false` in acra-server's command flags.

---

## 9. Session Init Queries Blocked

**Error**: `Query execution was interrupted` on `SET NAMES utf8mb4` and similar session init queries.

**Cause**: With `ignore_parse_error: false`, AcraCensor blocks any query its SQL parser cannot parse. MySQL connector sends session initialization queries (`SET NAMES`, `SET character_set_results`, etc.) that AcraCensor's parser does not recognize.

**Fix**: Changed to `ignore_parse_error: true` in `acra-censor.yaml`.

---

## 10. WSL2 Bind Mount Invalidation

**Error**: Config file changes not picked up after `docker compose restart`.

**Cause**: On WSL2, editing a bind-mounted file on the Windows filesystem invalidates the mount inside the running container. A simple `restart` reuses the same mount, which is now stale.

**Fix**: Use `docker compose up -d --force-recreate acra-server` instead of `docker compose restart` to recreate the container with a fresh mount.

---

## 11. CORE ISSUE — AcraCensor SQL Parser Fails on All Queries

**Error log**:
```
level=warning msg="Failed to parse input query" code=563 error="fail to parse specified query" service=acra-censor
level=info msg="Query has been allowed by Allowall handler" handler=allowall
```

**Cause**: AcraCensor's built-in SQL AST parser cannot parse ANY query arriving through the MySQL binary wire protocol — including trivial queries like `SELECT id FROM users LIMIT 3`. Every query triggers a parse failure. Because `ignore_parse_error: true` is required (see Problem #9), all unparseable queries skip the deny rules entirely and fall through to the `allowall` handler.

**Impact**: The deny rules (`DROP TABLE`, `TRUNCATE TABLE`, `SELECT * FROM users`, `UNION` patterns) are **never evaluated**. The firewall is effectively a transparent pass-through.

**Tested on**: Acra versions `0.93.0` and `0.96.0` — identical behavior on both.

**Root cause hypothesis**: AcraCensor's SQL parser expects plain-text SQL but receives queries encoded in MySQL's binary wire protocol format, or the parser has a compatibility issue with MySQL 8.4's query encoding.

**Status**: Unresolved. This is the blocking issue that prevents Phase 3 from working with AcraCensor.

---

## Conclusion

Problems 1–10 were all resolved through configuration changes. Problem 11 is a fundamental incompatibility in AcraCensor's SQL parser that cannot be fixed through configuration. Per the project proposal's fallback strategy (Section 4.3), the next step is to replace AcraCensor with a custom Python SQL firewall proxy that performs the same deny/allow filtering reliably.
