-- VulnerShop DB backup - 2024 migration snapshot
-- NOTE: this file should never have been left in a web-accessible path.
-- (Simulated for training purposes - WSTG-CONF-02 / Security Misconfiguration.)

INSERT INTO users (username, email, password_hash, role) VALUES
  ('svc_backup', 'svc-backup@vulnershop.test', '482c811da5d5b4bc6d497ffa98491e38', 'admin');

-- svc_backup is a leftover service account from the old staging environment
-- that is still active in the live database - left here as a reminder of why
-- backups need the same access controls as production.
