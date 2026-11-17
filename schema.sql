CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name_enc TEXT NOT NULL,
  pw TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','officer')),
  balance BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0),
  failed INTEGER NOT NULL DEFAULT 0,
  locked_until BIGINT NOT NULL DEFAULT 0,
  last_login BIGINT,
  prev_login BIGINT
);
CREATE TABLE IF NOT EXISTS otps (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  expires BIGINT NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS revoked (jti TEXT PRIMARY KEY, exp BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS txns (
  id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id),
  kind TEXT, amount BIGINT, ts BIGINT
);
CREATE TABLE IF NOT EXISTS loans (
  id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id),
  amount BIGINT, term INTEGER, payment BIGINT, purpose_enc TEXT,
  status TEXT NOT NULL DEFAULT 'pending', ts BIGINT
);
CREATE TABLE IF NOT EXISTS audit (
  id BIGSERIAL PRIMARY KEY, ts BIGINT, user_id BIGINT, event TEXT, ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_txns_user_id_id ON txns(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_loans_user_id_id ON loans(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_loans_status ON loans(status);
CREATE INDEX IF NOT EXISTS idx_revoked_exp ON revoked(exp);
