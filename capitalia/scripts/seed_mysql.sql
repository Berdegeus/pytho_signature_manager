-- Seed for MySQL using server-side SHA2
-- Alice: trial started 40 days ago (will expire on status read)
INSERT INTO users (name, email, password_hash, salt, plan, start_date, status)
VALUES (
  'Alice',
  'alice@example.com',
  SHA2(CONCAT('abcdef1234567890abcdef1234567890','password123'), 256),
  'abcdef1234567890abcdef1234567890',
  'trial',
  (CURRENT_DATE - INTERVAL 40 DAY),
  'active'
);

-- Bob: premium active
INSERT INTO users (name, email, password_hash, salt, plan, start_date, status)
VALUES (
  'Bob',
  'bob@example.com',
  SHA2(CONCAT('11112222333344445555666677778888','password123'), 256),
  '11112222333344445555666677778888',
  'premium',
  CURRENT_DATE,
  'active'
);

