-- DDL for MySQL (8.x)
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  password_hash CHAR(64) NOT NULL,
  salt CHAR(32) NOT NULL,
  plan ENUM('basic','trial','premium') NOT NULL DEFAULT 'trial',
  start_date DATE NOT NULL,
  status ENUM('active','suspended','expired') NOT NULL DEFAULT 'active',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

