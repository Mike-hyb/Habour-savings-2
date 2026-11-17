'use strict';
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is missing from .env');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });
(async () => {
  try {
    await pool.query(fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8'));
    console.log('Neon database schema created successfully.');
  } catch (err) { console.error('Schema creation failed:', err.message); process.exitCode = 1; }
  finally { await pool.end(); }
})();
