'use strict';
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { Pool } = require('pg');
const sqlitePath = path.join(process.cwd(), 'harbor.db');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is missing from .env');
if (!fs.existsSync(sqlitePath)) throw new Error('harbor.db was not found in this project folder. If you have no existing accounts/data to preserve, run npm run db:init instead.');
const sqlite = new Database(sqlitePath, { readonly: true, fileMustExist: true });
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });
const tables = ['users', 'otps', 'revoked', 'txns', 'loans', 'audit'];
(async () => {
  const client = await pool.connect();
  try {
    await client.query(fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8'));
    const existing = await client.query('SELECT COUNT(*)::int AS n FROM users');
    if (existing.rows[0].n > 0) throw new Error('Neon already contains user records. Migration stopped to avoid overwriting or duplicating data.');
    await client.query('BEGIN');
    for (const table of tables) {
      const rows = sqlite.prepare(`SELECT * FROM ${table}`).all();
      if (!rows.length) continue;
      const columns = Object.keys(rows[0]);
      const colSql = columns.map(c => `"${c}"`).join(',');
      for (const row of rows) {
        const values = columns.map(c => row[c]);
        const placeholders = values.map((_, i) => `$${i + 1}`).join(',');
        await client.query(`INSERT INTO ${table} (${colSql}) VALUES (${placeholders})`, values);
      }
      console.log(`Migrated ${rows.length} rows from ${table}.`);
    }
    for (const table of ['users', 'txns', 'loans', 'audit']) {
      await client.query(`SELECT setval(pg_get_serial_sequence('${table}','id'), COALESCE((SELECT MAX(id) FROM ${table}), 1), EXISTS(SELECT 1 FROM ${table}))`);
    }
    await client.query('COMMIT');
    console.log('SQLite data migration completed. Keep harbor.db as a private backup until the new application has been tested.');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Migration failed:', err.message);
    process.exitCode = 1;
  } finally {
    client.release(); sqlite.close(); await pool.end();
  }
})();
