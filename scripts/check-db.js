'use strict';
const { Pool } = require('pg');
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is missing.');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });
(async () => {
  try {
    const r = await pool.query('SELECT current_database() AS database, current_user AS username, NOW() AS server_time');
    console.log('PostgreSQL connection successful.');
    console.log(`Database: ${r.rows[0].database}`);
    console.log(`User: ${r.rows[0].username}`);
    console.log(`Server time: ${r.rows[0].server_time.toISOString()}`);
  } catch (e) {
    console.error('Database connection failed:', e.message);
    process.exitCode = 1;
  } finally { await pool.end(); }
})();
