<<<<<<< HEAD
# Harbor Savings & Loan — PostgreSQL / Vercel build

This version replaces the local SQLite runtime database with Neon PostgreSQL and adapts the Express application for Vercel serverless deployment. The existing frontend, email MFA flow, password hashing, role checks, rate limits, session cookies, encrypted fields, and application routes are retained.

## Requirements

- Node.js 20.6 or newer
- A Neon PostgreSQL database
- A Resend account/API key
- A Vercel account

## 1. Install locally

```powershell
npm install
```

The install creates a new `package-lock.json` for this version. Do not copy the old lockfile from the SQLite-only version.

## 2. Configure environment variables

Create `.env` in the project root. Start from `.env.example` and set:

```env
NODE_ENV=development
PORT=3000
JWT_SECRET=your_generated_96_character_hex_secret
ENC_KEY=your_generated_64_character_hex_secret
RESEND_API_KEY=your_resend_api_key
RESEND_FROM_EMAIL=onboarding@resend.dev
DATABASE_URL=your_neon_postgresql_connection_string
```

Generate fresh application secrets with:

```powershell
npm run keygen
```

Use the generated values for `JWT_SECRET` and `ENC_KEY`. Keep `.env` private. It is excluded by `.gitignore` and must never be committed or uploaded.

For local testing with `onboarding@resend.dev`, Resend restricts delivery to the verified email address on the Resend account. To send to other recipients, verify a domain in Resend and use an address on that verified domain.

## 3. Initialize Neon schema

```powershell
npm run db:init
```

This creates the tables and indexes required by the application. The application also checks/creates the schema when its API is first used, but running this command explicitly lets you confirm setup before testing.

Check the database connection:

```powershell
npm run db:check
```

## 4. Preserve existing SQLite test data (if needed)

If the previous local version created `harbor.db` and you need to preserve its users, balances, transactions, loans, OTP records, revoked tokens, and audit rows, place that database file in the project root and run:

```powershell
npm run db:migrate-sqlite
```

The migration stops if Neon already contains user records, to avoid accidental duplication or overwriting. It preserves IDs and encrypted values. Keep the old `harbor.db` as a private backup until the migrated application has been verified. The `ENC_KEY` used by the new deployment MUST be the same key used to encrypt the existing SQLite records; otherwise encrypted names and loan purposes cannot be decrypted. If you generated a new key, do not migrate old encrypted records until you have the original key or have decided to discard/re-enter that test data.

If you do not need any old local data, skip the migration and use `npm run db:init`.

## 5. Run locally

```powershell
npm start
```

Open `http://localhost:3000`. Test account registration, password login, email OTP, dashboard, deposit/withdraw simulation, loan application, and logout. Check `http://localhost:3000/api/health` for a database connectivity response.

## 6. Deploy to Vercel

1. Push the project to a private GitHub repository. Confirm `.env` and `harbor.db` are not staged or committed.
2. Import the repository into Vercel.
3. Set the following Project Environment Variables for **Production** (and Preview if needed):
   - `NODE_ENV` = `production`
   - `JWT_SECRET` = a fresh strong secret generated for deployment
   - `ENC_KEY` = the encryption key required for the data being migrated; do not change it after storing encrypted data
   - `DATABASE_URL` = Neon connection string (use the pooled connection string for serverless deployment)
   - `RESEND_API_KEY` = Resend API key
   - `RESEND_FROM_EMAIL` = `onboarding@resend.dev` for restricted testing, or an address on a domain verified in Resend
4. Deploy. Vercel uses `api/index.js` and `vercel.json` to route requests through Express.
5. Open the deployed site and test `/api/health`, registration, MFA email delivery, MFA verification, authenticated dashboard access, and logout.

Do not place secrets in frontend files, GitHub, screenshots, or chat messages. If any secret has been exposed, rotate it.

## Important limitations / verification status

- This build has been syntax-checked, but it has not been connected to your private Neon database or Resend account from this environment. You must run the database check and end-to-end tests using your own environment variables.
- The SQLite-to-PostgreSQL migration script is optional and requires the old local `harbor.db` file. No existing data is automatically transferred merely by setting `DATABASE_URL`.
- Vercel's serverless runtime and Neon connection behavior must be verified after deployment. The database pool is intentionally kept small for serverless use.
- Resend's test sender is not a production sender for arbitrary users. Verify a sending domain before public use.
- This is an educational demonstration application, not a production banking platform. Do not use real customer funds or sensitive financial data.
=======
# Habour-savings-2
>>>>>>> b4f52c7f1df88aa6e76a58d9ce7cfeaab0341f60
