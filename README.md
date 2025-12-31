# Cloudflare Workers Secure Text Share

This project is a secure text sharing application built with Cloudflare Workers, Hono, and D1 Database. It allows users to securely share text snippets using client-side (Worker-side) encryption.

## Features

- **Store & Share**: Encrypts text and stores it in D1.
- **Secure Retrieval**: Returns decrypted text only with the correct token.
- **Curl Friendly**: API accepts and returns raw text.
- **Web UI**: Simple, dark-themed Interface for ease of use.

## Prerequisites

- Node.js installed.
- Cloudflare Account.
- Wrangler CLI (`npm install -g wrangler`).

## Local Development

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Initialize Local Database**
   ```bash
   npx wrangler d1 execute DB --local --file=./schema.sql
   ```

3. **Start Development Server**
   ```bash
   npm run dev
   # or
   npx wrangler dev
   ```
   Access the app at `http://localhost:8787`.

## Deployment

1. **Login to Cloudflare**
   ```bash
   npx wrangler login
   ```

2. **Create D1 Database**
   Create a new D1 database in the Cloudflare dashboard or via CLI:
   ```bash
   npx wrangler d1 create share_db
   ```
   *Copy the `database_id` output from this command.*

3. **Update Configuration**
   Edit `wrangler.toml` and replace the `database_id` with your new database ID.
   ```toml
   [[d1_databases]]
   binding = "DB"
   database_name = "share_db"
   database_id = "YOUR_DATABASE_ID_HERE"
   ```

4. **Initialize Remote Database**
   Apply the schema to the production database:
   ```bash
   npx wrangler d1 execute DB --remote --file=./schema.sql
   ```

5. **Set Secret Key**
   Set the `SECRET_KEY` environment variable for production (use a strong random string):
   ```bash
   npx wrangler secret put SECRET_KEY
   ```

6. **Deploy**
   ```bash
   npm run deploy
   # or
   npx wrangler deploy
   ```

## API Usage

### Share Text
```bash
curl -X POST -d "Your secret text here" https://your-worker.your-subdomain.workers.dev/api/share
# Returns: <TOKEN>
```

### Retrieve Text
```bash
curl "https://your-worker.your-subdomain.workers.dev/api/retrieve?token=<TOKEN>"
# Returns: Your secret text here
```
