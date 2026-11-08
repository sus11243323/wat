# Wataszit dashboard + Discord beta review + website chat

## Features
- Account registration with mandatory 6-digit email verification (10-minute expiry, hashed verification codes, attempt limits) and password login (scrypt password hashing, HttpOnly session cookie).
- Invite generation and invite validation.
- Beta applications reviewed through Discord **Accept / Decline** buttons.
- Dashboard checks application state in near-real-time. Once accepted, the styled **Join** button appears and opens `BETA_SERVER_URL`.
- Discord bot can synchronize server channels and process the existing website-to-Discord message queue. The dashboard chat box is currently hidden.
- Logout and server-side session invalidation.

## Setup
1. Use Node.js 20 or newer.
2. Copy `.env.example` to `.env` and fill in real values. Never commit `.env`.
3. Create a Resend account, verify your sending domain, then set `RESEND_API_KEY` and `EMAIL_FROM` in `.env`. Registration sends a one-time 6-digit code through the Resend email API; without these settings registration will fail safely instead of creating an unverified account.
4. Create a Discord bot, invite it to the target server, and grant it **View Channels**, **Send Messages**, and **Read Message History** permissions for the channels it should access. It needs the Guilds intent; no message-content intent is needed.
5. Set `DISCORD_BOT_TOKEN`, `DISCORD_BETA_CHANNEL_ID`, `BETA_REVIEW_SECRET`, and `WATASZIT_API_URL`. Set `BETA_SERVER_URL` to the actual server join URL. `BETA_REVIEW_SECRET` must be a long random secret shared by the backend and bot.
6. Install and run:
   ```bash
   npm install
   npm start
   ```
   In a second process, run:
   ```bash
   npm run beta-bot
   ```

The backend must be publicly reachable by the bot if they run on separate hosts. Both services must use the same persistent storage volume because this version stores users, sessions, applications, and chat queues in JSON files. For multi-instance/production deployments, move these stores to a shared database.

## Email verification

New registrations first submit the account details, then the server emails a 6-digit code. The account is created and the invite is consumed only after the code is correct. Users can request a replacement code from the verification screen. Verification codes are stored as SHA-256 hashes, expire after 10 minutes, and are deleted after successful verification or expiry. Email delivery uses the Resend HTTPS API, so no SMTP password is stored in the app.

## Notes
- The bot synchronizes available text channels every 30 seconds and checks the website-to-Discord message queue every 2 seconds.
- The browser refreshes beta status every 3 seconds. Registration verification codes expire after 10 minutes and allow at most 5 attempts.
- The website chat is a one-way bridge: website messages are posted by the bot into Discord. Messages typed directly in Discord are not mirrored back into the website.
- The existing beta application flow collects the applicant's IP address. Keep the review channel private and disclose this collection to applicants.
- Use HTTPS in production. Set `NODE_ENV=production` so session cookies are marked Secure. Configure `TRUST_PROXY` only for a trusted reverse proxy.
- Do not expose `BETA_REVIEW_SECRET` or the Discord bot token to frontend code.


### Admin console commands

Open the browser developer console while viewing the site and run `NOINVITEREG()`. The command asks for `ADMIN_CONSOLE_PASSWORD` and toggles registration without invite codes on/off. The setting is stored server-side in `storage/settings.json` and survives restarts.

Set `RELEASE_SERVER_URL` in `.env` to show the small **Join Release** button in the dashboard. The Beta Join button remains visible only for accounts whose beta application is accepted.
