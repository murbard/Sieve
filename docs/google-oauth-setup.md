# Setting up Google OAuth credentials for Sieve

Sieve needs a Google OAuth "client ID" to connect to your Google account.
This is a one-time setup that takes about 5 minutes.

## Is this sensitive?

**Not really.** Google explicitly documents that OAuth client credentials for
desktop/installed applications are [not treated as secrets](https://developers.google.com/identity/protocols/oauth2):

> "The process results in a client ID and, in some cases, a client secret,
> which you embed in the source code of your application. In this context,
> the client secret is obviously not treated as a secret."

The client ID identifies the *app*, not your *account*. Your actual account
access is protected by the OAuth consent flow — you explicitly approve what
the app can do each time you connect. The credentials file can safely be
committed to a private repo or shared with collaborators.

That said, Sieve's `.gitignore` excludes it by default to keep things clean.

## Step by step

### 1. Go to Google Cloud Console

Open https://console.cloud.google.com/

Sign in with any Google account (personal is fine — this doesn't affect which
accounts you can connect later).

### 2. Create a project (or select an existing one)

- Click the project dropdown at the top of the page
- Click **New Project**
- Name it something like "Sieve"
- Click **Create**

### 3. Enable the APIs

Go to **APIs & Services → Library** (or https://console.cloud.google.com/apis/library).

Search for and enable each of these:

- **Gmail API**
- **Google Drive API**
- **Google Calendar API**
- **Google People API** (Contacts)
- **Google Sheets API**
- **Google Docs API**

Click each one, then click **Enable**.

You can skip any you don't plan to use — Sieve will only access services
you've enabled here.

### 4. Configure the OAuth consent screen

Go to **APIs & Services → OAuth consent screen** (or https://console.cloud.google.com/apis/credentials/consent).

- Select **External** (unless you have a Google Workspace org and want internal only)
- Click **Create**
- Fill in:
  - **App name**: Sieve
  - **User support email**: your email
  - **Developer contact email**: your email
- Click **Save and Continue** through the remaining steps (Scopes, Test Users, Summary)
- Click **Back to Dashboard**

**Note:** The app will be in "Testing" mode, which means only test users you
explicitly add can use it. You can add your email(s) under **Test users**.
Alternatively, when connecting, you can click "Advanced" → "Go to Sieve
(unsafe)" to bypass the unverified app warning.

### 5. Create OAuth credentials

Go to **APIs & Services → Credentials** (or https://console.cloud.google.com/apis/credentials).

- Click **+ Create Credentials → OAuth client ID**
- Application type: **Web application**
- Name: Sieve (or anything)
- Under **Authorized redirect URIs**, add:
  ```
  http://localhost:19816/oauth/callback
  ```
  (If you access Sieve via a different hostname/port, use that instead)
- Click **Create**

### 6. Download the credentials JSON

After creating, you'll see a dialog with your Client ID and Client Secret.

- Click **Download JSON**
- Save the file as `data/gmail_credentials.json` in your Sieve directory

The file looks like this:

```json
{
  "web": {
    "client_id": "123456789-xxxxxxxx.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxxxxxxx",
    "redirect_uris": ["http://localhost:19816/oauth/callback"],
    ...
  }
}
```

### 7. Configure Sieve

Make sure your `sieve.yaml` points to the file:

```yaml
connectors:
  google:
    client_credentials_file: "./data/gmail_credentials.json"
```

### 8. Connect your account

1. Start Sieve: `./sieve serve`
2. Open http://localhost:19816/connections
3. Click **Connect Google Account**
4. Sign in with the Google account you want to connect
5. Approve the requested permissions
6. Done — your connection appears in the list

You can connect multiple Google accounts. Each gets its own alias
(e.g., "work", "personal") and policies are configured per-connection.

## Troubleshooting

### "redirect_uri_mismatch" error

The redirect URI in Google Cloud Console must **exactly** match what Sieve
sends. Check:

- Port matches (default: 19816)
- Path is `/oauth/callback` (not `/oauth/callback/` with trailing slash)
- Protocol is `http` (not `https`, unless you're behind a reverse proxy)
- If accessing via hostname (not localhost), the hostname must match

### "This app isn't verified" warning

Expected in Testing mode. Either:
- Add your email as a test user in the OAuth consent screen
- Or click **Advanced → Go to Sieve (unsafe)** to proceed

### "Access blocked: This app's request is invalid"

Usually means the redirect URI doesn't match. Click "error details" on the
Google error page — it shows the exact URI mismatch.

## Sharing credentials with collaborators

Since the client ID/secret are not account credentials (they just identify
the app), you can share the JSON file with collaborators. Each person still
needs to go through the OAuth consent flow with their own Google account.

For teams, you can:
- Commit the file to a private repo
- Share it via a secure channel
- Or have each person create their own Google Cloud project
