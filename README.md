# AI eBook Generation User Management

Generic PHP user management: email and password accounts, Google sign-in, registration, and password
reset on SQLite. Plain functions, no framework, one Composer dependency (`firebase/php-jwt`, used to
verify Google ID tokens). It was extracted from a production app and stripped of everything
app-specific. No keys are included: every secret comes from the environment.

Requires PHP 8.2+ with `pdo_sqlite` and `curl`.

## Install

```bash
composer require wesblackmore/ai-ebook-generation-user-management
# or clone it and run: composer install
```

Then load it, either through Composer's autoloader (it registers `src/autoload.php`) or directly:

```php
require 'path/to/src/autoload.php';
```

Functions live in the global namespace (`register_user()`, `login_user()`, `current_user()`, ...).
Package internals are prefixed `um_`.

## Quick start

```php
require 'src/autoload.php';

um_configure([
    'db_path'          => '/var/lib/myapp/users.db',
    'app_name'         => 'My App',
    'default_redirect' => '/dashboard',
    'allowed_return_hosts' => ['app.example.com'],
]);

mailer_register(function (string $toEmail, string $subject, string $body): bool {
    return my_smtp_send($toEmail, $subject, $body);   // return false on failure
});

$result = register_user($_POST['email'], $_POST['password'], $_POST['name'] ?? '');
if ($result['ok']) um_redirect(post_login_redirect());
```

The SQLite file and its three tables are created on first use. To try everything now, with no keys:

```bash
composer install
php -S localhost:8000 examples/index.php
```

Open http://localhost:8000. Register, log out, log in, and use "Forgot your password?". With no
mail transport configured the reset link is printed to the server log (the terminal running
`php -S`). `sh examples/smoke.sh` drives the whole flow with curl and prints `SMOKE PASSED`.
`php tools/selfcheck.php` runs the assertion suite.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `APP_URL` | for password reset | Public base URL, e.g. `https://app.example.com`. Used to build links in emails. Never taken from the request, so a forged Host header cannot poison a reset link. Also makes the session cookie `Secure` when it starts with `https://`. |
| `APP_ENV` | no | `production` forces the `Secure` cookie flag. |
| `USER_MGMT_DB` | no | SQLite path. Overridden by the `db_path` option. Default `data/users.db` inside the package. |
| `MAIL_FROM` | no | Sender address. When set, the default mailer uses PHP `mail()`. When unset the default mailer only logs. Ignored if you register your own mailer. |
| `GOOGLE_CLIENT_ID` | for Google | OAuth client id. Also the expected `aud` of the ID token. |
| `GOOGLE_CLIENT_SECRET` | for Google | OAuth client secret. |
| `GOOGLE_REDIRECT_URI` | for Google | Full callback URL registered with Google. |
| `TURNSTILE_SITE_KEY` | no | Cloudflare Turnstile site key. |
| `TURNSTILE_SECRET` | no | Cloudflare Turnstile secret. With this unset the bot check is skipped entirely. |

`google_configured()` is false unless all three Google variables are set; the example hides the
button until then. Turnstile needs both its keys to switch on.

## Options (`um_configure`)

| Option | Default | Meaning |
|---|---|---|
| `db_path` | `$USER_MGMT_DB` or `data/users.db` | SQLite file. |
| `session_path` | `data/sessions` | Own session directory (so a shared host's sweeper cannot delete sessions). `false` keeps PHP's default. |
| `session_lifetime` | 30 days | Session and cookie lifetime, refreshed on each request. |
| `app_name` | `My App` | Used in email wording. |
| `login_path` | `/login` | Where `require_user()` sends signed-out visitors. |
| `reset_path` | `/reset` | Path of your reset page, used in the emailed link. |
| `google_link_path` | `/google-link` | Where `google_callback()` sends a visitor who must confirm a password. |
| `google_undo_path` | `/google-undo` | Path of your undo page, used in the Google-link notice. |
| `default_redirect` | `/` | Post-login target when no return URL was remembered. |
| `allowed_return_hosts` | `[]` | Hosts an absolute return URL may use. Relative paths are always allowed. |
| `email_dns_check` | `true` | Reject domains with no MX or A record. Turn off for offline tests. |
| `rate_limiter` | none | `fn(string $action, ?string $identity): void`, throw `RuntimeException` to refuse. Actions: `register`, `login`, `reset`. |
| `client_ip` | `REMOTE_ADDR` | `fn(): string` for hosts behind a proxy. |
| `templates` | `[]` | Email template overrides, see below. |
| `jwks_override` | none | Inject Google signing keys (tests). |

## The mailer

Everything the package emails (reset links, the Google-link notice) goes through one function.

```php
mailer_register(function (string $toEmail, string $subject, string $body): bool {
    // Send it however you like. Return false, or throw, to report failure.
    return true;
});
```

With nothing registered, the default sends through PHP `mail()` when `MAIL_FROM` is set, and
otherwise writes the full message (including the reset link) to `error_log` and reports success, so
local development works without SMTP. Do not run the logging fallback in production.

Wording lives in `mail_template()` in `src/mailer.php`. Override it per template without editing the package:

```php
um_configure(['templates' => [
    'password_reset' => fn(array $ctx): array => [   // $ctx: app_name, link
        'subject' => 'Your reset link',
        'body'    => "Reset here: {$ctx['link']}",
    ],
    'google_linked' => fn(array $ctx): array => [    // $ctx: app_name, link, email
        'subject' => 'Google connected', 'body' => "Undo: {$ctx['link']}",
    ],
]]);
```

## Wiring the routes

The package gives you functions, you own the pages. `examples/index.php` is a complete reference.

| Route | Calls |
|---|---|
| `POST /register` | `register_user($email, $password, $name)`, then `um_redirect(post_login_redirect())` |
| `POST /login` | `login_user($email, $password)` |
| `POST /logout` | `logout_user()` |
| any protected page | `$user = require_user();` remembers the URL and redirects to `login_path` |
| `POST /forgot` | `request_password_reset($email)`, then always show the same "check your email" page |
| `GET/POST /reset?token=` | `password_reset_security_headers()`, `password_reset_row($token)` to pre-check, `complete_password_reset($token, $pw, $confirm)` |
| `POST /google` | `google_begin()` (or `google_begin(true)` to connect Google to the signed-in account) |
| `GET /google-callback` | `um_redirect(google_callback($_GET))` |
| `GET/POST /google-link` | `google_link_pending()` to show the form, `google_link_with_password($pw)` to confirm |
| `GET /google-undo?token=` | `google_consume_undo_token($token)` |

Forms must carry the CSRF token: put `um_csrf_token()` in a hidden field named `csrf`, and call
`um_check_csrf()` (returns bool) before acting on any POST. With Turnstile configured, add
`turnstile_widget()` inside the register form and `turnstile_script()` to the page;
`register_user()` runs the check itself.

## Google setup

1. In the Google Cloud console, create an OAuth client of type "Web application".
2. Add your callback URL (for example `https://app.example.com/google-callback`) as an authorized redirect URI.
3. Export `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `GOOGLE_REDIRECT_URI` (the same callback URL).
4. Show a button that POSTs to the route calling `google_begin()` when `google_configured()` is true.

How accounts are matched: the Google subject (`sub`) is the join key. A new subject with an unused
email creates a password-less account. A new subject whose verified email matches a password
account is linked in place and the owner gets a notice with a 24 hour undo link through your mailer;
if that notice cannot be sent the link is reverted and the visitor must type the account's password
once (`google_link_with_password`).

ID token checks: RS256 signature against Google's JWKS (cached 12 hours, one forced refresh on an
unknown key id), issuer, audience equal to `GOOGLE_CLIENT_ID`, expiry, and `email_verified`.

## Security properties

- Passwords use `password_hash()` and `password_verify()`; length 8 to 72 bytes. Google-only accounts have a NULL hash and cannot password-login. Unknown emails cost the same hash check as known ones.
- Session id regenerated on every sign-in (fixation defence); `use_strict_mode`; cookies `HttpOnly`, `SameSite=Lax`, and `Secure` over HTTPS, when `APP_URL` is https, or in production.
- `session_version` is bumped on password change or reset, which signs out every other session for that account on its next request.
- Reset tokens are 256 random bits, stored only as SHA-256, single-use, expire in one hour, and a new link retires older ones. Completing a reset spends all of the account's live tokens in one transaction.
- Forgot-password answers identically for known and unknown emails, and reset links use `APP_URL`, not the Host header.
- CSRF helpers for every form; Google callback checks an unguessable `state`.
- Return URLs: relative paths, or hosts you list. `//host`, backslashes and non-http schemes are refused.
- Optional Turnstile; if the verifier is unreachable the request is refused, not waved through.
- Rate limiting is a hook, not built in: register your own `rate_limiter`.
- All SQL uses prepared statements.

## Schema

Created automatically (`um_bootstrap_schema()`), SQLite in WAL mode with foreign keys on.

```sql
users(id INTEGER PK, email TEXT NOT NULL UNIQUE, password_hash TEXT /* nullable */, name TEXT,
      google_sub TEXT /* unique when set */, google_picture TEXT,
      session_version INTEGER NOT NULL DEFAULT 1, created_at TEXT)
password_resets(id, user_id -> users, token_hash UNIQUE, expires_at, used_at, requested_ip, created_at)
google_undo_tokens(id, token_hash UNIQUE, user_id -> users, google_sub, created_at, expires_at)
```

## Tests

```bash
php tools/selfcheck.php   # assertion suite, exits non-zero on failure
sh examples/smoke.sh      # end-to-end run of the example app with curl
```

## No keys included

Nothing in this repository is a credential. The only secret-looking strings are obvious dummy values
in `tools/selfcheck.php`. `data/`, `vendor/`, `*.db`, `*.sqlite` and `.env` are gitignored.

## License

MIT, see `LICENSE`.
