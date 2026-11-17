<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/turnstile.php';

/**
 * Is this URL a safe place to send a person after sign-in?
 *
 * Relative paths ("/dashboard?x=1") are always allowed. An absolute http(s) URL is allowed only when
 * its host is listed in the `allowed_return_hosts` option. Anything else, including "//evil.test",
 * "/\evil.test" and "javascript:", is refused. This is the open-redirect defence.
 */
function auth_return_url_allowed(string $url): bool
{
    if ($url === '' || strlen($url) > 2048 || preg_match('/[\x00-\x1f\x7f\\\\]/', $url) === 1) return false;
    if ($url[0] === '/') return !str_starts_with($url, '//');

    $parts = parse_url($url);
    if (!is_array($parts) || !in_array($parts['scheme'] ?? '', ['http', 'https'], true) || empty($parts['host'])) {
        return false;
    }
    $allowed = array_map('strtolower', (array) um_config('allowed_return_hosts'));

    return in_array(strtolower($parts['host']), $allowed, true);
}

function remember_auth_return_url(string $url): void
{
    if (auth_return_url_allowed($url)) $_SESSION['auth_return_url'] = $url;
}

/** Remember the request being made now, when it is a GET worth coming back to. */
function remember_current_url_for_auth(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') return;
    remember_auth_return_url((string) ($_SERVER['REQUEST_URI'] ?? ''));
}

function take_auth_return_url(): ?string
{
    start_session();
    $url = $_SESSION['auth_return_url'] ?? null;
    unset($_SESSION['auth_return_url']);

    return is_string($url) && auth_return_url_allowed($url) ? $url : null;
}

/** Where to send a person who just signed in: the remembered return URL, else `default_redirect`. */
function post_login_redirect(): string
{
    return take_auth_return_url() ?? (string) um_config('default_redirect');
}

/** The signed-in user (no password hash), or null. A bumped session_version signs the old session out. */
function current_user(): ?array
{
    start_session();
    $userId = $_SESSION['user_id'] ?? null;
    if (!is_int($userId) && !ctype_digit((string) $userId)) return null;

    $statement = um_db()->prepare(
        'SELECT id, name, email, session_version, google_sub, google_picture, created_at,
                (password_hash IS NOT NULL) AS has_password
         FROM users WHERE id = :id'
    );
    $statement->execute(['id' => (int) $userId]);
    $user = $statement->fetch();
    $statement->closeCursor();
    if (!$user || !isset($_SESSION['auth_session_version'])
        || (int) $_SESSION['auth_session_version'] !== (int) $user['session_version']) {
        if (isset($_SESSION['user_id'])) {
            unset($_SESSION['user_id'], $_SESSION['auth_session_version']);
            session_regenerate_id(true);
        }

        return null;
    }

    return $user;
}

/** Issue an authenticated session bound to the user's current revocation version. */
function establish_authenticated_session(int $userId): void
{
    $statement = um_db()->prepare('SELECT session_version FROM users WHERE id = ?');
    $statement->execute([$userId]);
    $version = $statement->fetchColumn();
    $statement->closeCursor();
    if ($version === false) throw new RuntimeException('User not found.');

    start_session();
    /* A new id on every sign-in: a session id planted before login is worthless after it. */
    session_regenerate_id(true);
    unset($_SESSION['csrf']);
    $_SESSION['user_id'] = $userId;
    $_SESSION['auth_session_version'] = (int) $version;
}

function validate_email_address(string $email): ?string
{
    if (strlen($email) > 254 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return 'Enter a valid email address.';
    }
    $domain = strtolower(substr($email, strrpos($email, '@') + 1));
    $testDomains = ['example.com', 'example.net', 'example.org', 'example.test', 'test', 'localhost'];
    if (um_config('email_dns_check') && !in_array($domain, $testDomains, true)
        && !checkdnsrr($domain, 'MX') && !checkdnsrr($domain, 'A')) {
        return 'That email domain does not appear to accept mail.';
    }

    return null;
}

function validate_new_password(string $password): ?string
{
    if (strlen($password) < 8) return 'Password must be at least 8 characters.';
    /* bcrypt ignores everything past 72 bytes, so refuse rather than silently truncate. */
    if (strlen($password) > 72) return 'Password must be at most 72 characters.';

    return null;
}

/** Create an account and sign it in. Runs the Turnstile check first when it is configured. */
function register_user(string $email, string $password, string $name = ''): array
{
    $email = strtolower(trim($email));
    try {
        um_rate_limit('register');
        turnstile_check();
    } catch (RuntimeException $exception) {
        return ['ok' => false, 'error' => $exception->getMessage()];
    }
    $error = validate_email_address($email) ?? validate_new_password($password);
    if ($error !== null) return ['ok' => false, 'error' => $error];

    try {
        um_db()->prepare('INSERT INTO users (email, password_hash, name) VALUES (:email, :hash, :name)')
            ->execute(['email' => $email, 'hash' => password_hash($password, PASSWORD_DEFAULT),
                'name' => trim($name) !== '' ? trim($name) : null]);
    } catch (PDOException $exception) {
        if ($exception->getCode() === '23000') {
            return ['ok' => false, 'error' => 'An account already exists for that email.'];
        }
        throw $exception;
    }

    establish_authenticated_session((int) um_db()->lastInsertId());

    return ['ok' => true];
}

function login_user(string $email, string $password): array
{
    $email = strtolower(trim($email));
    try {
        um_rate_limit('login', $email);
    } catch (RuntimeException $exception) {
        return ['ok' => false, 'error' => $exception->getMessage()];
    }
    $statement = um_db()->prepare('SELECT id, password_hash FROM users WHERE email = :email');
    $statement->execute(['email' => $email]);
    $user = $statement->fetch();

    /* A Google-only account has no hash. Verify against a dummy anyway so timing does not say so. */
    $hash = is_array($user) && is_string($user['password_hash'])
        ? $user['password_hash'] : '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';
    $matches = password_verify($password, $hash);
    if (!$user || !is_string($user['password_hash']) || !$matches) {
        return ['ok' => false, 'error' => 'Email or password is incorrect.'];
    }

    establish_authenticated_session((int) $user['id']);

    return ['ok' => true];
}

function logout_user(): void
{
    start_session();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'],
            $params['secure'], $params['httponly']);
    }
    session_destroy();
}

/**
 * Set a new password and revoke every existing session for the account by bumping session_version.
 * The caller decides whether to sign the person back in.
 */
function update_user_password(int $userId, string $password): void
{
    $updated = um_db()->prepare('UPDATE users SET password_hash = :hash, session_version = session_version + 1
        WHERE id = :id');
    $updated->execute(['hash' => password_hash($password, PASSWORD_DEFAULT), 'id' => $userId]);
    if ($updated->rowCount() !== 1) throw new RuntimeException('That account could not be found.');
}

/** The signed-in user, or a redirect to `login_path` that remembers where they were going. */
function require_user(): array
{
    $user = current_user();
    if (!$user) {
        remember_current_url_for_auth();
        um_redirect((string) um_config('login_path'));
    }

    return $user;
}
