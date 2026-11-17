<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';

/** The PHP session, and nothing else. */

function session_lifetime_seconds(): int
{
    return (int) um_config('session_lifetime');
}

function start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;

    session_save_path_own();
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
        'cookie_secure' => session_cookie_is_secure(),
        /* Refuse a session id the server did not issue. Part of the fixation defence. */
        'use_strict_mode' => true,
        'gc_maxlifetime' => session_lifetime_seconds(),
        'cookie_lifetime' => session_lifetime_seconds(),
    ]);
    session_cookie_refresh();
}

/**
 * Keep session files in a directory of our own, so a shared host's 24 minute sweeper cannot delete
 * them under a long-lived cookie. Set `session_path` to false to use PHP's default instead.
 */
function session_save_path_own(): void
{
    $path = um_config('session_path');
    if (!is_string($path) || $path === '') return;

    if (!is_dir($path)) @mkdir($path, 0700, true);
    if (!is_dir($path) || !is_writable($path)) return;

    /* Belt and braces if the directory ends up under a web root. */
    $guard = $path . '/.htaccess';
    if (!is_file($guard)) @file_put_contents($guard, "Require all denied\n");

    ini_set('session.save_path', $path);
    /* We are now the only collector, so it has to actually run. */
    ini_set('session.gc_probability', '1');
    ini_set('session.gc_divisor', '200');
}

/** Push the cookie's expiry out on every request, so the window follows the person. */
function session_cookie_refresh(): void
{
    if (headers_sent() || session_status() !== PHP_SESSION_ACTIVE) return;

    setcookie(session_name(), session_id(), [
        'expires' => time() + session_lifetime_seconds(),
        'path' => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => session_cookie_is_secure(),
    ]);
}

/** Secure when the request is encrypted, when APP_URL is https, or when APP_ENV is production. */
function session_cookie_is_secure(): bool
{
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;
    if (str_starts_with(strtolower(trim((string) getenv('APP_URL'))), 'https://')) return true;

    return strtolower(trim((string) getenv('APP_ENV'))) === 'production';
}

/** Release PHP's file-session lock before slow work. */
function release_session_lock(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
}

function um_csrf_token(): string
{
    start_session();
    if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(24));

    return $_SESSION['csrf'];
}

/** True when the POSTed (or header) token matches. Both halves must be non-empty. */
function um_check_csrf(): bool
{
    start_session();
    $token = $_POST['csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    $expected = (string) ($_SESSION['csrf'] ?? '');

    return is_string($token) && $token !== '' && $expected !== '' && hash_equals($expected, $token);
}
