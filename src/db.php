<?php

declare(strict_types=1);

/**
 * Configuration, the PDO opener and the schema for the three tables this package owns.
 *
 * Every other file requires this one, and this one requires nothing, so there is no include cycle.
 */

/** Set options once at boot: `um_configure(['db_path' => '/var/lib/app/users.db', ...])`. */
function um_configure(array $options): void
{
    um_config_store($options);
    /* A new db_path or session setting must not be ignored because a connection already exists. */
    $GLOBALS['um_pdo'] = null;
}

function um_config_store(?array $set = null): array
{
    static $config = [];
    if ($set !== null) $config = array_merge($config, $set);

    return $config;
}

function um_config(string $key): mixed
{
    $config = um_config_store();
    if (array_key_exists($key, $config)) return $config[$key];

    $root = dirname(__DIR__);
    $defaults = [
        'db_path' => ((string) getenv('USER_MGMT_DB')) !== '' ? (string) getenv('USER_MGMT_DB') : $root . '/data/users.db',
        /* A directory of our own for session files, or false to leave PHP's default alone. */
        'session_path' => $root . '/data/sessions',
        'session_lifetime' => 30 * 24 * 60 * 60,
        'jwks_cache_path' => $root . '/data/google-jwks.json',
        'jwks_override' => null,
        'app_name' => 'My App',
        /* Paths of the pages the host mounts. Used for redirects and for links inside emails. */
        'login_path' => '/login',
        'reset_path' => '/reset',
        'google_link_path' => '/google-link',
        'google_undo_path' => '/google-undo',
        /* Where a successful sign-in goes when no allowed return URL was remembered. */
        'default_redirect' => '/',
        /* Hosts an absolute return URL may point at. Relative paths are always allowed. */
        'allowed_return_hosts' => [],
        'email_dns_check' => true,
        /* Optional: fn(string $action, ?string $identity): void, throws RuntimeException to refuse. */
        'rate_limiter' => null,
        /* Optional: fn(): string, for hosts behind a proxy. Default is REMOTE_ADDR. */
        'client_ip' => null,
        /* Optional overrides: ['password_reset' => fn(array $ctx): array{subject,body}, 'google_linked' => ...]. */
        'templates' => [],
    ];

    return $defaults[$key] ?? null;
}

function um_app_url(): string
{
    $url = rtrim(trim((string) getenv('APP_URL')), '/');
    if ($url === '') throw new RuntimeException('APP_URL is not set, so links in emails cannot be built.');

    return $url;
}

function um_client_ip(): string
{
    $custom = um_config('client_ip');
    if (is_callable($custom)) return (string) $custom();

    return (string) ($_SERVER['REMOTE_ADDR'] ?? 'cli');
}

/** Ask the host's limiter, if it registered one. It refuses by throwing RuntimeException. */
function um_rate_limit(string $action, ?string $identity = null): void
{
    $limiter = um_config('rate_limiter');
    if (is_callable($limiter)) $limiter($action, $identity);
}

function um_e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function um_redirect(string $url): never
{
    header('Location: ' . $url);
    exit;
}

function um_db(): PDO
{
    if (($GLOBALS['um_pdo'] ?? null) instanceof PDO) return $GLOBALS['um_pdo'];

    $path = (string) um_config('db_path');
    if ($path !== ':memory:' && !is_dir(dirname($path))) @mkdir(dirname($path), 0700, true);
    $pdo = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA busy_timeout = 5000');
    um_bootstrap_schema($pdo);

    return $GLOBALS['um_pdo'] = $pdo;
}

/** Idempotent. Safe to run on every connection. */
function um_bootstrap_schema(PDO $pdo): void
{
    /* password_hash is nullable: an account created by Google sign-in has no password until the
       person sets one through the reset flow. session_version is bumped to revoke every session. */
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            name TEXT,
            google_sub TEXT,
            google_picture TEXT,
            session_version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )'
    );
    $pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL');

    /* Only the SHA-256 of the token is stored. */
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            requested_ip TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )'
    );

    /* One row per Google auto-link, so the emailed undo link can detach it. Hash only. */
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS google_undo_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            google_sub TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )'
    );
}
