<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/mailer.php';

/** How long a reset link stays usable. */
const PASSWORD_RESET_TTL = 3600;

function password_reset_url(string $token): string
{
    return um_app_url() . (string) um_config('reset_path') . '?token=' . rawurlencode($token);
}

/**
 * Start a reset. Always answers the same way (nothing), whether or not the address has an account.
 * A form that says "no such account" is a free enumeration tool for anyone with a list of addresses.
 */
function request_password_reset(string $email): void
{
    um_rate_limit('reset');
    /* Resolved before the lookup so a misconfiguration fails the same way for every address. */
    um_app_url();
    $email = strtolower(trim($email));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return;

    $statement = um_db()->prepare('SELECT id FROM users WHERE email = :email');
    $statement->execute(['email' => $email]);
    $user = $statement->fetch();
    if (!$user) return;

    /* Only the hash is stored. Somebody who reads the database still cannot build a working link. */
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);
    um_db()->prepare('INSERT INTO password_resets (user_id, token_hash, expires_at, requested_ip)
        VALUES (:user_id, :token_hash, :expires_at, :ip)')->execute([
        'user_id' => (int) $user['id'],
        'token_hash' => $tokenHash,
        'expires_at' => gmdate('Y-m-d H:i:s', time() + PASSWORD_RESET_TTL),
        'ip' => um_client_ip(),
    ]);

    $mail = mail_template('password_reset', ['app_name' => um_config('app_name'), 'link' => password_reset_url($token)]);
    if (mail_send($email, $mail['subject'], $mail['body'])) {
        /* Retire older links only after the new message was accepted. A failed delivery must not
           replace the only recovery path. */
        um_db()->prepare('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP
            WHERE user_id = :user_id AND used_at IS NULL AND token_hash <> :token_hash')
            ->execute(['user_id' => (int) $user['id'], 'token_hash' => $tokenHash]);
    }
}

/** The row behind a token, or null when it is unknown, already used, or past its expiry. */
function password_reset_row(string $token): ?array
{
    if ($token === '') return null;

    $statement = um_db()->prepare('SELECT id, user_id, expires_at FROM password_resets
        WHERE token_hash = :hash AND used_at IS NULL');
    $statement->execute(['hash' => hash('sha256', $token)]);
    $row = $statement->fetch();
    if (!$row || strtotime((string) $row['expires_at'] . ' UTC') < time()) return null;

    return $row;
}

/**
 * Finish a reset: set the password, spend the token (and every other live one for the account),
 * revoke old sessions, and sign the person in.
 */
function complete_password_reset(string $token, string $password, string $confirm): array
{
    $expired = ['ok' => false, 'error' => 'That reset link has expired or has already been used. Ask for a new one.'];
    $row = password_reset_row($token);
    if (!$row) return $expired;
    $error = validate_new_password($password);
    if ($error !== null) return ['ok' => false, 'error' => $error];
    if (!hash_equals($password, $confirm)) return ['ok' => false, 'error' => 'The two passwords do not match.'];

    $pdo = um_db();
    $pdo->beginTransaction();
    try {
        $claim = $pdo->prepare('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP
            WHERE id = :id AND used_at IS NULL');
        $claim->execute(['id' => (int) $row['id']]);
        if ($claim->rowCount() !== 1) {
            $pdo->rollBack();

            return $expired;
        }
        $pdo->prepare('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP
            WHERE user_id = :user_id AND used_at IS NULL')->execute(['user_id' => (int) $row['user_id']]);
        update_user_password((int) $row['user_id'], $password);
        $pdo->commit();
    } catch (Throwable $exception) {
        $pdo->rollBack();
        throw $exception;
    }

    establish_authenticated_session((int) $row['user_id']);

    return ['ok' => true];
}

/** A reset token must not enter caches, referrers or search indexes. Call before rendering /reset. */
function password_reset_security_headers(): void
{
    header('Cache-Control: no-store, private, max-age=0');
    header('Pragma: no-cache');
    header('Referrer-Policy: no-referrer');
    header('X-Robots-Tag: noindex, nofollow');
}
