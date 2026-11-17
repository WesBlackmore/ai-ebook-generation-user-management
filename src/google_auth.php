<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/mailer.php';

/**
 * Google sign-in over the OAuth 2.0 authorization code flow, with curl and firebase/php-jwt.
 * The ID token is verified in full (RS256 against Google's JWKS, issuer, audience, expiry,
 * email_verified) even though it arrives over a channel authenticated with the client secret.
 */

/**
 * A Google identity that matches an existing password account, waiting for one proof (the password).
 * Not a failure: the sign-in worked and the only open question is who owns the existing account.
 */
final class GoogleLinkRequired extends RuntimeException
{
    public function __construct(
        public readonly int $userId,
        public readonly string $subject,
        public readonly string $googleEmail,
        public readonly string $googleName,
        public readonly string $googlePicture = ''
    ) {
        parent::__construct('That address already has a password account here.');
    }
}

const GOOGLE_LINK_WINDOW_SECONDS = 600;
const GOOGLE_JWKS_TTL_SECONDS = 43200;
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

function google_configured(): bool
{
    return trim((string) getenv('GOOGLE_CLIENT_ID')) !== ''
        && trim((string) getenv('GOOGLE_CLIENT_SECRET')) !== ''
        && trim((string) getenv('GOOGLE_REDIRECT_URI')) !== '';
}

/** Keep the browser image request on Google's profile-image host, never an arbitrary URL. */
function google_picture_url(mixed $picture): string
{
    if (!is_string($picture) || strlen($picture) > 2048) return '';
    $parts = parse_url(trim($picture));
    $host = strtolower((string) ($parts['host'] ?? ''));
    if (($parts['scheme'] ?? '') !== 'https' || $host === '') return '';
    if ($host !== 'googleusercontent.com' && !str_ends_with($host, '.googleusercontent.com')) return '';

    return trim($picture);
}

/** Park a verified Google identity in the session while the visitor proves the local account is theirs. */
function google_link_pending_store(int $userId, string $subject, string $email, string $name, string $picture = ''): void
{
    start_session();
    $_SESSION['google_link_pending'] = ['user_id' => $userId, 'subject' => $subject,
        'email' => $email, 'name' => $name, 'picture' => $picture, 'at' => time()];
}

function google_link_pending(): ?array
{
    start_session();
    $pending = $_SESSION['google_link_pending'] ?? null;
    if (!is_array($pending) || !isset($pending['at'], $pending['user_id'], $pending['subject'])) return null;
    if (time() - (int) $pending['at'] > GOOGLE_LINK_WINDOW_SECONDS) {
        google_link_pending_clear();

        return null;
    }

    return $pending;
}

function google_link_pending_clear(): void
{
    start_session();
    unset($_SESSION['google_link_pending']);
}

/**
 * Prove ownership of the pending account with its password, then connect Google to it and sign in.
 * Rate limited like a login, and a wrong answer says the same thing every time.
 */
function google_link_with_password(string $password): array
{
    $pending = google_link_pending();
    if ($pending === null) return ['ok' => false, 'error' => 'That sign-in attempt has expired. Please try again.'];
    try {
        um_rate_limit('login', (string) $pending['email']);
    } catch (RuntimeException $exception) {
        return ['ok' => false, 'error' => $exception->getMessage()];
    }

    $statement = um_db()->prepare('SELECT password_hash FROM users WHERE id = :id');
    $statement->execute(['id' => (int) $pending['user_id']]);
    $hash = $statement->fetchColumn();
    if (!is_string($hash) || !password_verify($password, $hash)) {
        return ['ok' => false, 'error' => 'That password does not match this account.'];
    }

    google_attach_identity((int) $pending['user_id'], (string) $pending['subject'],
        (string) $pending['name'], (string) ($pending['picture'] ?? ''));
    google_link_pending_clear();
    establish_authenticated_session((int) $pending['user_id']);

    return ['ok' => true];
}

/**
 * Join a Google identity to an existing account. The caller must have proved ownership. The unique
 * index on google_sub is the last word: an identity already on another account is never moved.
 */
function google_attach_identity(int $userId, string $subject, string $name = '', string $picture = ''): bool
{
    $taken = um_db()->prepare('SELECT id FROM users WHERE google_sub = :sub AND id != :id');
    $taken->execute(['sub' => $subject, 'id' => $userId]);
    if ($taken->fetchColumn() !== false) {
        throw new RuntimeException('That Google account is already connected to another account here.');
    }

    $attach = um_db()->prepare('UPDATE users SET google_sub = :sub, google_picture = :picture,
        name = COALESCE(name, :name) WHERE id = :id');
    $attach->execute(['sub' => $subject, 'picture' => $picture !== '' ? $picture : null,
        'name' => $name !== '' ? $name : null, 'id' => $userId]);

    return $attach->rowCount() === 1;
}

/** The Google consent URL. The state value ties the return trip to this session. */
function google_authorization_url(): string
{
    if (!google_configured()) throw new RuntimeException('Google sign-in is not configured.');
    start_session();
    $_SESSION['google_state'] = bin2hex(random_bytes(16));

    return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
        'client_id' => trim((string) getenv('GOOGLE_CLIENT_ID')),
        'redirect_uri' => trim((string) getenv('GOOGLE_REDIRECT_URI')),
        'response_type' => 'code',
        'scope' => 'openid email profile',
        'state' => $_SESSION['google_state'],
        'prompt' => 'select_account',
    ]);
}

/** Send the visitor to Google. Pass $connect=true to join Google to the account already signed in. */
function google_begin(bool $connect = false): never
{
    start_session();
    $user = $connect ? current_user() : null;
    $_SESSION['google_connecting_user'] = $user !== null ? (int) $user['id'] : 0;

    um_redirect(google_authorization_url());
}

/**
 * Handle the return from Google. Answers the signed-in user id. Every failure throws, except an
 * address that already has a password account, which throws GoogleLinkRequired.
 */
function google_complete(string $code, string $state): int
{
    start_session();
    $expected = (string) ($_SESSION['google_state'] ?? '');
    unset($_SESSION['google_state']);

    /* The state check is the CSRF defence for this route. */
    if ($expected === '' || $state === '' || !hash_equals($expected, $state)) {
        throw new RuntimeException('That sign-in attempt has expired. Please try again.');
    }
    if ($code === '') throw new RuntimeException('Google did not return a sign-in code.');

    $token = google_post('https://oauth2.googleapis.com/token', [
        'code' => $code,
        'client_id' => trim((string) getenv('GOOGLE_CLIENT_ID')),
        'client_secret' => trim((string) getenv('GOOGLE_CLIENT_SECRET')),
        'redirect_uri' => trim((string) getenv('GOOGLE_REDIRECT_URI')),
        'grant_type' => 'authorization_code',
    ]);
    $claims = google_id_token_claims((string) ($token['id_token'] ?? ''));

    $subject = (string) ($claims['sub'] ?? '');
    $email = strtolower(trim((string) ($claims['email'] ?? '')));
    if ($subject === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException('Google did not return a usable account.');
    }
    $picture = google_picture_url($claims['picture'] ?? null);

    $connecting = (int) ($_SESSION['google_connecting_user'] ?? 0);
    unset($_SESSION['google_connecting_user']);
    /* Connecting from a signed-in session: the live session is the proof, so no password is needed. */
    $signedIn = current_user();
    if ($connecting > 0 && $signedIn !== null && (int) $signedIn['id'] === $connecting) {
        google_attach_identity($connecting, $subject, (string) ($claims['name'] ?? ''), $picture);

        return $connecting;
    }

    $userId = google_link_account($subject, $email, (string) ($claims['name'] ?? ''), $picture, true);
    establish_authenticated_session($userId);

    return $userId;
}

/**
 * The whole callback, for a route: verifies the return and answers the URL to redirect to. A match on
 * an existing password account answers the `google_link_path` page instead.
 */
function google_callback(array $query): string
{
    try {
        google_complete((string) ($query['code'] ?? ''), (string) ($query['state'] ?? ''));
    } catch (GoogleLinkRequired $pause) {
        google_link_pending_store($pause->userId, $pause->subject, $pause->googleEmail,
            $pause->googleName, $pause->googlePicture);

        return (string) um_config('google_link_path');
    }

    return post_login_redirect();
}

/**
 * Find or create the account behind a Google identity. Answers the user id.
 *
 * The subject is the join key; the email is only a fallback for an existing password account.
 * Matching on email first would be wrong both ways: people change their Google address, and
 * addresses get reassigned.
 */
function google_link_account(string $subject, string $email, string $name, string $picture = '',
    bool $emailVerified = false): int
{
    $pdo = um_db();
    $bySubject = $pdo->prepare('SELECT id FROM users WHERE google_sub = :sub');
    $bySubject->execute(['sub' => $subject]);
    $existing = $bySubject->fetch();
    if ($existing) {
        $pdo->prepare('UPDATE users SET google_picture = :picture WHERE id = :id')
            ->execute(['picture' => $picture !== '' ? $picture : null, 'id' => (int) $existing['id']]);

        return (int) $existing['id'];
    }

    $byEmail = $pdo->prepare('SELECT id FROM users WHERE email = :email');
    $byEmail->execute(['email' => $email]);
    $matched = $byEmail->fetch();
    if ($matched) {
        $userId = (int) $matched['id'];
        /* Google's email_verified claim is mailbox proof, the same proof a password reset relies on,
           so a verified match links in place. The risk (a stranger registered this address first) is
           closed by the notice with a 24 hour undo link. If the notice cannot be sent, the link is
           reverted and the visitor is asked for the password instead. */
        if ($emailVerified) {
            $attach = $pdo->prepare('UPDATE users SET google_sub = :sub, google_picture = :picture
                WHERE id = :id AND google_sub IS NULL');
            $attach->execute(['sub' => $subject, 'picture' => $picture !== '' ? $picture : null, 'id' => $userId]);
            if ($attach->rowCount() > 0) {
                if (google_send_link_notice($userId, $subject, $email)) return $userId;

                $pdo->prepare('UPDATE users SET google_sub = NULL, google_picture = NULL
                    WHERE id = :id AND google_sub = :sub')->execute(['id' => $userId, 'sub' => $subject]);
                $pdo->prepare('DELETE FROM google_undo_tokens WHERE user_id = :id AND google_sub = :sub')
                    ->execute(['id' => $userId, 'sub' => $subject]);
            }
        }
        throw new GoogleLinkRequired($userId, $subject, $email, trim($name), $picture);
    }

    /* A new account, with no password. The person can set one later through the reset flow. */
    $pdo->prepare('INSERT INTO users (email, password_hash, name, google_sub, google_picture)
        VALUES (:email, NULL, :name, :sub, :picture)')->execute([
        'email' => $email,
        'name' => trim($name) !== '' ? trim($name) : null,
        'sub' => $subject,
        'picture' => $picture !== '' ? $picture : null,
    ]);

    return (int) $pdo->lastInsertId();
}

/** Mint the undo token and send the notice through the pluggable mailer. False means do not keep the link. */
function google_send_link_notice(int $userId, string $subject, string $email): bool
{
    $token = google_undo_link_token($userId, $subject);
    if ($token === null) return false;
    try {
        $link = um_app_url() . (string) um_config('google_undo_path') . '?token=' . rawurlencode($token);
        $mail = mail_template('google_linked', ['app_name' => um_config('app_name'), 'link' => $link, 'email' => $email]);

        return mail_send($email, $mail['subject'], $mail['body']);
    } catch (Throwable $exception) {
        error_log('user-management: google link notice failed: ' . $exception->getMessage());

        return false;
    }
}

/** Mint a 24 hour undo token for an auto-link. Only the hash is stored. */
function google_undo_link_token(int $userId, string $googleSub): ?string
{
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    try {
        um_db()->prepare('INSERT INTO google_undo_tokens (token_hash, user_id, google_sub, created_at, expires_at)
            VALUES (:hash, :user, :sub, :now, :expires)')
            ->execute(['hash' => hash('sha256', $token), 'user' => $userId, 'sub' => $googleSub,
                'now' => gmdate('Y-m-d H:i:s'), 'expires' => gmdate('Y-m-d H:i:s', time() + 86400)]);
    } catch (PDOException $exception) {
        if ($exception->getCode() !== '23000') throw $exception;

        return null;
    }

    return $token;
}

/** Spend an undo token: detach the Google identity it was minted for. */
function google_consume_undo_token(string $token): array
{
    $pdo = um_db();
    $find = $pdo->prepare('SELECT user_id, google_sub, expires_at FROM google_undo_tokens WHERE token_hash = :hash');
    $find->execute(['hash' => hash('sha256', $token)]);
    $row = $find->fetch();
    if (!$row) return ['ok' => false, 'error' => 'invalid'];
    if ((string) $row['expires_at'] < gmdate('Y-m-d H:i:s')) return ['ok' => false, 'error' => 'expired'];

    $pdo->beginTransaction();
    try {
        $pdo->prepare('DELETE FROM google_undo_tokens WHERE token_hash = :hash')
            ->execute(['hash' => hash('sha256', $token)]);
        $pdo->prepare('UPDATE users SET google_sub = NULL, google_picture = NULL WHERE id = :id AND google_sub = :sub')
            ->execute(['id' => (int) $row['user_id'], 'sub' => (string) $row['google_sub']]);
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }

    return ['ok' => true, 'user_id' => (int) $row['user_id']];
}

/**
 * Google's signing keys, cached on disk for 12 hours. Rejects on fetch failure (no stale fallback).
 * Tests inject keys through the `jwks_override` option.
 */
function google_jwks_load(bool $forceRefresh = false): array
{
    $override = um_config('jwks_override');
    if (is_array($override)) return $override;

    $path = (string) um_config('jwks_cache_path');
    if (!$forceRefresh && is_file($path) && (time() - (int) filemtime($path)) < GOOGLE_JWKS_TTL_SECONDS) {
        $cached = json_decode((string) file_get_contents($path), true);
        if (is_array($cached) && !empty($cached['keys'])) return $cached;
    }
    $handle = curl_init(GOOGLE_JWKS_URL);
    curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_CONNECTTIMEOUT => 5]);
    $body = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);
    $decoded = ($status === 200 && is_string($body)) ? json_decode($body, true) : null;
    if (!is_array($decoded) || empty($decoded['keys'])) {
        error_log('user-management: Google JWKS fetch failed, HTTP ' . $status);
        throw new RuntimeException('Could not fetch Google signing keys.');
    }
    if (!is_dir(dirname($path))) @mkdir(dirname($path), 0700, true);
    @file_put_contents($path, $body, LOCK_EX);

    return $decoded;
}

/**
 * Read and fully verify the claims of a Google ID token. Checks the RS256 signature against the
 * JWKS (one forced refresh on an unknown key id), expiry, issuer, audience and email_verified.
 * Any failure throws; callers never see an unverified claim.
 */
function google_id_token_claims(string $idToken): array
{
    try {
        $payload = \Firebase\JWT\JWT::decode($idToken, \Firebase\JWT\JWK::parseKeySet(google_jwks_load(false), 'RS256'));
    } catch (\Firebase\JWT\ExpiredException) {
        throw new RuntimeException('That sign-in has expired. Please try again.');
    } catch (\Firebase\JWT\SignatureInvalidException) {
        throw new RuntimeException('That sign-in token could not be verified.');
    } catch (\UnexpectedValueException) {
        /* Unknown kid or a header the cached keys cannot cover. One forced refresh, then stop. */
        try {
            $payload = \Firebase\JWT\JWT::decode($idToken, \Firebase\JWT\JWK::parseKeySet(google_jwks_load(true), 'RS256'));
        } catch (\Firebase\JWT\ExpiredException) {
            throw new RuntimeException('That sign-in has expired. Please try again.');
        } catch (\Throwable) {
            throw new RuntimeException('That sign-in token could not be verified.');
        }
    }

    $claims = json_decode((string) json_encode($payload), true);
    if (!is_array($claims)) throw new RuntimeException('Google returned an unreadable sign-in token.');

    if (!in_array((string) ($claims['iss'] ?? ''), ['https://accounts.google.com', 'accounts.google.com'], true)) {
        throw new RuntimeException('That sign-in did not come from Google.');
    }
    $expectedAud = trim((string) getenv('GOOGLE_CLIENT_ID'));
    if ($expectedAud === '' || (string) ($claims['aud'] ?? '') !== $expectedAud) {
        throw new RuntimeException('That sign-in was issued for a different application.');
    }
    /* JWT::decode rejects an expired token; this catches one minted without exp. */
    if (!isset($claims['exp']) || (int) $claims['exp'] < time()) {
        throw new RuntimeException('That sign-in has expired. Please try again.');
    }
    /* Anybody can put any address on a Google profile; an unverified one must never link an account. */
    if (($claims['email_verified'] ?? false) !== true && ($claims['email_verified'] ?? '') !== 'true') {
        throw new RuntimeException('Your Google email address is not verified, so it cannot be used to sign in.');
    }

    return $claims;
}

function google_post(string $url, array $fields): array
{
    $handle = curl_init($url);
    curl_setopt_array($handle, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20,
        CURLOPT_POSTFIELDS => http_build_query($fields)]);
    $body = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    $curlError = curl_error($handle);
    curl_close($handle);

    if ($body === false) throw new RuntimeException('Could not reach Google: ' . $curlError);
    $decoded = json_decode((string) $body, true);
    if (!is_array($decoded) || $status < 200 || $status >= 300) {
        error_log('user-management: Google token exchange failed: HTTP ' . $status);
        throw new RuntimeException('Google refused that sign-in. Please try again.');
    }

    return $decoded;
}
