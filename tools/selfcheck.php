<?php

declare(strict_types=1);

/** Assert-based selfcheck. No framework. Exits non-zero on any failure. Run: php tools/selfcheck.php */

/* Buffer all output so PHP sessions can start under the CLI; results print at the end. */
ob_start();
$work = sys_get_temp_dir() . '/um-selfcheck-' . bin2hex(random_bytes(4));
mkdir($work, 0700, true);

require __DIR__ . '/../src/autoload.php';
um_configure([
    'db_path' => $work . '/users.db',
    'session_path' => $work . '/sessions',
    'email_dns_check' => false,
    'app_name' => 'Selfcheck App',
]);
putenv('APP_URL=http://localhost:8000');
foreach (['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI', 'TURNSTILE_SECRET', 'TURNSTILE_SITE_KEY', 'MAIL_FROM'] as $name) {
    putenv($name);
}

$results = [];
$failed = 0;
function check(bool $condition, string $label): void
{
    global $results, $failed;
    $results[] = ($condition ? 'ok    ' : 'FAIL  ') . $label;
    if (!$condition) $failed++;
}
function throws(callable $fn): ?string
{
    try {
        $fn();
    } catch (Throwable $e) {
        return $e->getMessage();
    }

    return null;
}
function user_row(string $email): array
{
    $s = um_db()->prepare('SELECT * FROM users WHERE email = ?');
    $s->execute([$email]);

    return (array) $s->fetch();
}

/* Captured mail, standing in for the host's transport. */
$outbox = [];
mailer_register(function (string $to, string $subject, string $body) use (&$outbox): bool {
    $outbox[] = compact('to', 'subject', 'body');

    return true;
});
function last_token(array $outbox): string
{
    preg_match('/token=([0-9a-f]{64})/', end($outbox)['body'], $m);

    return $m[1] ?? '';
}

/* Schema */
$tables = um_db()->query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")->fetchAll(PDO::FETCH_COLUMN);
check($tables === ['google_undo_tokens', 'password_resets', 'users'], 'schema bootstraps exactly 3 tables');
$cols = array_column(um_db()->query('PRAGMA table_info(users)')->fetchAll(), null, 'name');
check((int) $cols['password_hash']['notnull'] === 0, 'users.password_hash is nullable');
check(array_keys($cols) === ['id', 'email', 'password_hash', 'name', 'google_sub', 'google_picture', 'session_version', 'created_at'], 'users has only the generic columns');

/* Email validation */
check(validate_email_address('not-an-email') !== null, 'email validation rejects junk');
check(validate_email_address('a@') !== null && validate_email_address('@b.test') !== null, 'email validation rejects fragments');
check(validate_email_address('person@example.com') === null, 'email validation accepts a normal address');

/* Register, login, logout, wrong password, duplicate */
$r = register_user('alice@example.com', 'correct horse battery');
check($r['ok'] === true && current_user()['email'] === 'alice@example.com', 'register creates an account and signs in');
check(user_row('alice@example.com')['password_hash'] !== 'correct horse battery', 'password is stored hashed');
logout_user();
check(current_user() === null, 'logout ends the session');
check(login_user('alice@example.com', 'wrong password!')['ok'] === false, 'wrong password fails');
check(login_user('nobody@example.com', 'whatever123')['ok'] === false, 'unknown email fails');
check(login_user('ALICE@example.com ', 'correct horse battery')['ok'] === true && current_user() !== null, 'login succeeds after register');
check(register_user('alice@example.com', 'another password')['ok'] === false, 'duplicate email rejected');
check(register_user('bob@example.com', 'short')['ok'] === false, 'short password rejected');
$oldId = session_id();
login_user('alice@example.com', 'correct horse battery');
check(session_id() !== $oldId, 'login regenerates the session id (fixation defence)');
check(auth_return_url_allowed('/dashboard?x=1') && !auth_return_url_allowed('//evil.test/x')
    && !auth_return_url_allowed('https://evil.test/x') && !auth_return_url_allowed('javascript:alert(1)')
    && !auth_return_url_allowed('/\\evil.test'), 'return-url allowlist blocks open redirects');
um_configure(['allowed_return_hosts' => ['app.test']]);
check(auth_return_url_allowed('https://app.test/x') && !auth_return_url_allowed('https://evil.test/x'), 'return-url hosts come from config');

/* Password reset */
$userId = (int) user_row('alice@example.com')['id'];
$outbox = [];
request_password_reset('alice@example.com');
$token = last_token($outbox);
check(count($outbox) === 1 && $outbox[0]['to'] === 'alice@example.com' && strlen($token) === 64, 'reset mail goes through the registered mailer');
check(str_contains($outbox[0]['subject'], 'Selfcheck App'), 'reset email template uses the configured app name');
$rows = um_db()->query('SELECT * FROM password_resets')->fetchAll();
check(count($rows) === 1 && $rows[0]['token_hash'] === hash('sha256', $token) && !in_array($token, $rows[0], true), 'reset token is hashed at rest');
$known = $outbox;
$outbox = [];
request_password_reset('ghost@example.com');
check(count($outbox) === 0 && count(um_db()->query('SELECT 1 FROM password_resets')->fetchAll()) === 1, 'unknown email: same silent result, nothing stored or sent');
check(throws(fn() => request_password_reset('ghost@example.com')) === null, 'forgot-password gives the same response (no error, no value) for an unknown email');

$oldSession = $_SESSION;
check(current_user() !== null, 'session valid before the reset');
$done = complete_password_reset($token, 'brand new password', 'brand new password');
check($done['ok'] === true, 'reset with a valid token succeeds');
check(complete_password_reset($token, 'yet another one', 'yet another one')['ok'] === false, 'reset token is single-use');
check(password_reset_row($token) === null, 'a spent token has no live row');
$_SESSION = $oldSession;
check(current_user() === null, 'password change bumps session_version and invalidates the old session');
check(login_user('alice@example.com', 'brand new password')['ok'] === true
    && login_user('alice@example.com', 'correct horse battery')['ok'] === false, 'new password works, old one does not');

$outbox = [];
request_password_reset('alice@example.com');
$expiring = last_token($outbox);
check(password_reset_row($expiring) !== null, 'fresh token is live');
um_db()->prepare('UPDATE password_resets SET expires_at = ? WHERE token_hash = ?')
    ->execute([gmdate('Y-m-d H:i:s', time() - 5), hash('sha256', $expiring)]);
check(password_reset_row($expiring) === null && complete_password_reset($expiring, 'whatever123', 'whatever123')['ok'] === false, 'reset token expires');
$outbox = [];
request_password_reset('alice@example.com');
$first = last_token($outbox);
request_password_reset('alice@example.com');
check(password_reset_row($first) === null, 'a newer link retires the older one');

/* Google */
check(google_configured() === false, 'google_configured() is false when env is unset');
putenv('GOOGLE_CLIENT_ID=test-client-id');
check(google_configured() === false, 'google_configured() needs secret and redirect URI too');
putenv('GOOGLE_CLIENT_SECRET=dummy-test-secret');
putenv('GOOGLE_REDIRECT_URI=http://localhost:8000/google-callback');
check(google_configured() === true, 'google_configured() is true when all three are set');

$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$b64 = fn(string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
$details = openssl_pkey_get_details($key);
um_configure(['jwks_override' => ['keys' => [[
    'kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-kid',
    'n' => $b64($details['rsa']['n']), 'e' => $b64($details['rsa']['e']),
]]]]);
$claims = fn(array $over = []): array => array_merge([
    'iss' => 'https://accounts.google.com', 'aud' => 'test-client-id', 'sub' => 'sub-123',
    'email' => 'gina@example.com', 'email_verified' => true, 'name' => 'Gina', 'exp' => time() + 600, 'iat' => time(),
], $over);
$mint = fn(array $payload, $signWith = null): string => \Firebase\JWT\JWT::encode($payload, $signWith ?? $key, 'RS256', 'test-kid');

check(google_id_token_claims($mint($claims()))['sub'] === 'sub-123', 'verifier accepts a correctly signed token (control)');
check(throws(fn() => google_id_token_claims($mint($claims(), $other))) !== null, 'verifier rejects a bad signature');
check(throws(fn() => google_id_token_claims($mint($claims(['iss' => 'https://evil.test'])))) !== null, 'verifier rejects a bad issuer');
check(throws(fn() => google_id_token_claims($mint($claims(['aud' => 'someone-else'])))) !== null, 'verifier rejects a bad audience');
check(throws(fn() => google_id_token_claims($mint($claims(['exp' => time() - 600])))) !== null, 'verifier rejects an expired token');
check(throws(fn() => google_id_token_claims($mint($claims(['email_verified' => false])))) !== null, 'verifier rejects an unverified email');
check(throws(fn() => google_id_token_claims('not.a.jwt')) !== null, 'verifier rejects garbage');

/* Google account create and link (mail is captured) */
$gid = google_link_account('sub-123', 'gina@example.com', 'Gina', '', true);
$gina = user_row('gina@example.com');
check($gid === (int) $gina['id'] && $gina['password_hash'] === null && $gina['google_sub'] === 'sub-123', 'google creates a password-less account');
check(login_user('gina@example.com', '')['ok'] === false && login_user('gina@example.com', 'anything123')['ok'] === false, 'google-only account cannot password-login');
check(google_link_account('sub-123', 'gina@example.com', 'Gina') === $gid, 'same google subject finds the same account');
$outbox = [];
$aliceId = google_link_account('sub-alice', 'alice@example.com', 'Alice', '', true);
check($aliceId === $userId && user_row('alice@example.com')['google_sub'] === 'sub-alice' && count($outbox) === 1, 'verified email match links in place and sends a notice');
preg_match('/token=([A-Za-z0-9_-]+)/', $outbox[0]['body'], $m);
check(google_consume_undo_token($m[1])['ok'] === true && user_row('alice@example.com')['google_sub'] === null, 'undo token detaches the identity');
check(google_consume_undo_token($m[1])['ok'] === false, 'undo token is single-use');
mailer_register(fn() => false);
$linkErr = throws(fn() => google_link_account('sub-alice2', 'alice@example.com', 'Alice', '', true));
check($linkErr !== null && user_row('alice@example.com')['google_sub'] === null, 'failed notice reverts the auto-link and asks for the password');

/* Optional Turnstile is inert when unset */
check(turnstile_widget() === '' && turnstile_script() === '', 'turnstile is inert when TURNSTILE_SECRET is unset');

/* Cleanup */
um_db()->exec('PRAGMA wal_checkpoint(TRUNCATE)');
exec('rm -rf ' . escapeshellarg($work));
ob_end_clean();
echo implode("\n", $results), "\n", $failed === 0 ? 'ALL ' . count($results) . " CHECKS PASSED\n" : "$failed FAILED\n";
exit($failed === 0 ? 0 : 1);
