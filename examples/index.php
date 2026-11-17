<?php

declare(strict_types=1);

/**
 * Runnable example. Plain, unstyled. Needs no keys for the password flows.
 *
 *   php -S localhost:8000 examples/index.php
 *
 * With no MAIL_FROM set, the reset link is written to the server log (this terminal).
 * The Google button appears only when GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI are set.
 */
require __DIR__ . '/../src/autoload.php';

if (getenv('APP_URL') === false || getenv('APP_URL') === '') putenv('APP_URL=http://localhost:8000');
um_configure([
    'db_path' => getenv('USER_MGMT_DB') ?: sys_get_temp_dir() . '/user-management-example.db',
    'session_path' => sys_get_temp_dir() . '/user-management-example-sessions',
    'email_dns_check' => false,
    'app_name' => 'Example App',
    'default_redirect' => '/dashboard',
]);
/* To use your own mailer: mailer_register(function (string $to, string $subject, string $body): bool { ... }); */

$path = parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);
$post = $_SERVER['REQUEST_METHOD'] === 'POST';
start_session();

function page(string $title, string $body): never
{
    echo '<!doctype html><meta charset="utf-8"><title>' . um_e($title) . '</title><h1>' . um_e($title) . '</h1>'
        . $body . turnstile_script();
    exit;
}
function form(string $action, string $fields, string $submit): string
{
    return '<form method="post" action="' . um_e($action) . '"><input type="hidden" name="csrf" value="'
        . um_e(um_csrf_token()) . '">' . $fields . '<button>' . um_e($submit) . '</button></form>';
}
function field(string $label, string $name, string $type = 'text'): string
{
    return '<p><label>' . um_e($label) . ' <input name="' . um_e($name) . '" type="' . um_e($type) . '"></label></p>';
}
function error(?string $message): string
{
    return $message ? '<p><strong>' . um_e($message) . '</strong></p>' : '';
}
function csrf_or_die(): void
{
    if (!um_check_csrf()) {
        http_response_code(419);
        page('Session expired', '<p>Reload the page and try again.</p>');
    }
}

switch ($path) {
    case '/':
        $user = current_user();
        page('Example App', $user
            ? '<p>Signed in as ' . um_e($user['email']) . '. <a href="/dashboard">Dashboard</a></p>'
            : '<p><a href="/register">Register</a> | <a href="/login">Log in</a></p>');

    case '/register':
        $error = null;
        if ($post) {
            csrf_or_die();
            $result = register_user((string) ($_POST['email'] ?? ''), (string) ($_POST['password'] ?? ''), (string) ($_POST['name'] ?? ''));
            if ($result['ok']) um_redirect(post_login_redirect());
            $error = $result['error'];
        }
        page('Register', error($error) . form('/register', field('Name', 'name') . field('Email', 'email', 'email')
            . field('Password', 'password', 'password') . turnstile_widget(), 'Create account'));

    case '/login':
        $error = null;
        if ($post) {
            csrf_or_die();
            $result = login_user((string) ($_POST['email'] ?? ''), (string) ($_POST['password'] ?? ''));
            if ($result['ok']) um_redirect(post_login_redirect());
            $error = $result['error'];
        }
        $google = google_configured() ? form('/google', '', 'Sign in with Google') : '';
        page('Log in', error($error) . form('/login', field('Email', 'email', 'email') . field('Password', 'password', 'password'), 'Log in')
            . $google . '<p><a href="/forgot">Forgot your password?</a></p>');

    case '/logout':
        if ($post) {
            csrf_or_die();
            logout_user();
        }
        um_redirect('/');

    case '/dashboard':
        $user = require_user();
        page('Dashboard', '<p>Hello ' . um_e($user['name'] ?: $user['email']) . '.</p>' . form('/logout', '', 'Log out'));

    case '/forgot':
        if ($post) {
            csrf_or_die();
            try {
                request_password_reset((string) ($_POST['email'] ?? ''));
            } catch (RuntimeException $e) {
                error_log('example: ' . $e->getMessage());
            }
            /* Identical for known and unknown addresses. */
            page('Check your email', '<p>If an account exists for that address, a reset link is on its way.</p>');
        }
        page('Reset your password', form('/forgot', field('Email', 'email', 'email'), 'Send the reset link'));

    case '/reset':
        password_reset_security_headers();
        $token = (string) ($_GET['token'] ?? '');
        $error = null;
        if ($post) {
            csrf_or_die();
            $result = complete_password_reset($token, (string) ($_POST['password'] ?? ''), (string) ($_POST['confirm_password'] ?? ''));
            if ($result['ok']) um_redirect('/dashboard');
            $error = $result['error'];
        } elseif (password_reset_row($token) === null) {
            page('That link no longer works', '<p><a href="/forgot">Send a new link</a></p>');
        }
        page('Choose a new password', error($error) . form('/reset?token=' . rawurlencode($token),
            field('New password', 'password', 'password') . field('Confirm', 'confirm_password', 'password'), 'Save and sign in'));

    case '/google':
        if (!$post || !google_configured()) um_redirect('/login');
        csrf_or_die();
        google_begin();

    case '/google-callback':
        try {
            um_redirect(google_callback($_GET));
        } catch (RuntimeException $e) {
            page('Google sign-in failed', '<p>' . um_e($e->getMessage()) . '</p><p><a href="/login">Back</a></p>');
        }

    case '/google-link':
        $pending = google_link_pending();
        if ($pending === null) um_redirect('/login');
        $error = null;
        if ($post) {
            csrf_or_die();
            $result = google_link_with_password((string) ($_POST['password'] ?? ''));
            if ($result['ok']) um_redirect(post_login_redirect());
            $error = $result['error'];
        }
        page('Connect Google', '<p>' . um_e($pending['email']) . ' already has an account. Enter its password once to connect them.</p>'
            . error($error) . form('/google-link', field('Password', 'password', 'password'), 'Connect'));

    case '/google-undo':
        $result = google_consume_undo_token((string) ($_GET['token'] ?? ''));
        page('Google sign-in', $result['ok'] ? '<p>The Google connection was removed.</p>' : '<p>That link is invalid or expired.</p>');

    default:
        http_response_code(404);
        page('Not found', '<p><a href="/">Home</a></p>');
}
