<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';

/**
 * Cloudflare Turnstile bot check. Entirely optional: with TURNSTILE_SECRET unset, every function
 * here is inert and registration is not gated. Set TURNSTILE_SITE_KEY and TURNSTILE_SECRET to enable.
 */
function turnstile_configured(): bool
{
    return trim((string) getenv('TURNSTILE_SITE_KEY')) !== '' && trim((string) getenv('TURNSTILE_SECRET')) !== '';
}

/** Widget markup, or '' when off. */
function turnstile_widget(): string
{
    if (!turnstile_configured()) return '';

    return '<div class="cf-turnstile" data-sitekey="' . um_e(trim((string) getenv('TURNSTILE_SITE_KEY')))
        . '" data-appearance="interaction-only"></div>';
}

/** The loader script, once per page, or '' when off. */
function turnstile_script(): string
{
    return turnstile_configured()
        ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : '';
}

/**
 * Check the widget's token from $_POST. Throws when the visitor does not pass. A verifier outage
 * refuses the request: treating it as a pass would turn an outage into a bypass.
 */
function turnstile_check(): void
{
    if (!turnstile_configured()) return;

    $token = (string) ($_POST['cf-turnstile-response'] ?? '');
    if ($token === '') throw new RuntimeException('Please complete the "not a robot" check and try again.');

    $handle = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($handle, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_POSTFIELDS => http_build_query([
            'secret' => trim((string) getenv('TURNSTILE_SECRET')),
            'response' => $token,
            'remoteip' => um_client_ip(),
        ]),
    ]);
    $body = curl_exec($handle);
    curl_close($handle);

    $result = $body === false ? null : json_decode((string) $body, true);
    if (!is_array($result)) {
        error_log('user-management: Turnstile unavailable, refusing the request.');
        throw new RuntimeException('The bot check is temporarily unavailable. Please try again.');
    }
    if (($result['success'] ?? false) !== true) {
        throw new RuntimeException('That "not a robot" check did not pass. Please try again.');
    }
}
