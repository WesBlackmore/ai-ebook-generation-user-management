<?php

declare(strict_types=1);

require_once __DIR__ . '/db.php';

/**
 * The one place the package sends email, and the one place its wording lives.
 *
 * Register your own transport once at boot:
 *
 *     mailer_register(function (string $toEmail, string $subject, string $body): bool { ... });
 *
 * Return false (or throw) to report a failed delivery. Anything else counts as sent.
 */
function mailer_register(?callable $send): void
{
    $GLOBALS['um_mailer'] = $send;
}

function mail_send(string $toEmail, string $subject, string $body): bool
{
    $send = $GLOBALS['um_mailer'] ?? null;
    try {
        $result = is_callable($send) ? $send($toEmail, $subject, $body) : mail_default_send($toEmail, $subject, $body);
    } catch (Throwable $exception) {
        error_log('user-management: mail send failed: ' . $exception->getMessage());

        return false;
    }

    return $result !== false;
}

/**
 * The default transport. With MAIL_FROM set it uses PHP's mail(). Without it nothing is sent and
 * the whole message, reset link included, goes to error_log so local development needs no SMTP.
 */
function mail_default_send(string $toEmail, string $subject, string $body): bool
{
    $from = trim((string) getenv('MAIL_FROM'));
    if ($from === '' || !filter_var($from, FILTER_VALIDATE_EMAIL)) {
        error_log("user-management: no MAIL_FROM set, not sending. To: $toEmail | Subject: $subject\n$body");

        return true;
    }
    if (!filter_var($toEmail, FILTER_VALIDATE_EMAIL)) return false;

    return mail($toEmail, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, [
        'From' => $from,
        'MIME-Version' => '1.0',
        'Content-Type' => 'text/plain; charset=UTF-8',
    ]);
}

/**
 * Build an email: ['subject' => ..., 'body' => ...]. Override any template through
 * `um_configure(['templates' => ['password_reset' => fn(array $ctx): array => [...]]])`.
 * $ctx carries `app_name`, `link`, and for `google_linked` also `email`.
 */
function mail_template(string $name, array $ctx): array
{
    $override = (um_config('templates') ?? [])[$name] ?? null;
    if (is_callable($override)) return $override($ctx);

    $app = (string) $ctx['app_name'];
    if ($name === 'password_reset') {
        return [
            'subject' => "Reset your $app password",
            'body' => "Someone asked to reset the password for your $app account.\n\n"
                . "Choose a new password here (the link works once and expires in an hour):\n"
                . $ctx['link'] . "\n\nIf this was not you, ignore this message. Nothing has changed.\n",
        ];
    }
    if ($name === 'google_linked') {
        return [
            'subject' => "Google sign-in was connected to your $app account",
            'body' => "A Google account was just connected to your $app account ({$ctx['email']}).\n\n"
                . "If that was you, nothing to do. If it was not, undo it within 24 hours:\n"
                . $ctx['link'] . "\n",
        ];
    }
    throw new InvalidArgumentException('Unknown email template: ' . $name);
}
