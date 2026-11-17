<?php

declare(strict_types=1);

/**
 * Plain require entry point: `require 'path/to/src/autoload.php';`
 * Also loads Composer's autoloader (for firebase/php-jwt) when it has not been loaded already.
 */
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/mailer.php';
require_once __DIR__ . '/turnstile.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/password_reset.php';
require_once __DIR__ . '/google_auth.php';

if (!class_exists(\Firebase\JWT\JWT::class)) {
    foreach ([dirname(__DIR__) . '/vendor/autoload.php', dirname(__DIR__, 3) . '/autoload.php'] as $composer) {
        if (is_file($composer)) {
            require_once $composer;
            break;
        }
    }
}
