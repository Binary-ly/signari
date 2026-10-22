<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'key' => env('POSTMARK_API_KEY'),
    ],

    'resend' => [
        'key' => env('RESEND_API_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    /*
     * Signing in to the console through Signari itself (6.06): the issuer, and
     * the console's own client there, which an owner designates for the Admin
     * API (`signari client set-admin-api`). Unset, the console signs in with
     * its local accounts as before; set, a password admits only a break-glass
     * account. See docs/console-configuration.md.
     */
    'signari' => [
        'issuer' => env('SIGNARI_ISSUER'),
        'client_id' => env('SIGNARI_CONSOLE_CLIENT_ID'),
        'client_secret' => env('SIGNARI_CONSOLE_CLIENT_SECRET'),
        'redirect' => env('SIGNARI_CONSOLE_REDIRECT_URI'),
    ],

];
