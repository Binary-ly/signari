<?php

// Where this application signs people in. Read from the environment, so `php artisan
// config:cache` keeps working.
return [
    'issuer' => env('SIGNARI_ISSUER'),
    'client_id' => env('SIGNARI_CLIENT_ID'),
    // Empty for a public client, whose only proof is PKCE.
    'client_secret' => env('SIGNARI_CLIENT_SECRET'),
    'redirect_uri' => env('SIGNARI_REDIRECT_URI'),
    // A certificate to trust for the issuer, for development only.
    'ca_file' => env('SIGNARI_CA_FILE'),
];
