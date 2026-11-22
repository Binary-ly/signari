<?php

namespace App\Support;

use RuntimeException;

/** The OpenID Connect client asking for the browser to be sent to $url. */
class RedirectTo extends RuntimeException
{
    public function __construct(public readonly string $url)
    {
        parent::__construct('redirect to the authorization endpoint');
    }
}
