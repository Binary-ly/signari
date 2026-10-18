<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The headers a console that administers an identity provider should never be
 * served without.
 *
 * Before this the console sent none of them, so it could be framed by any page
 * (clickjacking an operator into disabling a client is a click, not an exploit),
 * a stray <base> tag could re-point every relative URL, and nothing pinned it to
 * HTTPS once reached over HTTPS.
 *
 * # What the policy restricts, and what it does not yet
 *
 * frame-ancestors, base-uri, form-action and object-src: the directives that
 * stop framing, base-tag and form-target injection and plugins, none of which
 * the console uses. script-src and style-src are deliberately absent. Livewire
 * and Alpine evaluate expressions at runtime and Filament emits inline styles,
 * so a script-src without 'unsafe-eval' would break every screen, and one with
 * it would protect nothing worth the appearance of protection. That waits for a
 * nonce-based build.
 *
 * HSTS only on a response that arrived over HTTPS, and without
 * includeSubDomains: the console does not own the rest of the operator's
 * domain, and pinning it would be a decision about hosts this application
 * knows nothing about.
 */
class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        $headers = $response->headers;
        $headers->set('Content-Security-Policy',
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'");
        // The legacy spelling of frame-ancestors, for anything that predates it.
        $headers->set('X-Frame-Options', 'DENY');
        $headers->set('X-Content-Type-Options', 'nosniff');
        $headers->set('Referrer-Policy', 'same-origin');
        $headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
        if ($request->isSecure()) {
            $headers->set('Strict-Transport-Security', 'max-age=31536000');
        }

        return $response;
    }
}
