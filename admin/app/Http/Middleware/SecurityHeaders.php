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
 * the console uses.
 *
 * Everything else loads from here and nowhere else, default-src 'self' with
 * data: images for the avatar. The console has nothing to fetch from anybody
 * else, and the two times it did, a font CDN and an avatar service, were
 * defaults of the framework that told a third party who was administering this
 * identity provider and when. A third is now refused by the browser rather than
 * found by reading. connect-src 'self' also means a script that does get to run
 * cannot post what it read to another origin.
 *
 * What it does not do is stop a script injected into the page. Filament 4 writes
 * thirteen inline scripts with no way to give them a nonce, and the Alpine that
 * Livewire 3 bundles compiles every expression with `new Function`, so script-src
 * keeps 'unsafe-inline' and 'unsafe-eval'. Without either, every screen breaks;
 * the nonce would need Filament's own views copied here and kept in step with
 * every release of it.
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
        $headers->set('Content-Security-Policy', implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'",
        ]));
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
