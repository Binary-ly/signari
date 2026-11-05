<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Vite;
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
 * # Scripts: a nonce, so an injected inline script does not run
 *
 * Every response gets a nonce of its own (Vite::useCspNonce), and script-src
 * allows an inline script only when it carries that nonce. Livewire puts it on its
 * own tags (FrontendAssets::nonce). Filament writes seven inline scripts in three
 * views with no way to give them one, so those views are copied under
 * resources/views/vendor/ with the nonce added and nothing else changed;
 * FilamentViewCopiesTest fails when Filament's originals change and the copies
 * have not been brought into step. Filament's six other inline scripts are
 * Livewire @script blocks, which are never in the page: Livewire evaluates them.
 *
 * What stays is 'unsafe-eval'. The Alpine that Livewire 3 bundles compiles every
 * expression, and those @script blocks, with `new Function`; without it every
 * screen breaks. An injected attribute that Alpine reads as an expression is the
 * way in that leaves, which is why a nonce does not end the matter.
 *
 * Styles keep 'unsafe-inline': Filament writes style="" attributes throughout,
 * and a nonce cannot cover an attribute.
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
        // Before the response is rendered, so every tag written for it carries the nonce.
        $nonce = Vite::useCspNonce();

        $response = $next($request);

        $headers = $response->headers;
        $headers->set('Content-Security-Policy', implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'nonce-{$nonce}' 'unsafe-eval'",
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
