<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Answer the console in the operator's language.
 *
 * The engine negotiates from OIDC's `ui_locales` and then Accept-Language,
 * because a relying party can say what language the person was already using.
 * Nothing sends a console request on somebody's behalf, so there is no
 * equivalent here: the browser's Accept-Language is the whole signal.
 *
 * What is deliberately NOT here is a language switcher writing to a cookie.
 * A preference the operator sets belongs on their account, and until there is a
 * column for it, honouring the browser is the honest behaviour rather than
 * inventing a third place for state to live.
 */
class NegotiateLocale
{
    public function handle(Request $request, Closure $next): Response
    {
        if ($locale = $this->preferred($request)) {
            app()->setLocale($locale);
        }

        return $next($request);
    }

    /**
     * The best available match, or null to leave the default alone.
     *
     * Availability is decided by what is on disk -- lang/<tag>.json for our own
     * strings, and Filament's own catalogue for its chrome -- so adding a
     * language is adding a file, with nothing to register.
     */
    private function preferred(Request $request): ?string
    {
        foreach ($this->acceptable($request) as $tag) {
            // Region subtags resolve to the base language: somebody asking for
            // ar-EG should get Arabic rather than falling through to English
            // because the file happens to be named ar.json.
            foreach ([$tag, explode('-', $tag)[0]] as $candidate) {
                if ($this->available($candidate)) {
                    return $candidate;
                }
            }
        }

        return null;
    }

    /**
     * Accept-Language, most preferred first.
     *
     * Parsed here rather than trusted: the header is a stranger's input, and a
     * malformed one must produce an English page, not an exception on the
     * console somebody opened to find out what is broken.
     *
     * @return array<int, string>
     */
    private function acceptable(Request $request): array
    {
        $header = (string) $request->headers->get('Accept-Language', '');
        if ($header === '') {
            return [];
        }

        $weighted = [];
        foreach (explode(',', $header) as $part) {
            $bits = explode(';', trim($part));
            $tag = trim($bits[0]);
            if ($tag === '' || $tag === '*' || ! preg_match('/^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$/', $tag)) {
                continue;
            }
            $q = 1.0;
            foreach (array_slice($bits, 1) as $param) {
                if (str_starts_with(trim($param), 'q=')) {
                    $q = (float) substr(trim($param), 2);
                }
            }
            $weighted[] = ['tag' => $tag, 'q' => $q];
        }

        // Stable sort on quality, so equal weights keep the header's own order.
        usort($weighted, fn (array $a, array $b): int => $b['q'] <=> $a['q']);

        return array_column($weighted, 'tag');
    }

    private function available(string $tag): bool
    {
        return is_file(lang_path($tag.'.json')) || is_dir(lang_path($tag));
    }
}
