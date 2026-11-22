<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * The console loads nothing from another origin.
 *
 * Filament's `->font()` resolves a font name against the Bunny Fonts CDN by
 * default, which would put a third-party request on the console's sign-in page
 * — telling that CDN the IP address of every operator who signs in, and when.
 * The panel therefore uses LocalFontProvider against files vendored into
 * public/fonts/instrument-sans/, and this is what keeps it that way.
 *
 * The sign-in page specifically, because it is the one page served to somebody
 * who is not yet authenticated, and the one whose failure mode is worst: a
 * console that renders badly when a CDN is unreachable is a console that looks
 * broken exactly when somebody is trying to log in and fix something.
 *
 * docs/egress-inventory.md documents the same property for the engine's pages,
 * where it is enforced by TestNoPageLoadsAnythingFromAnotherOrigin.
 */
class NoThirdPartyAssetsTest extends TestCase
{
    public function test_the_sign_in_page_loads_no_asset_from_another_origin(): void
    {
        $this->assertSame(
            [],
            $this->foreignHosts($this->get('/admin/login')->assertOk()->getContent()),
            'The console sign-in page fetches from another origin. Vendor the '.
            'asset into public/ and serve it from here, or record it in '.
            'docs/egress-inventory.md and allow it explicitly.',
        );
    }

    /*
     * Signed in too. Only the sign-in page was looked at, and it has no user menu,
     * so the avatar beside every signed-in screen's menu went to ui-avatars.com
     * with the operator's initials until November 2026.
     */
    public function test_a_signed_in_screen_loads_no_asset_from_another_origin(): void
    {
        $operator = new User;
        $operator->name = 'Ada Lovelace';
        $operator->email = 'egress-'.Str::random(8).'@example.test';
        $operator->password = bcrypt('irrelevant');
        $this->enrol($operator)->save();

        try {
            $html = $this->actingAs($operator)->get('/admin')->assertOk()->getContent();
            $this->assertSame([], $this->foreignHosts($html), 'a signed-in screen fetches from another origin');
            $this->assertStringContainsString('data:image/svg+xml;base64,', $html, 'no avatar was drawn, so this looked at nothing');
        } finally {
            $operator->delete();
        }
    }

    /** @return list<string> */
    private function foreignHosts(string $html): array
    {
        // Only attributes that make the browser fetch something. A page may
        // legitimately display an absolute URL as text; that is content.
        preg_match_all(
            '/(?:<script[^>]+src|<link[^>]+href|<img[^>]+src|@import\s+|url\()\s*=?\s*["\']?([a-z]+:)?\/\/([^"\'\)\s>]+)/i',
            $html,
            $matches,
            PREG_SET_ORDER,
        );

        $ownHost = parse_url(config('app.url'), PHP_URL_HOST) ?: '127.0.0.1';

        $foreign = [];

        foreach ($matches as $m) {
            $host = preg_split('/[\/?:]/', $m[2])[0];

            if ($host === '' || $host === $ownHost || $host === 'localhost') {
                continue;
            }

            $foreign[] = $host;
        }

        return array_values(array_unique($foreign));
    }

    public function test_the_vendored_typeface_is_actually_present(): void
    {
        /*
         * The panel names these files. If they are missing the page still
         * renders — in the fallback stack, looking merely slightly wrong — so
         * nothing else here would notice.
         */
        foreach ([
            'fonts/instrument-sans/index.css',
            'fonts/instrument-sans/instrument-sans-latin-wght-normal.woff2',
            'fonts/instrument-sans/instrument-sans-latin-ext-wght-normal.woff2',
            'fonts/instrument-sans/LICENSE.txt',
        ] as $path) {
            $this->assertFileExists(
                public_path($path),
                "Missing {$path}. The panel points at it, and a missing font ".
                'file degrades silently to the fallback stack.',
            );
        }
    }
}
