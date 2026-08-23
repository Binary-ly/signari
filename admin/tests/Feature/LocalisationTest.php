<?php

namespace Tests\Feature;

use Tests\TestCase;

/**
 * The console answers in the operator's language.
 *
 * Two halves have to agree for this to work, and they fail differently:
 * Filament ships catalogues for its own chrome, and lang/ carries the words
 * that are ours -- the domain terms an identity console is mostly made of.
 * Getting only one produces a page half in each language, which is the state
 * this file exists to prevent.
 */
class LocalisationTest extends TestCase
{
    public function test_the_console_answers_in_the_language_the_browser_asked_for(): void
    {
        $html = $this->withHeaders(['Accept-Language' => 'ar'])
            ->get('/admin/login')->assertOk()->getContent();

        $this->assertStringContainsString('lang="ar"', $html,
            'The page did not declare Arabic, so a screen reader announces it as English.');

        // Right-to-left is not decorative. Without dir the whole layout is
        // mirrored wrongly: labels detach from their fields and punctuation
        // lands at the wrong end of every sentence.
        $this->assertStringContainsString('dir="rtl"', $html,
            'An Arabic page rendered left-to-right.');
    }

    public function test_english_is_the_default_when_nothing_is_asked_for(): void
    {
        $html = $this->get('/admin/login')->assertOk()->getContent();

        $this->assertStringContainsString('lang="en"', $html);
        $this->assertStringContainsString('dir="ltr"', $html);
    }

    public function test_a_region_subtag_resolves_to_the_base_language(): void
    {
        // ar-EG has no catalogue of its own. Falling through to English because
        // the file is named ar.json would be the wrong answer, and is the
        // mistake a naive exact-match lookup makes.
        $html = $this->withHeaders(['Accept-Language' => 'ar-EG,ar;q=0.9'])
            ->get('/admin/login')->assertOk()->getContent();

        $this->assertStringContainsString('lang="ar"', $html);
    }

    public function test_a_malformed_header_does_not_break_the_sign_in_page(): void
    {
        // The header is a stranger's input reaching the one page somebody opens
        // when they are trying to find out what is broken.
        foreach (['', '*', ';;;q=', 'ar;q=notanumber', str_repeat('x', 500)] as $header) {
            $this->withHeaders(['Accept-Language' => $header])
                ->get('/admin/login')
                ->assertOk();
        }
    }

    public function test_our_own_words_are_translated_and_not_just_filaments(): void
    {
        // Filament translates "Sign in" from its own catalogue. The domain
        // terms are ours, and a console where only the framework's chrome is
        // translated is the failure this test names.
        $translated = __('Configuration', [], 'ar');

        $this->assertNotSame('Configuration', $translated,
            'lang/ar.json does not translate a term the navigation uses, so the '.
            'sidebar stays English while the buttons around it do not.');
    }

    public function test_the_arabic_catalogue_covers_every_string_the_console_uses(): void
    {
        $used = $this->stringsPassedThroughTranslation();
        $this->assertGreaterThan(100, count($used),
            'Almost nothing was found; the scan is broken, not the catalogue.');

        $have = json_decode((string) file_get_contents(lang_path('ar.json')), true);
        $this->assertIsArray($have, 'lang/ar.json is not valid JSON.');

        $missing = array_values(array_diff($used, array_keys($have)));
        sort($missing);

        $this->assertSame([], $missing,
            "lang/ar.json is missing ".count($missing)." string(s). A partial ".
            "translation still renders -- half in each language -- which reads ".
            "as a broken page rather than an untranslated one.");
    }

    public function test_the_arabic_catalogue_has_no_entries_nothing_uses(): void
    {
        $used = $this->stringsPassedThroughTranslation();
        $have = array_keys((array) json_decode((string) file_get_contents(lang_path('ar.json')), true));

        // Plural forms carry their own pipe-separated syntax and are matched by
        // trans_choice rather than __(), so they are not in the scanned set.
        $orphans = array_values(array_filter(
            array_diff($have, $used),
            fn (string $key): bool => ! str_contains($key, '|'),
        ));
        sort($orphans);

        $this->assertSame([], $orphans,
            'lang/ar.json carries strings nothing renders. Either a label was '.
            'reworded and the translation left behind, or the key is a typo.');
    }

    /**
     * Every literal passed to __() anywhere in the application.
     *
     * Reading source rather than maintaining a list, so the check cannot drift
     * from what the console actually asks for.
     *
     * @return array<int, string>
     */
    private function stringsPassedThroughTranslation(): array
    {
        $found = [];

        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(app_path(), \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($files as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $src = (string) file_get_contents($file->getPathname());
            if (preg_match_all("/__\('((?:[^'\\\\]|\\\\.)*)'/", $src, $m)) {
                foreach ($m[1] as $literal) {
                    $found[] = str_replace("\\'", "'", $literal);
                }
            }
        }

        return array_values(array_unique($found));
    }
}
