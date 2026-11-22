<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Settings are read from the environment in config/ and nowhere else. Once
 * `php artisan config:cache` has run, Laravel stops loading .env and env()
 * returns null, so a read in app/ falls back to its default: the Admin API's
 * address, token and client certificate were read that way, and a console
 * with cached config would have talked to http://127.0.0.1:8090 with no
 * certificate. Found because CI, which copies .env.example, failed five
 * sign-in tests that had passed against a developer's .env.
 */
class NoEnvOutsideConfigTest extends TestCase
{
    public function test_nothing_outside_config_reads_the_environment(): void
    {
        $app = dirname(__DIR__, 2).'/app';
        $found = [];
        $files = 0;
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($app)) as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            $files++;
            // Tokens rather than text, so a comment or a string that mentions env() is not a read.
            $tokens = array_values(array_filter(
                token_get_all((string) file_get_contents($file->getPathname())),
                fn ($t) => ! is_array($t) || ! in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
            ));
            foreach ($tokens as $i => $t) {
                $called = is_array($t) && strtolower($t[1]) === 'env' && ($tokens[$i + 1] ?? null) === '(';
                $method = is_array($tokens[$i - 1] ?? null) && in_array($tokens[$i - 1][0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NULLSAFE_OBJECT_OPERATOR, T_FUNCTION], true);
                if ($called && ! $method) {
                    $found[] = substr($file->getPathname(), strlen($app) + 1).':'.$t[2];
                }
            }
        }

        $this->assertGreaterThan(50, $files, 'the scan found almost nothing under app/, so it has stopped looking');
        $this->assertSame([], $found, "env() outside config/, which returns null once config is cached:\n".implode("\n", $found));
    }
}
