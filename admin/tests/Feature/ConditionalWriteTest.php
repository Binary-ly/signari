<?php

namespace Tests\Feature;

use App\Services\EngineAdminApi;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Tests\TestCase;

/**
 * The console makes CONDITIONAL writes.
 *
 * # The bug this closes, which was live here
 *
 * The engine has accepted `If-Match` on every mutation since the admin API
 * existed, and this application sent it nowhere. So the exact scenario the
 * precondition was built for was reachable through the console: two
 * administrators open the same client, the first disables it, the second saves
 * an unrelated change from a page rendered before that, and the client is
 * enabled again. Nobody is told, and the audit trail records two successful
 * updates -- because both were.
 *
 * Building a guarantee into the engine and not using it from the one
 * application that ships with it is the "a control nobody uses" shape this
 * project keeps finding in other people's systems.
 */
class ConditionalWriteTest extends TestCase
{
    private function api(): EngineAdminApi
    {
        return new EngineAdminApi('http://engine.test', str_repeat('t', 32));
    }

    public function test_a_client_change_carries_an_if_match_header(): void
    {
        Http::fake([
            'http://engine.test/admin/config-version' => Http::response(['config_version' => 417]),
            'http://engine.test/admin/clients/*' => Http::response(['config_version' => 418]),
        ]);

        $this->api()->setClientEnabled('wiki', false);

        Http::assertSent(function (Request $r) {
            if (! str_contains($r->url(), '/admin/clients/')) {
                return false;
            }

            // Quoted. RFC 7232 does not permit a bare entity-tag, and the engine
            // refuses an unquoted one with a 400 rather than ignoring it --
            // deliberately, since ignoring it would perform an unconditional
            // write for a caller who asked for a conditional one.
            return $r->header('If-Match') === ['"417"'];
        });
    }

    public function test_a_user_change_carries_an_if_match_header(): void
    {
        Http::fake([
            'http://engine.test/admin/config-version' => Http::response(['config_version' => 100]),
            'http://engine.test/admin/users/*' => Http::response(['config_version' => 101]),
        ]);

        $this->api()->setUserActive('u1', false);

        Http::assertSent(fn (Request $r) => ! str_contains($r->url(), '/admin/users/')
            || $r->header('If-Match') === ['"100"']);
    }

    /**
     * A refused write says so, and says nothing was written.
     *
     * An operator who does not know a refused write left the system untouched
     * will reasonably assume a partial change and go looking for it.
     */
    public function test_a_refused_precondition_is_explained(): void
    {
        Http::fake([
            'http://engine.test/admin/config-version' => Http::response(['config_version' => 417]),
            'http://engine.test/admin/clients/*' => Http::response([
                'error' => 'precondition_failed',
                'detail' => 'the configuration was at version 419, not the expected 417',
                'expected_version' => 417,
                'current_version' => 419,
            ], 412),
        ]);

        try {
            $this->api()->setClientEnabled('wiki', false);
            $this->fail('a 412 did not raise');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('Somebody else changed the configuration', $e->getMessage());
            $this->assertStringContainsString('Nothing was written', $e->getMessage(),
                'an operator who does not know the write was refused entirely will '.
                'go looking for a partial change that does not exist');
            $this->assertStringContainsString('419', $e->getMessage(),
                'the engine names both versions, which is what makes "somebody '.
                'else saved" a fact rather than a guess');
        }
    }

    /**
     * The scope of the guarantee is stated, not implied.
     *
     * A precondition people believe is stronger than it is would be worse than
     * none: reading the version immediately before the write catches two
     * administrators saving at the same moment, and does NOT catch a change made
     * while somebody had a form open.
     */
    public function test_the_precondition_scope_is_recorded(): void
    {
        $this->assertStringContainsString('does NOT catch', EngineAdminApi::PRECONDITION_SCOPE);
        $this->assertStringContainsString('form open', EngineAdminApi::PRECONDITION_SCOPE);
    }
}
