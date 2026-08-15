<?php

namespace Tests\Feature;

use App\Services\EngineAdminApi;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Tests\TestCase;

/**
 * How the console reports an admin token that is not permitted to do something.
 *
 * The engine's tokens are now scoped and organisation-bound, so 403 is a normal
 * answer rather than a bug — and it carries a `detail` naming the missing scope
 * on purpose. Before this, 403 fell through to the generic branch and an operator
 * saw a raw JSON dump with a status code, which buries the one sentence that
 * tells them what to change.
 *
 * The engine end is covered by internal/adminapi against a real database. This
 * covers the half nothing tested: whether the console passes the explanation on.
 */
class AdminTokenRefusalTest extends TestCase
{
    private function api(): EngineAdminApi
    {
        return new EngineAdminApi('http://engine.test', str_repeat('t', 32), 5);
    }

    public function test_a_missing_scope_is_reported_in_words(): void
    {
        Http::fake([
            'engine.test/*' => Http::response([
                'error' => 'insufficient_scope',
                'detail' => 'this token does not hold users:write',
            ], 403),
        ]);

        try {
            $this->api()->createUser('org', 'a@b.test', null);
            $this->fail('a 403 did not raise');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString(
                'users:write',
                $e->getMessage(),
                'the operator is not told which scope is missing, which is the only '.
                'part of the answer they can act on'
            );
            $this->assertStringNotContainsString('403', $e->getMessage());
        }
    }

    public function test_the_organisation_boundary_is_reported_in_words(): void
    {
        Http::fake([
            'engine.test/*' => Http::response([
                'error' => 'outside_token_organisation',
                'detail' => 'this token may only act on organisation 1111',
            ], 403),
        ]);

        try {
            $this->api()->createUser('other', 'a@b.test', null);
            $this->fail('a cross-organisation 403 did not raise');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('only act on organisation', $e->getMessage());
        }
    }

    /**
     * A revoked token now looks exactly like a wrong one, so the message has to
     * point at where the answer actually is rather than implying it is mistyped.
     */
    public function test_a_rejected_token_points_at_the_token_list(): void
    {
        Http::fake(['engine.test/*' => Http::response(['error' => 'unauthorized'], 401)]);

        try {
            $this->api()->createUser('org', 'a@b.test', null);
            $this->fail('a 401 did not raise');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('admin-token list', $e->getMessage());
        }
    }
}
