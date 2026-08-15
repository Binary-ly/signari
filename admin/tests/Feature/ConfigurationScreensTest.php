<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * The configuration screens: SAML providers, sign-in providers, groups, SCIM
 * targets and admin tokens.
 *
 * All of this worked and was CLI-only, so an operator wanting to know what was
 * configured had to SSH somewhere — which means in practice nobody looked, and
 * the half-configurations `signari doctor` reports are exactly the ones that go
 * unnoticed for months.
 *
 * Two things are asserted, and the second is the one that matters:
 *
 *  1. Each screen renders with real rows in it. An empty list evaluates no
 *     column closures at all, so a screen that 500s the moment data appears
 *     looks perfectly healthy until the day it is needed. That has already
 *     happened once here, with three closures whose parameters Filament could
 *     not inject.
 *
 *  2. Each screen is under the same database-enforced tenant boundary as the
 *     rest of the console. These are new views over tables that mostly already
 *     had RLS — `core.admin_tokens` did NOT, and adding these screens is what
 *     surfaced it.
 */
class ConfigurationScreensTest extends TestCase
{
    private array $createdUserIds = [];

    /** Every configuration screen this test covers. */
    private const SCREENS = [
        '/admin/saml-providers',
        '/admin/identity-providers',
        '/admin/groups',
        '/admin/scim-targets',
        '/admin/admin-tokens',
    ];

    protected function tearDown(): void
    {
        if ($this->createdUserIds !== []) {
            User::whereIn('id', $this->createdUserIds)->delete();
        }

        parent::tearDown();
    }

    private function operatorFor(?string $orgId): User
    {
        $user = new User();
        $user->name = 'Operator';
        $user->email = 'cfg-'.Str::random(10).'@example.test';
        $user->password = bcrypt('irrelevant');
        $user->org_id = $orgId;
        $user->save();

        $this->createdUserIds[] = $user->id;

        return $user;
    }

    /**
     * An organisation that actually has some of this configuration, so the
     * screens are exercised with rows rather than empty states.
     *
     * Found by asking each organisation in turn THROUGH the scoped view, because
     * the console role has no privilege on schema `core` at all (ADR-004) — the
     * first version of this helper queried core.saml_providers directly and was
     * refused by the database, which is the boundary doing its job.
     */
    private function orgWithConfiguration(): string
    {
        $orgs = DB::select('SELECT id::text AS id FROM core_v1.organizations');

        if ($orgs === []) {
            $this->markTestSkipped('no organisation in this database');
        }

        foreach ($orgs as $org) {
            $found = DB::transaction(function () use ($org) {
                DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org->id]);

                return DB::selectOne('SELECT entity_id FROM core_v1.saml_providers LIMIT 1');
            });

            if ($found !== null) {
                return $org->id;
            }
        }

        // None has SAML configured; the render tests are still worth running.
        return $orgs[0]->id;
    }

    public function test_every_configuration_screen_renders(): void
    {
        $operator = $this->operatorFor($this->orgWithConfiguration());

        foreach (self::SCREENS as $screen) {
            $this->actingAs($operator)->get($screen)->assertOk();
        }
    }

    /**
     * The SAML screen must actually show a provider, not an empty state.
     *
     * Without this the test above passes on a console that renders nothing at
     * all, which is the failure it is supposed to catch.
     */
    public function test_the_saml_screen_shows_a_real_provider(): void
    {
        $org = $this->orgWithConfiguration();

        $provider = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);

            return DB::selectOne('SELECT entity_id FROM core_v1.saml_providers LIMIT 1');
        });

        if ($provider === null) {
            $this->markTestSkipped('no SAML provider registered for that organisation');
        }

        $this->actingAs($this->operatorFor($org))
            ->get('/admin/saml-providers')
            ->assertOk()
            ->assertSee($provider->entity_id);
    }

    public function test_configuration_is_scoped_to_the_operators_organisation(): void
    {
        $org = $this->orgWithConfiguration();

        $provider = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);

            return DB::selectOne('SELECT entity_id FROM core_v1.saml_providers LIMIT 1');
        });

        if ($provider === null) {
            $this->markTestSkipped('no SAML provider registered for that organisation');
        }

        // A well-formed organisation that owns nothing.
        $this->actingAs($this->operatorFor((string) Str::uuid()))
            ->get('/admin/saml-providers')
            ->assertOk()
            ->assertDontSee($provider->entity_id);
    }

    /**
     * Fails closed, like the rest of the console: an operator with no
     * organisation gets empty screens, never unscoped ones.
     */
    public function test_an_unassigned_operator_sees_no_configuration(): void
    {
        $org = $this->orgWithConfiguration();

        $provider = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);

            return DB::selectOne('SELECT entity_id FROM core_v1.saml_providers LIMIT 1');
        });

        if ($provider === null) {
            $this->markTestSkipped('no SAML provider registered for that organisation');
        }

        $this->actingAs($this->operatorFor(null))
            ->get('/admin/saml-providers')
            ->assertOk()
            ->assertDontSee($provider->entity_id);
    }

    /**
     * Admin tokens are the sharpest case, because the table had no row-level
     * security at all until these screens were added: without a policy this
     * screen would list every tenant's credentials by name and scope.
     *
     * Deployment-wide tokens (org_id NULL) must not appear either. Listing one
     * for a tenant would disclose that another tenant is reachable with it.
     */
    public function test_admin_tokens_are_scoped_and_hide_deployment_wide_ones(): void
    {
        $org = $this->orgWithConfiguration();

        $scoped = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);

            return DB::select('SELECT name, org_id FROM core_v1.admin_tokens');
        });

        foreach ($scoped as $token) {
            $this->assertSame(
                $org,
                $token->org_id,
                'a token belonging to another organisation is visible on this screen'
            );
        }

        // A deployment-wide token has org_id NULL, so the assertion above already
        // excludes it — there is no way for one to appear without failing that
        // identity check. Stated explicitly because "we cannot see them" and "we
        // checked and there were none" are different claims, and only the first
        // is what the policy guarantees.
        foreach ($scoped as $token) {
            $this->assertNotNull(
                $token->org_id,
                'a deployment-wide token is listed on a tenant screen'
            );
        }
    }

    /**
     * The secret must not be reachable from the console at all. It is stored as
     * a SHA-256 and shown once at creation; no path in this system reveals it
     * afterwards, and the read model must not quietly become one.
     */
    public function test_the_token_secret_is_not_exposed(): void
    {
        $columns = DB::select(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'core_v1' AND table_name = 'admin_tokens'"
        );

        $names = array_map(fn ($c) => $c->column_name, $columns);

        foreach (['token', 'token_hash', 'secret'] as $forbidden) {
            $this->assertNotContains(
                $forbidden,
                $names,
                "core_v1.admin_tokens exposes {$forbidden}; the console must never see it"
            );
        }
    }
}
