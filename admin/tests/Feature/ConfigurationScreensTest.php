<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\Concerns\SeedsEngineState;
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
    use SeedsEngineState;

    private array $createdUserIds = [];

    /** Every configuration screen this test covers. */
    private const SCREENS = [
        '/admin/saml-providers',
        '/admin/identity-providers',
        '/admin/groups',
        '/admin/scim-targets',
        '/admin/admin-tokens',
        '/admin/radius-clients',
        '/admin/access-policies',
    ];

    protected function tearDown(): void
    {
        if ($this->createdUserIds !== []) {
            User::whereIn('id', $this->createdUserIds)->delete();
        }
        $this->removePlantedEngineState();

        parent::tearDown();
    }

    private function operatorFor(?string $orgId): User
    {
        $user = new User();
        $user->name = 'Operator';
        $user->email = 'cfg-'.Str::random(10).'@example.test';
        $user->password = bcrypt('irrelevant');
        $user->org_id = $orgId;
        $this->enrol($user)->save();

        $this->createdUserIds[] = $user->id;

        return $user;
    }

    /**
     * An organisation planted with configuration, so the screens are exercised
     * with rows rather than empty states. Returns [org id, SAML entity id].
     *
     * The SAML provider is read back THROUGH the scoped view: the console role
     * has no privilege on schema `core` at all (ADR-004).
     */
    private function orgWithConfiguration(): array
    {
        $org = $this->plantOrganisation();
        $entityId = $this->plantSAMLProvider($org);
        $this->plantClient($org);
        $this->plantAdminToken($org);

        $visible = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);

            return DB::selectOne('SELECT entity_id FROM core_v1.saml_providers LIMIT 1');
        });
        $this->assertSame($entityId, $visible?->entity_id);

        return [$org, $entityId];
    }

    public function test_every_configuration_screen_renders(): void
    {
        [$org] = $this->orgWithConfiguration();
        $operator = $this->operatorFor($org);

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
        [$org, $entityId] = $this->orgWithConfiguration();

        $this->actingAs($this->operatorFor($org))
            ->get('/admin/saml-providers')
            ->assertOk()
            ->assertSee($entityId);
    }

    public function test_configuration_is_scoped_to_the_operators_organisation(): void
    {
        [, $entityId] = $this->orgWithConfiguration();

        // A real, configured second organisation sees its own provider only.
        [$other, $otherEntity] = $this->orgWithConfiguration();
        $this->actingAs($this->operatorFor($other))
            ->get('/admin/saml-providers')
            ->assertOk()
            ->assertSee($otherEntity)
            ->assertDontSee($entityId);
    }

    public function test_an_organisation_that_owns_nothing_sees_no_configuration(): void
    {
        [, $entityId] = $this->orgWithConfiguration();

        // A well-formed organisation that owns nothing.
        $this->actingAs($this->operatorFor((string) Str::uuid()))
            ->get('/admin/saml-providers')
            ->assertOk()
            ->assertDontSee($entityId);
    }

    /**
     * Fails closed, like the rest of the console: an operator with no
     * organisation gets empty screens, never unscoped ones.
     */
    public function test_an_unassigned_operator_sees_no_configuration(): void
    {
        [, $entityId] = $this->orgWithConfiguration();

        $this->actingAs($this->operatorFor(null))
            ->get('/admin/saml-providers')
            ->assertOk()
            ->assertDontSee($entityId);
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
        $org = $this->plantOrganisation();
        $own = $this->plantAdminToken($org);
        // The two that must stay invisible: a deployment-wide token (org_id NULL)
        // and another tenant's. Planted, not hoped for, because "we cannot see
        // them" and "there happened to be none" are different claims and only
        // the first is what the policy guarantees.
        $deploymentWide = $this->plantAdminToken(null);
        $foreign = $this->plantAdminToken($this->plantOrganisation());

        $names = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org]);

            return array_map(fn ($t) => $t->name, DB::select('SELECT name FROM core_v1.admin_tokens'));
        });

        $this->assertContains($own, $names, 'the organisation cannot see its own token');
        $this->assertNotContains($deploymentWide, $names, 'a deployment-wide token is listed on a tenant screen');
        $this->assertNotContains($foreign, $names, 'another organisation\'s token is visible on this screen');

        $this->actingAs($this->operatorFor($org))
            ->get('/admin/admin-tokens')
            ->assertOk()
            ->assertSee($own)
            ->assertDontSee($deploymentWide)
            ->assertDontSee($foreign);
    }

    /**
     * The RADIUS shared secret must not be reachable from the console.
     *
     * Sharper than the token case: this one is stored ENCRYPTED rather than
     * hashed, because RADIUS needs the secret itself to verify a request. So it
     * is recoverable by anything holding the root key, and the console must not
     * be on that list.
     */
    public function test_the_radius_secret_is_not_exposed(): void
    {
        $columns = DB::select(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema = 'core_v1' AND table_name = 'radius_clients'"
        );

        $names = array_map(fn ($c) => $c->column_name, $columns);

        foreach (['secret', 'secret_enc', 'shared_secret'] as $forbidden) {
            $this->assertNotContains(
                $forbidden,
                $names,
                "core_v1.radius_clients exposes {$forbidden}; the console must never see it"
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
