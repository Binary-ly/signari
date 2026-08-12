<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * Proves the tenant boundary is actually connected to the console.
 *
 * Two failures this catches, both of which the console looked fine with:
 *
 *  1. ScopeToOrganisation not registered at all -- every screen renders zero rows
 *     because no app.org_id is ever set, and RLS matches nothing.
 *  2. Registered in the WRONG stack. In Filament's outer `middleware()` list it
 *     runs before Authenticate, finds no user, and behaves exactly like (1) while
 *     appearing correctly wired in the provider.
 *
 * It also asserts the more important direction: an operator scoped to some other
 * organisation must not see this one's clients. That is the claim ADR-006 makes,
 * and it is enforced by the database rather than by a WHERE clause anyone can
 * forget, so it is worth a test that would fail loudly if the enforcement were
 * ever swapped for application-level filtering.
 */
class OrganisationScopingTest extends TestCase
{
    private array $createdUserIds = [];

    protected function tearDown(): void
    {
        // No RefreshDatabase: it would try to drop schemas signari_admin has no
        // privilege on. Clean up only what this test made.
        if ($this->createdUserIds !== []) {
            User::whereIn('id', $this->createdUserIds)->delete();
        }

        parent::tearDown();
    }

    /**
     * An organisation and one of its clients, to assert against.
     *
     * core.organizations carries no RLS policy -- a console has to be able to
     * offer an org picker -- so it is listable without context. core_v1.clients
     * is not, hence the explicit set_config here.
     *
     * That is not circular with what the test asserts. This establishes that the
     * SQL mechanism works; the assertions establish that an ordinary HTTP request
     * through the panel actually goes through it. If the middleware were
     * unregistered, this discovery would still succeed and every assertion below
     * would fail -- which is exactly the bug being guarded against.
     */
    private function seededOrg(): array
    {
        $org = DB::selectOne('SELECT id::text AS id FROM core_v1.organizations LIMIT 1');

        if ($org === null) {
            $this->markTestSkipped('no organisation seeded in this database');
        }

        $client = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org->id]);

            return DB::selectOne('SELECT client_id FROM core_v1.clients LIMIT 1');
        });

        if ($client === null) {
            $this->markTestSkipped('the seeded organisation has no clients to assert on');
        }

        return ['id' => $org->id, 'client_id' => $client->client_id];
    }

    private function operatorFor(?string $orgId): User
    {
        $user = new User();
        $user->name = 'Operator';
        $user->email = 'op-'.Str::random(10).'@example.test';
        $user->password = bcrypt('irrelevant');
        $user->org_id = $orgId;
        $user->save();

        $this->createdUserIds[] = $user->id;

        return $user;
    }

    public function test_operator_sees_their_own_organisations_clients(): void
    {
        $org = $this->seededOrg();

        $this->actingAs($this->operatorFor($org['id']))
            ->get('/admin/engine-clients')
            ->assertOk()
            ->assertSee($org['client_id']);
    }

    /**
     * Every list screen must survive rendering an actual row.
     *
     * The clients table shipped with three closures whose parameters Filament
     * could not inject ($s, $r rather than $state, $record). Nothing caught it
     * because the console had never displayed a single row -- the empty state
     * evaluates no column closures at all. A screen that 500s the moment real
     * data appears is the exact failure mode an empty console hides.
     */
    public function test_every_list_screen_renders_with_real_rows(): void
    {
        $org = $this->seededOrg();
        $operator = $this->operatorFor($org['id']);

        foreach (['/admin/engine-clients', '/admin/engine-users'] as $screen) {
            $this->actingAs($operator)->get($screen)->assertOk();
        }
    }

    public function test_operator_in_another_organisation_sees_nothing(): void
    {
        $org = $this->seededOrg();

        // A well-formed UUID that owns nothing. The request is legitimate; the
        // rows simply are not theirs.
        $this->actingAs($this->operatorFor((string) Str::uuid()))
            ->get('/admin/engine-clients')
            ->assertOk()
            ->assertDontSee($org['client_id']);
    }

    public function test_operator_with_no_organisation_sees_nothing(): void
    {
        $org = $this->seededOrg();

        // Fails CLOSED. An unassigned operator must get an empty console, never
        // an unscoped one -- "no filter" must not mean "no limit".
        $this->actingAs($this->operatorFor(null))
            ->get('/admin/engine-clients')
            ->assertOk()
            ->assertDontSee($org['client_id']);
    }
}
