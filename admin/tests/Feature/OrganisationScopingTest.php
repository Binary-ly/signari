<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\Concerns\SeedsEngineState;
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
    use SeedsEngineState;

    private array $createdUserIds = [];

    protected function tearDown(): void
    {
        // No RefreshDatabase: it would try to drop schemas signari_admin has no
        // privilege on. Clean up only what this test made.
        if ($this->createdUserIds !== []) {
            User::whereIn('id', $this->createdUserIds)->delete();
        }
        $this->removePlantedEngineState();

        parent::tearDown();
    }

    /**
     * An organisation with one client and one user, planted for this test.
     *
     * The discovery below runs on the console's own connection, with an
     * explicit set_config, to establish that the SQL mechanism works. That is
     * not circular with what the test asserts: the assertions establish that an
     * ordinary HTTP request through the panel actually goes through it. If the
     * middleware were unregistered, this discovery would still succeed and every
     * assertion below would fail -- which is exactly the bug being guarded
     * against.
     */
    private function seededOrg(): array
    {
        $orgId = $this->plantOrganisation();
        $clientId = $this->plantClient($orgId);
        $this->plantUser($orgId);

        $visible = DB::transaction(function () use ($orgId) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $orgId]);

            return DB::selectOne('SELECT client_id FROM core_v1.clients LIMIT 1');
        });
        $this->assertSame($clientId, $visible?->client_id,
            'the planted client must be visible through core_v1 once app.org_id is set');

        return ['id' => $orgId, 'client_id' => $clientId];
    }

    private function operatorFor(?string $orgId): User
    {
        $user = new User;
        $user->name = 'Operator';
        $user->email = 'op-'.Str::random(10).'@example.test';
        $user->password = bcrypt('irrelevant');
        $user->org_id = $orgId;
        $this->enrol($user)->save();

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

    /**
     * Every click on a screen after the first load -- a row action, a search, a
     * sort, the next page -- is a POST to /livewire/update, and Filament runs
     * authMiddleware there only when it is registered as persistent. It was not:
     * the page loaded with its rows, the first round-trip rendered the table with
     * no organisation and so with none, and a row action opened no form, since
     * its record was no longer in the table. Found in Chrome, removing a sign-in
     * method; the feature tests set app.org_id themselves and Livewire::test makes
     * no HTTP request, so every one of them passed.
     */
    public function test_a_round_trip_after_the_page_keeps_the_organisation(): void
    {
        $org = $this->seededOrg();
        $operator = $this->operatorFor($org['id']);

        $page = $this->actingAs($operator)->get('/admin/engine-clients')->assertOk()->getContent();
        $snapshot = null;
        $token = null;
        preg_match('/<meta name="csrf-token" content="([^"]+)"/', $page, $m) && $token = $m[1];
        preg_match_all('/wire:snapshot="([^"]*)"/', $page, $all);
        foreach ($all[1] as $raw) {
            $json = html_entity_decode($raw, ENT_QUOTES | ENT_HTML5);
            if (str_contains((string) (json_decode($json, true)['memo']['name'] ?? ''), 'list-engine-clients')) {
                $snapshot = $json;
            }
        }
        $this->assertNotNull($snapshot, 'the clients screen carries no snapshot of its list');

        // What the browser sends when a component asks the server to render it again
        // ($refresh, which is client-side: a commit with no updates and no calls).
        $html = $this->actingAs($operator)
            ->withHeaders(['X-Livewire' => '1'])
            ->postJson('/livewire/update', [
                '_token' => $token,
                'components' => [['snapshot' => $snapshot, 'updates' => new \stdClass, 'calls' => []]],
            ])
            ->assertOk()
            ->json('components.0.effects.html');

        $this->assertIsString($html, 'the round-trip rendered nothing');
        $this->assertStringContainsString($org['client_id'], $html,
            'after a round-trip the list rendered without its organisation, so with no rows');
    }

    public function test_operator_in_another_organisation_sees_nothing(): void
    {
        $org = $this->seededOrg();

        // A real, populated second organisation. The request is legitimate; the
        // rows simply are not theirs.
        $other = $this->plantOrganisation();
        $otherClient = $this->plantClient($other);

        $this->actingAs($this->operatorFor($other))
            ->get('/admin/engine-clients')
            ->assertOk()
            ->assertSee($otherClient)
            ->assertDontSee($org['client_id']);
    }

    public function test_operator_of_an_organisation_that_owns_nothing_sees_nothing(): void
    {
        $org = $this->seededOrg();

        // A well-formed UUID that owns nothing at all.
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
